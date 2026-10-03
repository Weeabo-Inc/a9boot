//! `a9boot-host` — command line.
//!
//! Two modes, and the distinction is enforced by the build rather than by a flag:
//!
//! * **offline** (always available): `selftest`, `plan`, `probe`. These compute, print and
//!   check; `plan` and `probe` print every packet they *would* send and send nothing.
//! * **device** (`--features usb`, and still Lead-only): not reachable from this binary. The
//!   default build has no USB capability at all (`transport::open_live` says so by name), so
//!   nobody can touch the phone from a9boot by accident — which is the point, because a second
//!   agent on one DFU device loses the session (HANDOFF §9.1).

use a9boot_core::abi::{self, Command};
use a9boot_core::image::Header;
use a9boot_core::layout::{self, *};
use a9boot_core::plan::{self, Inputs};
use a9boot_host::bundle::{self, AusbTunables, BootBlobs, EditOptions, Step};
use a9boot_host::evidence::{self, Transcript};
use a9boot_host::capacity as capmod;
use a9boot_host::exec as execmod;
use a9boot_host::firstlight::{self, Options as FlOptions, ReadSpec, WriteSpec};
use a9boot_host::transport::{Sequence, Transport};
use std::process::ExitCode;

/// The environment variable that arms a live run.
///
/// Two keys, not one: the `usb` **feature** (compile time) and this **variable** (run time), plus
/// the explicit `--live` flag. A pwned device is a loaded gun — one careless write is a wild write
/// into SRAM — so reaching it must be something a person did on purpose, twice, and it must be
/// impossible for a script that merely inherits a shell to do it by accident.
const LIVE_ENV: &str = "A9BOOT_LIVE_CONFIRMED";

const USAGE: &str = "\
a9boot-host — offline planner and (Lead-only) first-light driver for the A9 loader.

USAGE:
  a9boot-host selftest
  a9boot-host probe [--live] [--json FILE]
  a9boot-host firstlight [--live] [--json FILE]
                        [--read ADDR:LEN]... [--write ADDR:LEN]
                        [--terminator none|dfu] [--no-status]
  a9boot-host plan --image FILE --dtb FILE [--initramfs FILE] [--payload FILE]
                   [--ausb-cfg0 HEX --ausb-cfg1 HEX] [--spin ADDR] [--fb-enable]
                   [--maxcpus1] [--dump-dtb FILE]

  selftest     Offline checks. Sends nothing; the default build cannot open a device at all.

  probe        The unified post-pwn experiment: the AUSB PHY tunables and the DRAM walk.
               Writes 32-byte patterns into DRAM. Without --live it prints the packets it would
               send and sends nothing.

  pagewalk     Read the ROM's live EL3 translation tables and answer, for each --lookup address,
               MAPPED / NOT_ACCESSIBLE / UNMAPPED / UNKNOWN — BEFORE anything touches it. Gated by
               the handler canary; follows no table pointer outside known-mapped SRAM.

  capacity     The U-2 ladder: how large a single command can be. ONE command per step, with a
               memcpy(0,0,0) header, so the probe writes NOTHING except the DNLOAD itself and the
               reply echoes the appended data back. Reports a BRACKET (last good, first bad) — run
               it FIRST, before any payload upload.

  exec         Stage a9boot-payload in the ROM's DFU buffer, VERIFY it byte for byte, re-stage
               it, and only then EXEC it. Refuses to execute an image it could not verify.

  firstlight   The smallest sequence that can prove the command channel works. Default: ONE
               read-only MEMC read of the AUSB PHY pair the SecureROM programmed. Optional
               --write ADDR:LEN adds a write+read-back of a per-run-unique pattern inside DRAM
               (the only content-verifiable step). --json writes the evidence transcript.

  plan         Parses the arm64 Image header, computes the physical layout, applies the loader's
               device-tree obligations, and prints every packet it would send.

LIVE RUNS (--live) ARE LEAD-ONLY and need all three of: a build with --features usb, the
--live flag, and A9BOOT_LIVE_CONFIRMED=yes in the environment. Nothing else in this binary can
open a device.

EXIT CODES:
  0 PASS      2 bad arguments      3 refused before sending (feature/gate/identity)
  4 file error
  5 FAIL, no reply          (the wire did not answer; the message says which transfer)
  6 UNKNOWN                 (nothing was verified: a dry run, or no exchange attempted)
  7 FAIL, reply rejected    (the wire answered, and the bytes failed the contract, or two
                             exchanges contradicted each other; the message names which)
  8 FAIL, DFU state walk    (STATE_WALK_MISMATCH: the reference's MANIFEST_SYNC -> MANIFEST ->
                             MANIFEST_WAIT_RESET framing did not see the states it requires; the
                             message carries the state actually observed)
  9 REFUSED to execute      (the staged image failed verification: nothing was executed)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("firstlight") => match firstlight_cmd(&args[1..]) {
            Ok(code) => code,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("pagewalk") => match pagewalk_cmd(&args[1..]) {
            Ok(code) => code,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("capacity") => match capacity_cmd(&args[1..]) {
            Ok(code) => code,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("exec") => match exec_cmd(&args[1..]) {
            Ok(code) => code,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("probe") => match probe_cmd(&args[1..]) {
            Ok(code) => code,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("plan") => match plan_cmd(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err((code, msg)) => {
                eprintln!("a9boot-host: {msg}");
                ExitCode::from(code)
            }
        },
        Some("help") | Some("--help") | Some("-h") | None => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("a9boot-host: unknown command {other:?}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Offline checks. The `a9pwn selftest` pattern: cheap, offline, and it fails loudly on the things
/// that are structural rather than device-specific.
fn selftest() -> ExitCode {
    let mut failures = 0;
    let mut check = |name: &str, r: Result<(), String>| match r {
        Ok(()) => println!("PASS  {name}"),
        Err(e) => {
            println!("FAIL  {name}: {e}");
            failures += 1;
        }
    };

    check("layout invariants", layout::check().map_err(|e| format!("{} ({:#x})", e.code, e.detail)));
    check("channel ABI invariants", abi::check().map_err(|e| format!("{} ({:#x})", e.code, e.detail)));
    check("build flavour: USB capability matches the feature", {
        #[cfg(not(feature = "usb"))]
        {
            match a9boot_host::transport::open_live() {
                Err(e) if e.contains("no USB capability") => Ok(()),
                Err(e) => Err(e),
                Ok(()) => Err("this build CAN open a device; the default must not".to_string()),
            }
        }
        #[cfg(feature = "usb")]
        {
            // Deliberately not a failure: this flavour is the one the Lead builds to run the
            // probe, and `LiveTransport` is UNVERIFIED-BY-TEST until that has happened.
            println!("      NOTE  built with --features usb: this build CAN open the device.");
            println!("      NOTE  transport::live is UNVERIFIED-BY-TEST. Device access is Lead-only.");
            match a9boot_host::transport::open_live() {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            }
        }
    });
    check("magic values match the reference", {
        if abi::EXEC_MAGIC == 0x6578_6563_6578_6563
            && abi::MEMC_MAGIC == 0x6D65_6D63_6D65_6D63
            && abi::DONE_MAGIC == 0x646F_6E65_646F_6E65
        {
            Ok(())
        } else {
            Err("a channel magic does not match gaster.c:49-51".to_string())
        }
    });
    check("payload executes inside the DFU buffer, past the reply area", {
        if abi::payload_exec_addr() == DFU_BUFFER_ADDR + abi::PAYLOAD_OFF
            && abi::PAYLOAD_OFF >= abi::REPLY_OFF + abi::REPLY_CAP
        {
            Ok(())
        } else {
            Err(format!("{:#x}", abi::payload_exec_addr()))
        }
    });
    check("the AUSB PHY registers are where the PHY node is", {
        if AUSB_CFG0_ADDR == AUSB_PHY_BASE + 0x08 && AUSB_CFG1_ADDR == AUSB_PHY_BASE + 0x0c {
            Ok(())
        } else {
            Err(format!("{AUSB_CFG0_ADDR:#x} / {AUSB_CFG1_ADDR:#x}"))
        }
    });
    check("a synthetic plan computes and re-checks", {
        let inputs = Inputs {
            image_size: 0x0180_0000,
            image_text_offset: 0x80000,
            dtb_size: 0x5800,
            initrd_size: 0x300000,
            ..Default::default()
        };
        plan::compute(&inputs)
            .map_err(|e| format!("{} ({:#x})", e.code, e.detail))
            .map(|p| {
                println!(
                    "      entry {:#x}, dtb {:#x}, image {:#x}, initrd {:#x}",
                    p.kernel_entry, p.dtb_addr, p.image_addr, p.initrd_addr
                );
                println!("      bootargs {:?}", p.bootargs.as_str());
            })
    });
    check("bootargs carry the dt-engineer contract and no forced baud", (|| {
        let b = plan::default_bootargs().map_err(|e| e.code.to_string())?;
        let s = b.as_str();
        for token in ["earlycon", "console=ttySAC0", "keep_bootcon", "initcall_debug"] {
            if !s.contains(token) {
                return Err(format!("missing {token} in {s:?}"));
            }
        }
        if s.contains("ttySAC0,") {
            return Err("a forced baud is present; s3c24xx_serial_get_options() reads UBRDIV back \
                        and cancelling the two errors is the point"
                .to_string());
        }
        Ok(())
    })());
    check("the DRAM walk covers the whole nominal range", (|| {
        let v = bundle::dram_walk_addresses();
        if v.first() != Some(&DRAM_BASE) {
            return Err(format!("walk starts at {:?}", v.first()));
        }
        if v.last() != Some(&(DRAM_BASE + DRAM_SIZE - 0x20)) {
            return Err(format!("walk ends at {:?}", v.last()));
        }
        if v.len() < 10 {
            return Err(format!("walk has only {} addresses", v.len()));
        }
        Ok(())
    })());

    println!();
    if failures == 0 {
        println!("selftest: all checks passed. Nothing was sent; no device was opened.");
        ExitCode::SUCCESS
    } else {
        println!("selftest: {failures} check(s) FAILED.");
        ExitCode::from(3)
    }
}

/// Print the unified post-pwn experiment. This is the highest-value measurement available to the
/// project, and it does not need any loader: it is the ROM's own `memcpy`, driven by the resident
/// checkm8 handler.
///
/// Without `--live` this prints and sends nothing, and exits **6 (UNKNOWN)** — a dry run is not
/// evidence, so it must not exit the way a verified run does. With `--live` it runs the *same*
/// steps through the same code path against a real device — which is **Lead-only** (HANDOFF §9.1)
/// and impossible unless the build has the `usb` feature, `--live` is given, and
/// `A9BOOT_LIVE_CONFIRMED=yes` is in the environment.
fn probe_cmd(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let mut live = false;
    let mut json: Option<String> = None;
    let mut only: Option<bundle::ProbePart> = None;
    let mut skip: Option<bundle::ProbePart> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--live" => live = true,
            "--json" => {
                i += 1;
                json = Some(
                    args.get(i).cloned().ok_or((2, "--json needs a file path".to_string()))?,
                );
            }
            "--only" => {
                i += 1;
                only = Some(parse_probe_part(args.get(i).map(|s| s.as_str()).ok_or((
                    2,
                    "--only needs ausb|dram".to_string(),
                ))?)?);
            }
            "--skip" => {
                i += 1;
                skip = Some(parse_probe_part(args.get(i).map(|s| s.as_str()).ok_or((
                    2,
                    "--skip needs ausb|dram".to_string(),
                ))?)?);
            }
            other => return Err((2, format!("probe: unknown option {other:?}"))),
        }
        i += 1;
    }
    if only.is_some() && only == skip {
        return Err((
            2,
            format!(
                "--only {:?} --skip {:?} selects NOTHING. A run with no steps proves nothing and \
                 must not look like a run that proved something.",
                only.unwrap(),
                skip.unwrap()
            ),
        ));
    }
    if live {
        return probe_live(json.as_deref(), only, skip);
    }

    let steps = bundle::probe_steps_filtered(only, skip);
    println!("# a9boot probe — the unified post-pwn experiment (DRAM extent + AUSB tunables).");
    println!("# Run after the first PWND:[checkm8]. This build sends nothing; the packet list is");
    println!("# what a live run would send, and it is the same code path (`bundle::run_probe`).");
    if only.is_some() || skip.is_some() {
        println!("# SELECTED: {}{}", only.map(|p| format!("only {p:?}")).unwrap_or_default(),
                 skip.map(|p| format!(" skip {p:?}")).unwrap_or_default());
    }
    println!();
    let mut n = 0;
    let mut bytes = 0usize;
    for (i, s) in steps.iter().enumerate() {
        match s {
            Step::Comment(c) => println!("{i:>3}  # {c}"),
            other => {
                for p in bundle::step_packets(other, &[], &bundle::TransferBudget::default()) {
                    n += 1;
                    bytes += p.dnload.len();
                    println!("{i:>3}  DNLOAD {:>4} bytes  UPLOAD {:>4}  {}", p.dnload.len(), p.upload_len, p.label);
                }
            }
        }
    }
    println!();
    println!("{n} packets, {bytes} DNLOAD bytes, {} addresses walked.", bundle::dram_walk_addresses().len());
    println!();
    println!("## what the result decides");
    println!("  * AUSB cfg0/cfg1 non-zero and stable -> `apple,cfg0-device`/`cfg1-device` for the");
    println!("    ausbphy0 node, which is what unblocks the USB gadget console (ttyGS0).");
    println!("  * last address that round-trips -> the DRAM extent. Declaring MORE than exists");
    println!("    corrupts rather than panics (LOADER-FILL.md §2), so this is measured, not assumed.");
    println!("  * a failure at the first address means the ROM's EL3 translation does not reach DRAM");
    println!("    at all, which is PLAN B in DESIGN.md §11.1 and stops the design.");
    println!("  * CAVEAT: the walk cannot see a cache. If the ROM runs with the D-cache on and maps");
    println!("    DRAM cacheable, a write-then-read-back is served by the cache line and passes on");
    println!("    memory that does not exist. A FAILURE is real evidence; a PASS is not sufficient");
    println!("    evidence for an extent until SCTLR_EL3 is known (payload DESCRIBE) or the");
    println!("    eviction-pressure experiment has run. `--only ausb` avoids the question entirely.");
    println!();
    if let Some(path) = &json {
        // The dry run still writes a transcript, so there is a record of what was *planned* — and
        // it says UNKNOWN in the verdict, because nothing was sent.
        let rec: a9boot_host::evidence::Recorder<DeadTransport> =
            a9boot_host::evidence::Recorder::new(DeadTransport);
        let t = rec.transcript(
            command_line(),
            "dry-run",
            vec!["this was a dry run: UNKNOWN is the verdict because nothing was sent, and a dry \
                  run must never exit the way a verified run does"
                .to_string()],
            vec![(
                "planned_packets".to_string(),
                format!("{}", n),
            )],
            None,
        );
        write_json(path, &t)?;
    }
    println!("no device was opened, and this build cannot open one.");
    println!("VERDICT       UNKNOWN — nothing was sent (exit 6 by design).");
    Ok(ExitCode::from(6))
}

fn parse_probe_part(s: &str) -> Result<bundle::ProbePart, (u8, String)> {
    match s {
        "ausb" => Ok(bundle::ProbePart::Ausb),
        "dram" => Ok(bundle::ProbePart::Dram),
        other => Err((2, format!("{other:?} is not ausb|dram"))),
    }
}

/// A transport that refuses everything. Used to build a dry-run transcript: it makes "no exchange
/// happened" structurally true rather than a claim.
struct DeadTransport;

impl Transport for DeadTransport {
    fn serial(&mut self) -> Result<String, String> {
        Err("dry run: no device".to_string())
    }
    fn exchange(&mut self, _e: &a9boot_host::transport::Exchange) -> Result<Vec<u8>, String> {
        Err("dry run: no device".to_string())
    }
    fn describe(&self) -> String {
        "none (dry run)".to_string()
    }
}

/// The three-key live gate, checked **before anything can open a device**.
///
/// 1. `--live` on the command line (the caller's job);
/// 2. a build with the `usb` feature — `transport::open_live` names the refusal otherwise;
/// 3. `A9BOOT_LIVE_CONFIRMED=yes`.
///
/// Nothing here touches USB. The tests for this function are the reason it is a function.
fn live_gate() -> Result<(), (u8, String)> {
    a9boot_host::transport::open_live().map_err(|e| (3, e))?;
    match std::env::var(LIVE_ENV).as_deref() {
        Ok("yes") => Ok(()),
        Ok(other) => Err((
            3,
            format!("REFUSED: {LIVE_ENV} is {other:?}, not \"yes\". Live device access is armed \
                     explicitly, one run at a time."),
        )),
        Err(_) => Err((
            3,
            format!(
                "REFUSED: live device access needs {LIVE_ENV}=yes in the environment as well as \
                 --live. This is deliberate (a pwned device is a loaded gun: one careless write is \
                 a wild write into SRAM). Nothing was opened and nothing was sent.\n\
                 To arm exactly one command:\n\
                 \n    {LIVE_ENV}=yes a9boot-host {} --live ...\n",
                std::env::args().nth(1).unwrap_or_else(|| "<command>".into())
            ),
        )),
    }
}

/// Run the probe against a real device.
///
/// **UNVERIFIED-BY-TEST** (`transport::live` says why). Compiled only with `--features usb`; the
/// default build refuses by name, and the identity check runs *before* the first command so that a
/// wrong device, a wrong board and a not-pwned device are three different messages.
pub fn probe_live_impl(
    json: Option<&str>,
    only: Option<bundle::ProbePart>,
    skip: Option<bundle::ProbePart>,
) -> Result<ExitCode, (u8, String)> {
    live_gate()?;
    #[cfg(feature = "usb")]
    {
        use a9boot_host::channel::{check_identity, Expect};
        use a9boot_host::evidence::{Recorder, Verdict};
        use a9boot_host::transport::live::LiveTransport;
        let t = LiveTransport::open().map_err(|e| (4, e))?;
        let mut rec = Recorder::new(t);
        let serial = rec.serial().map_err(|e| (4, e))?;
        check_identity(&serial, &Expect::default())
            .map_err(|e| (3, format!("identity check refused before sending anything: {e}")))?;
        rec.note("identity: CPID 0x8003, BDID 0x02, PWND:[checkm8] all present".to_string());
        let steps = bundle::probe_steps_filtered(only, skip);
        if steps.is_empty() {
            return Err((
                2,
                "--only and --skip selected zero probe steps. Refusing before the device is \
                 opened: a run that measures nothing must not be reported as a measurement."
                    .to_string(),
            ));
        }
        let want_ausb = steps.iter().any(|s| matches!(s, Step::Read { .. }));
        let want_dram = steps.iter().any(|s| matches!(s, Step::WriteVerify { .. }));
        rec.note(format!(
            "selected parts: {}",
            match (want_ausb, want_dram) {
                (true, true) => "AUSB read + DRAM walk".to_string(),
                (true, false) => "AUSB read only (no DRAM write; the extent stays UNMEASURED)"
                    .to_string(),
                (false, true) => "DRAM walk only".to_string(),
                (false, false) => "NOTHING — the selector removed every step".to_string(),
            }
        ));
        let probe = bundle::run_probe_with(&mut rec, steps).map_err(|e| (5, e))?;

        println!("{}", rec.inner().describe());
        println!("{}", probe.report());

        // The probe's own verdict. A DRAM walk that stops early is the *measurement*, not a tool
        // failure — so a tolerated failure does not make the transcript FAIL. A failure at the
        // FIRST address is different: it is PLAN B, and the design stops. And a walk that was
        // *skipped* is neither: the extent is UNMEASURED, which is not a pass and not a failure.
        let mut warnings = Vec::new();
        let mut verdict = Verdict::Pass;
        let mut reason = None;

        if want_ausb && probe.ausb.is_none() {
            verdict = Verdict::Fail;
            reason = Some("the AUSB read was selected but no tunables came back".to_string());
            warnings.push(reason.clone().unwrap());
        }
        if let Some(a) = probe.ausb {
            if !a.looks_plausible() {
                warnings.push(
                    "AUSB cfg0/cfg1 read back as ZERO or ALL-ONES. Record it, but do not pass it \
                     to the device tree: the values are context, not a tunable, until a second \
                     read agrees."
                        .to_string(),
                );
            }
        }
        if !probe.dram_measured() {
            warnings.push(
                "DRAM EXTENT UNMEASURED: this run did not walk DRAM, so nothing here is evidence \
                 about DRAM reachability, extent or usability (U-1, U-5). Declaring an extent \
                 from a run that did not measure one is the failure mode U-5 describes. Re-run \
                 with `--only dram` when the cache question is answerable."
                    .to_string(),
            );
        } else if probe.dram_first_bad == Some(layout::DRAM_BASE) {
            verdict = Verdict::Fail;
            reason = Some(format!(
                "the DRAM walk failed at its first address ({:#x}): PLAN B.",
                layout::DRAM_BASE
            ));
            warnings.push(
                "the DRAM walk failed at its FIRST address. That is PLAN B (DESIGN.md §11.1): the \
                 ROM's EL3 translation does not reach DRAM, nothing can be staged, and the design \
                 stops. Do not retry; re-read DESIGN.md §11.1 and decide whether to attempt \
                 TTBR0_EL3 surgery (which can lose the DFU session)."
                    .to_string(),
            );
        } else if probe.dram_first_bad.is_some() {
            warnings.push(format!(
                "the DRAM walk stopped at {:#x} and everything above it is unmeasured. That is the \
                 *extent*: declare no more than `Probe::dram_extent()`, because over-declaring \
                 hands the kernel dead pages and corrupts rather than panics (LOADER-FILL.md §2). \
                 A FAILURE is real evidence; a PASS would not have been (see the cache caveat in \
                 the probe report).",
                probe.dram_first_bad.unwrap()
            ));
        } else {
            warnings.push(
                "every DRAM address round-tripped — and that is NOT yet sufficient evidence for a \
                 declared extent. The walk cannot see a cache: if the ROM's EL3 context maps DRAM \
                 Normal cacheable with the D-cache on, each write/read-back is served by the cache \
                 line and passes on memory that may not exist. Nothing in this channel can do \
                 cache maintenance or read SCTLR_EL3. Treat the extent as UNMEASURED until the \
                 payload's DESCRIBE reports SCTLR_EL3/SCTLR_EL1 (U-3/U-4) or the \
                 eviction-pressure experiment has run."
                    .to_string(),
            );
        }
        let extras = vec![
            (
                "probe".to_string(),
                format!(
                    "{{\"dram_walk_ran\": {}, \"dram_measured\": {}, \"dram_last_ok\": {}, \
                     \"dram_first_bad\": {}, \"dram_extent\": {}, \"ausb_cfg0_device\": {}, \
                     \"ausb_cfg1_device\": {}}}",
                    probe.dram_walk_ran,
                    probe.dram_measured(),
                    if probe.dram_measured() {
                        format!("\"{:#x}\"", probe.dram_last_ok)
                    } else {
                        "null".to_string()
                    },
                    match probe.dram_first_bad {
                        Some(a) => format!("\"{a:#x}\""),
                        None => "null".to_string(),
                    },
                    if probe.dram_measured() {
                        format!("\"{:#x}\"", probe.dram_extent())
                    } else {
                        "null".to_string()
                    },
                    probe.ausb.map(|a| format!("\"{:#010x}\"", a.cfg0_device)).unwrap_or("null".into()),
                    probe.ausb.map(|a| format!("\"{:#010x}\"", a.cfg1_device)).unwrap_or("null".into()),
                ),
            ),
            ("probe_report".to_string(), json_string(&probe.report())),
        ];
        let verdict = if rec.records.is_empty() { Verdict::Unknown } else { verdict };
        let t = rec.transcript(command_line(), "live", warnings, extras, Some((verdict, reason)));
        println!("{}", t.human());
        if let Some(path) = json {
            write_json(path, &t)?;
        }
        println!("Read the numbers, not the run: U-1/U-5/U-13 in a9boot/UNVERIFIED.md.");
        Ok(match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Unknown => ExitCode::from(6),
            _ => ExitCode::from(7),
        })
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = (json, only, skip);
        Err((3, "this build has no USB capability. Rebuild with --features usb; device access is \
                 Lead-only."
            .to_string()))
    }
}

/// Read one translation table through the channel, chunked to its read limit. The byte size is
/// `entries_needed(level, granule) * 8` — 4 KiB for 4K granule (512 entries), 16 KiB for 16K
/// (2048 entries), 64 KiB for 64K (8192 entries).
///
/// Non-generic on purpose: the root search needs two closures over the same recorder, so these
/// cannot capture it.
#[cfg(feature = "usb")]
fn read_table_entries(
    rec: &mut a9boot_host::evidence::Recorder<a9boot_host::transport::live::LiveTransport>,
    addr: u64,
    level: u8,
    granule: a9boot_host::pagetable::Granule,
) -> Result<Vec<u64>, String> {
    let total = a9boot_host::pagetable::entries_needed(level, granule) * 8;
    let chunk = bundle::TransferBudget::default().max_read().max(1);
    let mut bytes = Vec::new();
    let mut off = 0usize;
    while off < total {
        let n = chunk.min(total - off);
        let p = a9boot_host::channel::mem_read(addr + off as u64, n);
        let e = evidence::exchange_for(
            &p,
            &format!("table L{level} {:#x}", addr + off as u64),
            Sequence::Reference,
        );
        let raw = rec.exchange(&e)?;
        let r = a9boot_host::channel::parse_response(&raw, p.upload_len)?;
        if r.data.len() < n {
            return Err(format!("short table read at {:#x}: {} < {n}", addr + off as u64, r.data.len()));
        }
        bytes.extend_from_slice(&r.data[..n]);
        off += n;
    }
    Ok(bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
}

/// Read eight bytes, for the root sweep.
#[cfg(feature = "usb")]
fn read8_at(
    rec: &mut a9boot_host::evidence::Recorder<a9boot_host::transport::live::LiveTransport>,
    addr: u64,
) -> Result<[u8; 8], String> {
    let p = a9boot_host::channel::mem_read(addr, 8);
    let e = evidence::exchange_for(&p, &format!("root sweep {addr:#x}"), Sequence::Reference);
    let raw = rec.exchange(&e)?;
    let r = a9boot_host::channel::parse_response(&raw, p.upload_len)?;
    let mut b = [0u8; 8];
    let n = r.data.len().min(8);
    b[..n].copy_from_slice(&r.data[..n]);
    Ok(b)
}

fn probe_live(
    json: Option<&str>,
    only: Option<bundle::ProbePart>,
    skip: Option<bundle::ProbePart>,
) -> Result<ExitCode, (u8, String)> {
    probe_live_impl(json, only, skip)
}

fn plan_cmd(args: &[String]) -> Result<(), (u8, String)> {
    let mut image: Option<String> = None;
    let mut dtb: Option<String> = None;
    let mut initramfs: Option<String> = None;
    let mut payload_path: Option<String> = None;
    let mut spin: Option<u64> = None;
    let mut ausb0: Option<u32> = None;
    let mut ausb1: Option<u32> = None;
    let mut fb_enable = false;
    let mut maxcpus1 = false;
    let mut dump_dtb: Option<String> = None;
    let mut expect_image_size: Option<u64> = None;
    let mut expect_image_sha: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let next = |i: &mut usize| -> Result<String, (u8, String)> {
            *i += 1;
            args.get(*i).cloned().ok_or((2, format!("{a} needs a value")))
        };
        match a.as_str() {
            "--image" => image = Some(next(&mut i)?),
            "--dtb" => dtb = Some(next(&mut i)?),
            "--initramfs" => initramfs = Some(next(&mut i)?),
            "--payload" => payload_path = Some(next(&mut i)?),
            "--dump-dtb" => dump_dtb = Some(next(&mut i)?),
            "--expect-image-size" => expect_image_size = Some(parse_int(&next(&mut i)?)?),
            "--expect-image-sha256" => {
                expect_image_sha = Some(next(&mut i)?.to_ascii_lowercase())
            }
            "--spin" => spin = Some(parse_int(&next(&mut i)?)?),
            "--ausb-cfg0" => ausb0 = Some(parse_int(&next(&mut i)?)? as u32),
            "--ausb-cfg1" => ausb1 = Some(parse_int(&next(&mut i)?)? as u32),
            "--fb-enable" => fb_enable = true,
            "--maxcpus1" => maxcpus1 = true,
            other => return Err((2, format!("unknown option {other:?}"))),
        }
        i += 1;
    }

    let image_path = image.ok_or((2, "--image is required".to_string()))?;
    let dtb_path = dtb.ok_or((2, "--dtb is required".to_string()))?;
    let image = read(&image_path)?;
    let dtb_src = read(&dtb_path)?;
    let initrd = match &initramfs {
        Some(p) => Some(read(p)?),
        None => None,
    };
    let payload = match &payload_path {
        Some(p) => {
            let raw = read(p)?;
            if raw.len() >= 4 && raw[0..4] == a9boot_host::elf::ELF_MAGIC {
                // The ELF is what `cargo build` produces; the channel carries the flattened image.
                let flat = a9boot_host::elf::flatten(&raw)
                    .map_err(|e| (3, format!("{p}: {e}")))?;
                flat.check().map_err(|e| (3, format!("{p}: {e}")))?;
                println!("payload    {} -> flat: {}", p, flat.summary());
                flat.bytes
            } else {
                if raw.len() as u64 > a9boot_core::layout::PAYLOAD_MAX_FOOTPRINT {
                    return Err((
                        3,
                        format!(
                            "{p}: {} bytes exceeds the {} byte payload budget",
                            raw.len(),
                            a9boot_core::layout::PAYLOAD_MAX_FOOTPRINT
                        ),
                    ));
                }
                raw
            }
        }
        None => Vec::new(),
    };

    // 1. The Image header is the authority on where the kernel goes. `Image.gz` is refused by
    //    name rather than mis-parsed: the AArch64 kernel has no decompressor, so decompression is
    //    the loader's job (booting.rst §3) and a9boot consumes a plain Image.
    let header = Header::parse(&image).map_err(|e| (3, format!("{} ({:#x})", e.code, e.detail)))?;
    header
        .validate_for_a9()
        .map_err(|e| (3, format!("{} ({:#x}): this kernel cannot be staged", e.code, e.detail)))?;
    // Reserve vs transfer. `image_size` is `_end - _text`: the footprint, `.bss` included
    // (`a9linux/artefacts/kernel/BUILD-LOG.md:845`). The file holds only the stored portion, so
    // `file_len < image_size` is the normal case — MEASURED on both shipped kernels:
    // image_size 0x1370000, file 0x12d7200, gap 0x98e00. The structural check is
    // `file_len <= image_size`; the gap is `.bss`, which the kernel's `head.S` clears.
    let extent = header
        .check_extent(image.len() as u64)
        .map_err(|e| (3, format!("{} ({:#x}): this Image is not storable", e.code, e.detail)))?;

    // The header cannot express how long the file should be, so a truncated *tail* is invisible
    // to it. Verification is by artefact identity, which is why these two options exist and why
    // the runbook tells the deploy step to pass them.
    let mut artefact_verified = false;
    if let Some(want) = expect_image_size {
        if want != image.len() as u64 {
            return Err((
                3,
                format!(
                    "IMAGE_ARTEFACT_MISMATCH: --expect-image-size says {want:#x} but the file is {:#x} bytes. A truncated or substituted Image looks exactly like an Image with a large .bss to the header, so this check is the one that catches it.",
                    image.len()
                ),
            ));
        }
        artefact_verified = true;
    }
    if let Some(want) = &expect_image_sha {
        let got = a9boot_host::evidence::sha256_hex(&image);
        if &got != want {
            return Err((
                3,
                format!(
                    "IMAGE_ARTEFACT_MISMATCH: --expect-image-sha256 says {want} but the file hashes to {got}. Refusing to stage a kernel that is not the one that was built and reviewed."
                ),
            ));
        }
        artefact_verified = true;
    }

    let ausb = match (ausb0, ausb1) {
        (Some(a0), Some(a1)) => Some(AusbTunables { cfg0_device: a0, cfg1_device: a1 }),
        (None, None) => None,
        _ => {
            return Err((
                2,
                "--ausb-cfg0 and --ausb-cfg1 must be given together (they come from one probe)"
                    .to_string(),
            ))
        }
    };

    // 2. Plan. The command line follows the AUSB tunables: supplying one without the other is the
    //    half-configured console that `edit_dtb` refuses, so the CLI cannot produce it either.
    let mut bootargs = if ausb.is_some() {
        plan::bootargs_with_usb_console()
    } else {
        plan::default_bootargs()
    }
    .map_err(|e| (3, e.code.to_string()))?;
    if maxcpus1 {
        bootargs.push("maxcpus=1").map_err(|e| (3, e.code.to_string()))?;
    }
    let inputs = Inputs {
        image_size: header.image_size,
        image_text_offset: header.text_offset,
        dtb_size: dtb_src.len() as u64,
        initrd_size: initrd.as_ref().map(|i| i.len() as u64).unwrap_or(0),
        dram_size: DRAM_SIZE,
        fb_enabled: fb_enable,
        usb_console: ausb.is_some(),
        bootargs: Some(bootargs),
    };
    let plan = plan::compute(&inputs).map_err(|e| (3, format!("{} ({:#x})", e.code, e.detail)))?;

    // 3. Edit the DTB with the values the plan just fixed.
    let opts = EditOptions { spin_addr: spin, fb_enable, ausb };
    let dtb = bundle::edit_dtb(&dtb_src, &plan, &opts).map_err(|e| (3, e))?;
    // What gets staged is the *edited* blob, which is larger than its source, so the plan adopts
    // that size before any size-dependent check runs.
    let mut plan = plan;
    plan.adopt_edited_dtb(dtb.len() as u64).map_err(|e| (3, format!("{} ({:#x})", e.code, e.detail)))?;
    if let Some(p) = &dump_dtb {
        std::fs::write(p, &dtb).map_err(|e| (4, format!("{p}: {e}")))?;
    }

    // 4. Descriptor + steps.
    let blobs = BootBlobs { payload: payload.clone(), dtb: dtb.clone(), image: image.clone(), initrd: initrd.clone() };
    let steps = bundle::build_steps(&blobs, &plan, &opts).map_err(|e| (3, e))?;
    let budget = bundle::TransferBudget::default();
    let descriptor = bundle::build_descriptor(&plan, &header, &opts).map_err(|e| (3, e))?;

    // 5. Print everything.
    println!("# a9boot plan — computed offline. NOTHING IS SENT by this build.");
    println!("image      {} ({} bytes, text_offset {:#x}, image_size {:#x})",
        image_path, image.len(), header.text_offset, header.image_size);
    println!("           reserve {:#x} bytes (footprint = _end - _text, .bss included), transfer {:#x} \
bytes (the file), gap {:#x} bytes = .bss the kernel clears itself{}",
        extent.reserve, extent.transfer, extent.bss_gap,
        if extent.is_exact() { " (no gap: file == footprint)" } else { "" });
    if !artefact_verified {
        println!(
            "           WARNING: image artefact NOT verified. The header cannot detect a truncated \
tail — a short file looks like a large .bss. Pass --expect-image-size and/or --expect-image-sha256 \
(from the build log) before staging this on hardware."
        );
    }
    println!("dtb        {} -> {} bytes edited", dtb_path, dtb.len());
    println!("initramfs  {}", initramfs.as_deref().unwrap_or("(none)"));
    println!("payload    {} bytes{}", payload.len(),
        if payload.is_empty() { " (NOT SUPPLIED: exec packets cannot be sized)" } else { "" });
    match ausb {
        Some(a) => println!("usb        console=ttyGS0 enabled; cfg0-device={:#010x} cfg1-device={:#010x}",
            a.cfg0_device, a.cfg1_device),
        None => println!("usb        NO AUSB tunables: the PHY will not probe and USB stays dead \
                          (run `probe` first)"),
    }
    println!();
    println!("## physical layout (DRAM base {:#x}, {} MiB nominal, INFERRED until probed)",
        plan.dram_base, plan.dram_size / (1024 * 1024));
    for r in plan.regions() {
        println!("  {:<8} {:#014x} + {:#012x}   {}", r.name, r.addr, r.size, note_for(r.name));
    }
    println!("  entry    {:#014x}          (booting.rst: call the Image's first instruction)", plan.kernel_entry);
    println!();
    println!("## /reserved-memory children (plain, never no-map)");
    for r in plan.reservations() {
        println!("  {:#014x} + {:#012x}   {}", r.addr, r.size, bundle::reservation_node_name(r.name, r.addr));
    }
    println!();
    println!("## bootargs  {:?}", plan.bootargs.as_str());
    println!("## descriptor at {:#x} ({} bytes)", DESCRIPTOR_ADDR, abi::DESCRIPTOR_SIZE);
    println!("   flags {:#x}  vectors {:#x}  mailbox {:#x}  stack top {:#x}  spin {:#x}",
        descriptor.flags, descriptor.vectors_addr, descriptor.mailbox_addr, descriptor.stack_top,
        descriptor.spin_addr);
    match descriptor.validate() {
        Ok(()) => println!("   descriptor validation: OK (the payload runs the same check)"),
        Err((c, d)) => println!("   descriptor validation: {} ({:#x})", abi::status::name(c), d),
    }
    println!();
    println!("## hand-off contract (asserted against the bytes actually staged)");
    match bundle::handoff_contract(&dtb, &plan, &steps, &opts) {
        Ok(c) => println!("  {}", c.report()),
        Err(e) => println!("  REFUSED (build_steps would have failed too): {e}"),
    }
    println!();
    println!("## command sequence (chunked to a {} byte buffer, {}-byte transfers)",
        budget.buffer_capacity, bundle::DNLOAD_CHUNK);
    let mut bytes_sent = 0usize;
    let mut largest = 0usize;
    for (n, s) in steps.iter().enumerate() {
        match s {
            Step::Comment(c) => println!("  {n:>3}  # {c}"),
            other => {
                for (k, p) in bundle::step_packets(other, &payload, &bundle::TransferBudget::default()).iter().enumerate() {
                    bytes_sent += p.dnload.len();
                    largest = largest.max(p.dnload.len());
                    let t = budget.transfers(p.dnload.len());
                    println!("  {n:>3}{}  DNLOAD {:>8} bytes ({} transfer{})  UPLOAD {:>5}  {}",
                        if k == 0 { " " } else { "+" }, p.dnload.len(), t, if t == 1 { "" } else { "s" }, p.upload_len, p.label);
                }
            }
        }
    }
    println!();
    println!("largest single command: {largest} bytes; total DNLOAD bytes: {bytes_sent}");
    println!("no device was opened, and this build cannot open one.");
    Ok(())
}

/// `pagewalk`: decide whether an address may be touched, without touching it.
#[allow(unused_mut)]
fn pagewalk_cmd(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let mut live = false;
    let mut json: Option<String> = None;
    let mut lookups: Vec<u64> = Vec::new();
    let mut root = a9boot_host::pagetable::ROM_TTBR0_TABLES;
    let mut root_explicit = false;
    let mut granule = a9boot_host::pagetable::Granule::Granule4k;
    let mut t0sz: u8 = 16; // 48-bit input; MEASURED on this unit: TCR_EL3.T0SZ = 27
    let mut canary = true;
    let mut find_root = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--live" => live = true,
            "--no-canary" => canary = false,
            "--find-root" => find_root = true,
            "--json" => {
                i += 1;
                json = Some(args.get(i).cloned().ok_or((2, "--json needs a file path".into()))?);
            }
            "--lookup" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--lookup needs an address".into()))?;
                lookups.push(parse_int(&v)?);
            }
            "--root" => {
                i += 1;
                root = parse_int(&args.get(i).cloned().ok_or((2, "--root needs an address".into()))?)?;
                root_explicit = true;
            }
            "--granule" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--granule needs 4k|16k|64k".into()))?;
                granule = a9boot_host::pagetable::Granule::from_arg(&v)
                    .ok_or((2, format!("pagewalk: unknown granule {v:?} (expected 4k|16k|64k)")))?;
            }
            "--t0sz" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--t0sz needs a number".into()))?;
                t0sz = v
                    .parse::<u8>()
                    .map_err(|_| (2, format!("--t0sz: {v:?} is not a u8")))?;
            }
            other => return Err((2, format!("pagewalk: unknown option {other:?}"))),
        }
        i += 1;
    }
    if lookups.is_empty() {
        return Err((2, "--lookup ADDR is required (repeatable)".into()));
    }
    // The positive controls: addresses MEASURED to be mapped. Without one of these decoding
    // MAPPED, an UNMAPPED answer says nothing about the lookup — it says the walk is broken. The
    // default set is the canary and the payload staging address, so every run proves the walk can
    // say "yes" before any "no" is believed.
    let controls: Vec<u64> = a9boot_host::pagetable::positive_controls()
        .iter()
        .map(|(a, _)| *a)
        .collect();
    let root_origin = if root_explicit {
        "explicitly provided via --root".to_string()
    } else {
        "INSPECTED gaster.c:627-631 (a CANDIDATE, not the measured root — see RUNG2-EVIDENCE §6.0)"
            .to_string()
    };
    println!("# a9boot pagewalk — may I touch this address? (read-only; touches no lookup address)");
    println!("  root       {root:#x} ({root_origin})");
    println!("  granule    {} (NOT YET MEASURED — tcr_el3.TG0 was not captured; the level structure is only correct for the granule it is TOLD)", granule.name());
    println!("  canary     {}", if canary { "yes: the handler's own bytes must match first" } else { "DISABLED (unsafe)" });
    println!("  find-root  {}", if find_root { "yes: sweep SRAM for the base that proves itself on the canary" } else { "no: --root is used as given" });
    for c in &controls {
        println!("  control    {c:#x} (MEASURED mapped; the run FAILS if this does not walk to MAPPED)");
    }
    for a in &lookups {
        println!("  lookup     {a:#x}");
    }
    println!("  {} entries x 8 bytes per level, read through `memc read`; a table pointer outside", granule.entries_per_level());
    println!("  known-mapped SRAM is REFUSED by name rather than followed.");
    println!();
    if !live {
        println!("DRY RUN. Nothing was sent.");
        println!("VERDICT       UNKNOWN — nothing was sent (exit 6 by design).");
        return Ok(ExitCode::from(6));
    }
    pagewalk_live(&lookups, root, canary, find_root, &controls, granule, t0sz, json.as_deref())
}

fn pagewalk_live(
    lookups: &[u64],
    mut root: u64,
    canary: bool,
    find_root: bool,
    controls: &[u64],
    granule: a9boot_host::pagetable::Granule,
    t0sz: u8,
    json: Option<&str>,
) -> Result<ExitCode, (u8, String)> {
    let start_level = granule.first_level_for_t0sz(t0sz);
    live_gate()?;
    #[cfg(feature = "usb")]
    {
        use a9boot_host::channel::{self, check_identity, Expect};
        use a9boot_host::evidence::{self, Recorder, Verdict};
        use a9boot_host::pagetable::{self, Mapping};
        use a9boot_host::transport::{live::LiveTransport, Transport};
        let t = LiveTransport::open().map_err(|e| (4, e))?;
        let mut rec = Recorder::new(t);
        let serial = rec.serial().map_err(|e| (4, e))?;
        check_identity(&serial, &Expect::default())
            .map_err(|e| (3, format!("identity check refused before sending anything: {e}")))?;
        rec.note("identity: CPID 0x8003, BDID 0x02, PWND:[checkm8] all present".to_string());

        // The canary: the handler's own bytes, a page the CPU is executing right now.
        if canary {
            let p = channel::mem_read(execmod::HANDLER_ADDR, 32);
            let e = evidence::exchange_for(&p, "canary: the resident handler's first 32 bytes", Sequence::Reference);
            let raw = rec.exchange(&e).map_err(|err| (5, format!("canary read failed: {err}")))?;
            let r = channel::parse_response(&raw, p.upload_len).map_err(|err| (7, err))?;
            let got = evidence::hex(&r.data[..32.min(r.data.len())]);
            if !got.eq_ignore_ascii_case(execmod::HANDLER_FIRST_32_HEX) {
                let msg = format!(
                    "CANARY_FAILED: the handler's first bytes are {got}, expected {}. The page                      that is executing this very request does not read back as the reference                      handler, so SRAM reads are not behaving as assumed and the tables will NOT be                      read. Nothing further is sent.",
                    execmod::HANDLER_FIRST_32_HEX
                );
                rec.note(msg.clone());
                let t = rec.transcript(command_line(), "live", vec![msg], vec![], Some((Verdict::Fail, None)));
                println!("{}", t.human());
                if let Some(p) = json { write_json(p, &t)?; }
                return Err((7, "canary failed".into()));
            }
            rec.note("CANARY OK: the resident handler reads back as the 248-byte reference build".to_string());
        }

        // 0. Root. If asked, find the base that PROVES itself on a known-mapped address; an
        //    INSPECTED constant that walks everything to UNMAPPED is not truth, and the hardware
        //    run proved it wrong (r18-pagewalk: every lookup UNMAPPED at level 0, entry 0 zero).
        if find_root {
            let prove = controls.first().copied().unwrap_or(execmod::HANDLER_ADDR);
            // Sweep and prove, inline: one `&mut rec` at a time, in order.
            let mut candidates: Vec<u64> = Vec::new();
            let sram_end = layout::SRAM_BASE + 0x0040_0000;
            let mut cand = layout::SRAM_BASE;
            let mut sweep_err: Option<String> = None;
            while cand < sram_end {
                match read8_at(&mut rec, cand) {
                    Ok(b) => {
                        let raw = u64::from_le_bytes(b);
                        // entry 0 must be a table descriptor (0b11) pointing into SRAM; the table
                        // address field width is the granule's (bits[47:12]/[47:14]/[47:16]).
                        if raw & 0b11 == 0b11
                            && (layout::SRAM_BASE..sram_end).contains(&(raw & granule.table_mask()))
                        {
                            candidates.push(cand);
                        }
                    }
                    Err(e) => {
                        sweep_err = Some(format!("sweep stopped at {cand:#x}: {e}"));
                        break;
                    }
                }
                cand += 4096;
            }
            let mut notes = vec![format!(
                "root sweep: {} pages in SRAM, {} with a level-0 table descriptor at entry 0{}",
                (sram_end - layout::SRAM_BASE) / 4096,
                candidates.len(),
                sweep_err.map(|e| format!(" ({e})")).unwrap_or_default()
            )];
            let mut found: Option<u64> = None;
            for c in &candidates {
                // Prove by walking the control address from this candidate, via the SAME walk the
                // lookups use, so the proof and the answer cannot disagree.
                let mapping = pagetable::walk_with(prove, *c, granule, start_level, |level, base| {
                    if let Err(e) = pagetable::may_follow(base, false) {
                        return Err(e);
                    }
                    read_table_entries(&mut rec, base, level, granule)
                });
                if mapping.may_touch() {
                    notes.push(format!("root candidate {c:#x} PROVED on {prove:#x}"));
                    found = Some(*c);
                    break;
                }
            }
            match found {
                Some(b) => {
                    root = b;
                    println!("  ROOT FOUND: {root:#x} ({candidates:?} were plausible)");
                }
                None => {
                    let msg = format!(
                        "NO_POSITIVE_CONTROL: no SRAM base walks {prove:#x} to MAPPED, so this walk \
                         cannot answer whether anything is mapped and every UNMAPPED it could print \
                         would be uninterpretable. Refusing the run."
                    );
                    rec.note(msg.clone());
                    let t = rec.transcript(command_line(), "live", vec![msg], vec![], Some((Verdict::Fail, None)));
                    println!("{}", t.human());
                    if let Some(p) = json { write_json(p, &t)?; }
                    return Err((7, "no root found".into()));
                }
            }
        }

        // The walk. Every table read is chunked to the channel's read limit, and every pointer is
        // checked before it is followed.
        // POSITIVE CONTROLS FIRST, through the very same code path. Without one of these decoding
        // MAPPED, every UNMAPPED below is uninterpretable ("the walk says no to everything" is not
        // evidence about an address), and the run is refused rather than reported.
        let mut pending: Vec<u64> = controls.iter().copied().chain(lookups.iter().copied()).collect();
        pending.dedup();
        let mut results: Vec<(u64, Mapping)> = Vec::new();
        let mut tables_read = 0usize;
        let mut refused: Option<String> = None;
        for target in pending.drain(..) {
            let mut tables = 0usize;
            let mapping = pagetable::walk_with(target, root, granule, start_level, |level, base| {
                if let Err(e) = pagetable::may_follow(base, false) {
                    return Err(e);
                }
                tables += 1;
                read_table_entries(&mut rec, base, level, granule)
            });
            tables_read += tables;
            println!("{target:#014x}  {}  {}", mapping.name(), mapping.summary());
            if !mapping.may_touch() {
                refused = Some(format!("{target:#x}: {}", mapping.summary()));
            }
            results.push((target, mapping));
        }
        let mut warnings = Vec::new();
        let controls_ok = controls
            .iter()
            .all(|c| results.iter().any(|(a, m)| a == c && m.may_touch()));
        if !controls_ok {
            let msg = "NO_POSITIVE_CONTROL: a known-mapped address (the resident handler or the DFU \
                       staging address) did not walk to MAPPED, so this walk cannot say 'yes' \
                       anywhere and its 'no' answers mean nothing. Every UNMAPPED above is \
                       UNINTERPRETABLE — the root is wrong, not the mapping."
                .to_string();
            warnings.push(msg.clone());
            rec.note(msg);
            let t = rec.transcript(command_line(), "live", warnings, vec![], Some((Verdict::Fail, Some(
                "no positive control: the walk mapped nothing it knows to be mapped".into()))));
            println!("{}", t.human());
            if let Some(p) = json { write_json(p, &t)?; }
            return Err((7, "no positive control".into()));
        }
        if let Some(r) = &refused {
            warnings.push(format!("DO NOT TOUCH {r}"));
        }
        let extras = vec![
            ("tables_read".to_string(), tables_read.to_string()),
            (
                "mappings".to_string(),
                format!(
                    "[{}]",
                    results
                        .iter()
                        .map(|(a, m)| format!(
                            "{{\"addr\": \"{a:#x}\", \"mapping\": \"{}\", \"may_touch\": {}}}",
                            m.name(),
                            m.may_touch()
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
        ];
        let verdict = if results.iter().all(|(_, m)| m.may_touch()) { Verdict::Pass } else { Verdict::Fail };
        let _ = &controls;
        let t = rec.transcript(command_line(), "live", warnings, extras, Some((verdict, refused)));
        println!("{}", t.human());
        if let Some(p) = json { write_json(p, &t)?; }
        Ok(if verdict == Verdict::Pass { ExitCode::SUCCESS } else { ExitCode::from(7) })
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = (lookups, root, canary, find_root, controls, granule, json);
        Err((3, "this build has no USB capability. Rebuild with --features usb.".to_string()))
    }
}

/// `capacity`: the U-2 ladder, run before anything large is sent.
fn capacity_cmd(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let mut live = false;
    let mut json: Option<String> = None;
    let mut pairs: Vec<(usize, usize)> = capmod::DEFAULT_STEPS.iter().map(|n| (*n, *n)).collect();
    let mut sequence = Sequence::Reference;
    let mut discriminate = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--live" => live = true,
            "--json" => {
                i += 1;
                json = Some(args.get(i).cloned().ok_or((2, "--json needs a file path".into()))?);
            }
            // `--steps 8192:2048,2048:8192,...` — command:reply. Reply defaults to the command
            // length (the first hardware ladder's shape) ONLY if omitted; the discriminating
            // preset below never omits it.
            "--steps" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--steps needs CMD[:REPLY],...".into()))?;
                pairs = v
                    .split(',')
                    .map(|part| {
                        let (c, r) = part.trim().split_once(':').unwrap_or((part.trim(), part.trim()));
                        let cmd = parse_int(c)? as usize;
                        let rep = parse_int(r)? as usize;
                        if cmd <= abi::HEADER_LEN as usize {
                            return Err((2, format!("step {cmd} is not larger than the 72-byte header")));
                        }
                        Ok((cmd, rep))
                    })
                    .collect::<Result<Vec<_>, (u8, String)>>()?;
            }
            "--discriminate" => discriminate = true,
            "--sequence" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--sequence needs a value".into()))?;
                sequence = Sequence::parse(&v)
                    .ok_or((2, format!("--sequence {v:?} is not minimal|terminated|reference")))?;
            }
            other => return Err((2, format!("capacity: unknown option {other:?}"))),
        }
        i += 1;
    }

    if discriminate {
        // Four cells that separate the three hypotheses the first ladder conflated. Smallest
        // first, and every step stops the ladder on failure.
        pairs = capmod::DISCRIMINATE_CELLS.to_vec();
    }
    let need = capmod::required_command_bytes();
    println!("# a9boot capacity — the U-2 ladder (how large ONE command can be).");
    println!("  required command   {need:#x} bytes (PAYLOAD_OFF {:#x} + the 10,640-byte payload image)", abi::PAYLOAD_OFF);
    println!("  assumed capacity   {:#x} bytes (the value every budget in this tree uses, unmeasured)", bundle::ASSUMED_BUFFER_CAPACITY);
    println!(
        "  ladder (command:reply bytes): {:?}",
        pairs.iter().map(|(c, r)| format!("{c:#x}:{r:#x}")).collect::<Vec<_>>()
    );
    if pairs.iter().any(|(c, r)| c != r) {
        println!("  NOTE: command and reply lengths differ here ON PURPOSE — the first hardware ladder");
        println!("  confounded them, and its 8192 failure was a host-side LIBUSB INVALID_PARAM on the");
        println!("  REPLY path, not a device stall. These cells separate the two.");
    }
    println!("  each step is ONE command whose header is memcpy(0,0,0): no destination, no source, no");
    println!("  length. It writes nothing anywhere, and the reply echoes the appended data back for");
    println!("  comparison. The ladder stops at the first step that does not come back intact.");
    println!();
    if !live {
        println!("DRY RUN. Nothing was sent.");
        println!("VERDICT       UNKNOWN — nothing was sent (exit 6 by design).");
        if let Some(p) = &json {
            let rec: evidence::Recorder<DeadTransport> = evidence::Recorder::new(DeadTransport);
            let t = rec.transcript(
                command_line(),
                "dry-run",
                vec!["this was a dry run: the ladder measured nothing, so the capacity is still the \
                      measured lower bound 0x1000 and anything above it stays UNVERIFIED"
                    .to_string()],
                vec![(
                    "capacity_ladder_planned".to_string(),
                    format!(
                        "[{}]",
                        pairs
                            .iter()
                            .map(|(c, r)| format!("{{\"command\": {c}, \"reply\": {r}}}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )],
                None,
            );
            write_json(p, &t)?;
        }
        return Ok(ExitCode::from(6));
    }
    capacity_live(&pairs, sequence, json.as_deref())
}

fn capacity_live(
    pairs: &[(usize, usize)],
    sequence: Sequence,
    json: Option<&str>,
) -> Result<ExitCode, (u8, String)> {
    live_gate()?;
    #[cfg(feature = "usb")]
    {
        use a9boot_host::channel::{check_identity, Expect};
        use a9boot_host::evidence::{Recorder, Verdict};
        use a9boot_host::transport::live::LiveTransport;
        let t = LiveTransport::open().map_err(|e| (4, e))?;
        let mut rec = Recorder::new(t);
        let serial = rec.serial().map_err(|e| (4, e))?;
        check_identity(&serial, &Expect::default())
            .map_err(|e| (3, format!("identity check refused before sending anything: {e}")))?;
        rec.note("identity: CPID 0x8003, BDID 0x02, PWND:[checkm8] all present".to_string());
        match rec.dfu_status() {
            Ok(s) => rec.note(format!("DFU state before the ladder: {}", s.summary())),
            Err(e) => rec.note(format!("DFU state UNREAD: {e}")),
        }
        let (report, notes) = capmod::run_ladder_pairs(&mut rec, &pairs, sequence);
        for n in &notes {
            rec.note(n.clone());
        }
        println!("{}", report.declaration());
        println!("{}", report.brackets());
        let need = capmod::required_command_bytes();
        let mut warnings = Vec::new();
        let mut verdict = if report.lower_bound > 0 { Verdict::Pass } else { Verdict::Fail };
        let mut reason = None;
        match report.fits(need) {
            Ok(()) => rec.note(format!(
                "the payload's {need:#x}-byte EXEC command is ADMISSIBLE against the measured                  bracket"
            )),
            Err(e) => {
                warnings.push(format!(
                    "{e} Re-cut the payload smaller, or stream it in pieces, before any upload."
                ));
                verdict = Verdict::Fail;
                reason = Some(e);
            }
        }
        if report.first_failure.is_some() && report.lower_bound < capmod::assumed_max_command() {
            warnings.push(format!(
                "the ASSUMED capacity ({:#x}) is above the measured bracket: every budget in this                  tree that uses `TransferBudget::default()` is now known to be optimistic, and                  U-2 must be recorded as a measured ceiling, not an assumption.",
                capmod::assumed_max_command()
            ));
        }
        let extras = vec![
            (
                "capacity".to_string(),
                format!(
                    "{{\"lower_bound_command_bytes\": {}, \"first_failure_command_bytes\": {},                      \"reached_ceiling\": {}, \"required_command_bytes\": {}, \"lower_bound_hex\": \"{:#x}\"}}",
                    report.lower_bound,
                    report.first_failure.map(|n| n.to_string()).unwrap_or_else(|| "null".into()),
                    report.reached_ceiling,
                    need,
                    report.lower_bound
                ),
            ),
            (
                "capacity_steps".to_string(),
                format!(
                    "[{}]",
                    report
                        .steps
                        .iter()
                        .map(|s| format!(
                            "{{\"command_len\": {}, \"outcome\": \"{}\", \"first_mismatch\": {}}}",
                            s.command_len,
                            s.outcome.name(),
                            s.first_mismatch.map(|o| o.to_string()).unwrap_or_else(|| "null".into())
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
        ];
        if rec.records.is_empty() {
            verdict = Verdict::Unknown;
        }
        let t = rec.transcript(command_line(), "live", warnings, extras, Some((verdict, reason)));
        println!("{}", t.human());
        if let Some(p) = json {
            write_json(p, &t)?;
        }
        Ok(match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Unknown => ExitCode::from(6),
            Verdict::Fail if report.lower_bound == 0 => ExitCode::from(5),
            Verdict::Fail => ExitCode::from(7),
        })
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = (pairs, sequence, json);
        Err((3, "this build has no USB capability. Rebuild with --features usb; device access is \
                 Lead-only."
            .to_string()))
    }
}

/// `exec`: deliver the a9boot payload and run it — verified first, triggered second.
///
/// `--cmd PING` is the first thing that should ever be executed on this device, because it reads
/// nothing outside the DFU buffer: it proves our code runs at EL3 and returns, with a blast radius
/// of one 16 KiB SRAM buffer.
fn exec_cmd(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let mut live = false;
    let mut json: Option<String> = None;
    let mut payload_path: Option<String> = None;
    let mut cmd_name = "PING".to_string();
    let mut sequence = Sequence::Reference;
    let mut sequence_set = false;
    // The budget's capacity. Default: the conservative measured lower bound. A capacity measured by
    // the ladder may RAISE it, never lower the guard, and the run prints which one it used and
    // where the number came from — a retyped constant is what this flag exists to avoid.
    let mut capacity: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--live" => live = true,
            "--json" => {
                i += 1;
                json = Some(args.get(i).cloned().ok_or((2, "--json needs a file path".into()))?);
            }
            "--payload" => {
                i += 1;
                payload_path =
                    Some(args.get(i).cloned().ok_or((2, "--payload needs a file".into()))?);
            }
            // `--capacity-from ladder.json` reads the number out of the run that produced it, so
            // the trace survives; `--capacity N` is the same thing typed by hand and is labelled
            // as such.
            "--capacity" | "--capacity-from" => {
                let from_file = args[i] == "--capacity-from";
                i += 1;
                let v = args.get(i).cloned().ok_or((2, format!("{} needs a value", args[i - 1])))?;
                if from_file {
                    let text = std::fs::read_to_string(&v).map_err(|e| (4, format!("{v}: {e}")))?;
                    let n = extract_capacity(&text).ok_or((
                        4,
                        format!(
                            "{v}: no capacity.command_lower_bound_command_bytes / \
                             \"lower_bound_command_bytes\" field found; refusing to guess"
                        ),
                    ))?;
                    capacity = Some(n);
                    println!("capacity   {n:#x} command bytes, read from {v} (a LADDER RESULT: a \
lower bound from a pass, not a buffer size — U-2 stays bounded-above-unknown)");
                } else {
                    let n = parse_int(&v)? as usize;
                    capacity = Some(n);
                    println!("capacity   {n:#x} command bytes, from --capacity (TYPED BY HAND: not \
traceable to a run — prefer --capacity-from)");
                }
            }
            "--cmd" => {
                i += 1;
                cmd_name = args.get(i).cloned().ok_or((2, "--cmd needs PING|DESCRIBE".into()))?;
            }
            "--sequence" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((2, "--sequence needs a value".into()))?;
                sequence = Sequence::parse(&v)
                    .ok_or((2, format!("--sequence {v:?} is not minimal|terminated|reference")))?;
                sequence_set = true;
            }
            other => return Err((2, format!("exec: unknown option {other:?}"))),
        }
        i += 1;
    }
    let _ = sequence_set;
    let path = payload_path.ok_or((2, "--payload is required".into()))?;
    let cmd = match cmd_name.to_ascii_uppercase().as_str() {
        "PING" => Command::Ping,
        "DESCRIBE" => Command::Describe,
        other => {
            return Err((
                2,
                format!(
                    "exec --cmd {other:?}: only PING and DESCRIBE are executable first. PREPARE \
                     and GO touch DRAM and the CPU state, and need the DRAM extent measured first."
                ),
            ))
        }
    };

    // Flatten and check. This is what makes the verified bytes the same bytes that were reviewed.
    let raw = read(&path)?;
    let flat = a9boot_host::elf::flatten(&raw).map_err(|e| (4, format!("{path}: {e}")))?;
    flat.check().map_err(|e| (3, format!("{path}: {e}")))?;
    let default_capacity = bundle::TransferBudget::default().buffer_capacity;
    let budget_capacity = match capacity {
        Some(n) if n > default_capacity => n,
        Some(n) => {
            return Err((
                2,
                format!(
                    "--capacity {n:#x} is BELOW the conservative default {default_capacity:#x}: a \
                     supplied capacity may only raise the budget, never lower the guard."
                ),
            ))
        }
        None => default_capacity,
    };
    let budget = bundle::TransferBudget { buffer_capacity: budget_capacity };
    let needs = abi::PAYLOAD_OFF as usize + flat.bytes.len();
    println!(
        "  capacity     {budget_capacity:#x} command bytes ({})",
        if capacity.is_some() {
            "measured; the ladder's lower bound"
        } else {
            "the conservative default; pass --capacity-from <ladder.json> once the ladder has measured it"
        }
    );
    if needs > budget.buffer_capacity {
        return Err((
            3,
            format!(
                "the EXEC command is {needs} bytes but the buffer capacity in use is {} — the \
                 command would overrun the buffer, which is corruption rather than a stall. Probe \
                 the capacity with `capacity --live --steps {needs}:2048` and pass the result with \
                 --capacity-from.",
                budget.buffer_capacity
            ),
        ));
    }

    let plan = execmod::plan_exec(&flat.bytes);
    println!("# a9boot exec — payload {} -> flat: {}", path, flat.summary());
    println!(
        "  command      EXEC {} ({}), packet {} bytes = {} DNLOAD transfers",
        cmd.name(),
        cmd as u64,
        plan.packet_len,
        plan.transfers
    );
    println!("  staged at    {:#x} (entry {:#x}), inside the ROM's DFU buffer", plan.payload_addr, flat.entry);
    println!("  verification {} read-back chunk(s) of {} bytes, compared byte for byte", plan.verify_chunks, plan.verify_chunk_len);
    println!("  sequence     {}", sequence.name());
    for (n, st) in sequence.steps(plan.packet_len, abi::upload_len_for(abi::REPLY_SIZE as u64) as u16).iter().enumerate() {
        println!("    step {}: {st}", n + 1);
    }
    println!();
    println!("  ORDER: stage (no trigger) -> read the staged bytes back -> compare -> re-stage -> trigger.");
    println!("  If the comparison fails, NOTHING IS EXECUTED (exit 9). That is the whole point: the");
    println!("  handler runs whatever the buffer holds the moment the 0xFFFF UPLOAD arrives.");
    println!();
    if !live {
        println!("DRY RUN. Nothing was sent.");
        println!("VERDICT       UNKNOWN — nothing was sent (exit 6 by design).");
        if let Some(p) = &json {
            let rec: evidence::Recorder<DeadTransport> = evidence::Recorder::new(DeadTransport);
            let t = rec.transcript(
                command_line(),
                "dry-run",
                vec!["this was a dry run: the verdict is UNKNOWN because nothing was sent, so                       every exchange field is UNREAD by construction"
                    .to_string()],
                vec![(
                    "exec_plan".to_string(),
                    format!(
                        "{{\"payload_len\": {}, \"payload_addr\": \"{:#x}\", \"packet_len\": {}, \"dnload_transfers\": {}, \"verify_chunks\": {}}}",
                        plan.payload_len, plan.payload_addr, plan.packet_len, plan.transfers, plan.verify_chunks
                    ),
                )],
                None,
            );
            write_json(p, &t)?;
        }
        return Ok(ExitCode::from(6));
    }

    exec_live(&flat.bytes, cmd, sequence, json.as_deref())
}

fn exec_live(
    payload: &[u8],
    cmd: Command,
    sequence: Sequence,
    json: Option<&str>,
) -> Result<ExitCode, (u8, String)> {
    live_gate()?;
    #[cfg(feature = "usb")]
    {
        use a9boot_host::channel::{check_identity, Expect};
        use a9boot_host::evidence::{Recorder, Verdict};
        use a9boot_host::transport::live::LiveTransport;
        let t = LiveTransport::open().map_err(|e| (4, e))?;
        let mut rec = Recorder::new(t);
        let serial = rec.serial().map_err(|e| (4, e))?;
        check_identity(&serial, &Expect::default())
            .map_err(|e| (3, format!("identity check refused before sending anything: {e}")))?;
        rec.note("identity: CPID 0x8003, BDID 0x02, PWND:[checkm8] all present".to_string());

        // The state pre-read: the machine must accept a fresh download.
        match rec.dfu_status() {
            Ok(s) => rec.note(format!("DFU state before staging: {}", s.summary())),
            Err(e) => rec.note(format!("DFU state UNREAD: {e}")),
        }

        let (rep, outcome) = execmod::run_exec(&mut rec, payload, cmd, sequence);
        for n in &rep.notes {
            rec.note(n.clone());
        }

        let mut verdict = rec.verdict();
        let mut reason = rec.verdict_reason();
        let mut exit = match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Unknown => ExitCode::from(6),
            Verdict::Fail => ExitCode::from(7),
        };
        if let Some(hard) = &rep.hard_fail {
            verdict = Verdict::Fail;
            reason = Some(hard.clone());
            exit = if hard.starts_with("STAGED_IMAGE") || hard.starts_with("RESTAGE") {
                ExitCode::from(9) // refused to execute: verification failed
            } else {
                ExitCode::from(5) // no reply
            };
        }

        // The PASS criterion for EXEC, checked structurally.
        if let Ok(raw) = &outcome {
            let want = abi::upload_len_for(abi::REPLY_SIZE as u64) as u16;
            match execmod::check_exec_reply(raw, want, cmd) {
                Ok(reply) => rec.note(format!(
                    "EXEC PASS: the payload ran. command echo {}, status {}, current_el {:#x},                      midr {:#x}, mpidr {:#x}",
                    reply.command, reply.status, reply.current_el, reply.midr_el1, reply.mpidr_el1
                )),
                Err(e) => {
                    verdict = Verdict::Fail;
                    reason = Some(e.clone());
                    exit = ExitCode::from(7);
                    rec.note(format!("EXEC reply rejected: {e}"));
                }
            }
        } else if let Err(e) = outcome {
            rec.note(format!("no trigger reply: {e}"));
        }

        // No exchange at all can never be PASS.
        if rec.records.is_empty() {
            verdict = Verdict::Unknown;
            exit = ExitCode::from(6);
        }
        let extras = {
            let mut v = rep.extras.clone();
            v.push((
                "exec_pass_criterion".to_string(),
                format!(
                    "[{}]",
                    execmod::pass_criterion()
                        .iter()
                        .map(|s| json_string(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
            v
        };
        let t = rec.transcript(command_line(), "live", rep.warnings.clone(), extras, Some((verdict, reason)));
        println!("{}", t.human());
        if let Some(p) = json {
            write_json(p, &t)?;
        }
        Ok(exit)
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = (payload, cmd, sequence, json);
        Err((3, "this build has no USB capability. Rebuild with --features usb; device access is                  Lead-only."
            .to_string()))
    }
}

/// The first-light sequence: the smallest thing that can prove the channel works.
///
/// The **default** is one read-only `MEMC` read. `--write` adds a content-verifiable write; the
/// dry run prints exactly what a live run would send, and exits **6 (UNKNOWN)** so that a run that
/// sent nothing can never look like a run that verified something.
fn firstlight_cmd(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let mut live = false;
    let mut json: Option<String> = None;
    let mut reads: Vec<ReadSpec> = Vec::new();
    let mut write: Option<WriteSpec> = None;
    let mut sequence = Sequence::Minimal;
    let mut status = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--live" => live = true,
            "--no-status" => status = false,
            "--json" => {
                i += 1;
                json = Some(args.get(i).cloned().ok_or((2, "--json needs a file path".into()))?);
            }
            "--read" => {
                i += 1;
                let v = args.get(i).ok_or((2, "--read needs ADDR:LEN".to_string()))?;
                reads.push(ReadSpec::parse(v).map_err(|e| (2, e))?);
            }
            "--write" => {
                i += 1;
                let v = args.get(i).ok_or((2, "--write needs ADDR:LEN".to_string()))?;
                write = Some(WriteSpec::parse(v).map_err(|e| (2, e))?);
            }
            // `--sequence` is the honest name (the reference shape is a sequence, not just a
            // terminator). `--terminator none|dfu` is kept as an alias because two hardware
            // attempts have already been made under those names and the A/B must stay comparable.
            "--sequence" | "--terminator" => {
                i += 1;
                let v = args.get(i).cloned().ok_or((
                    2,
                    "--sequence wants minimal|terminated|reference (aliases: none|dfu|gaster)"
                        .to_string(),
                ))?;
                sequence = Sequence::parse(&v).ok_or((
                    2,
                    format!("--sequence {v:?} is not minimal|terminated|reference"),
                ))?;
            }
            other => return Err((2, format!("firstlight: unknown option {other:?}"))),
        }
        i += 1;
    }
    if reads.is_empty() {
        reads.push(firstlight::DEFAULT_READ);
    }
    let o = FlOptions { reads, write, sequence, status };

    // Print what will be sent **before** sending it: the operator compares this against the
    // runbook's expected bytes, and it is the same list `planned_packets` gives a live run.
    let planned = firstlight::planned_packets(&o);
    println!("# a9boot firstlight — {} packet(s), {} exchange(s)", planned.len(), o.reads.len() + usize::from(o.write.is_some()));
    for (n, p) in planned.iter().enumerate() {
        println!(
            "  [{n}] DNLOAD {:>6} bytes ({} transfer{})  UPLOAD wLength {:>4}  {}",
            p.packet.dnload.len(),
            p.packet.dnload.len().div_ceil(bundle::DNLOAD_CHUNK),
            if p.packet.dnload.len() > bundle::DNLOAD_CHUNK { "s" } else { "" },
            p.packet.upload_len,
            p.packet.label
        );
        println!("       purpose: {}", p.purpose);
        if p.packet.dnload.len() <= 256 {
            println!("       DNLOAD  {}", evidence::hex(&p.packet.dnload));
        } else {
            println!(
                "       DNLOAD  sha256 {} ({} bytes; full bytes in the JSON evidence)",
                evidence::sha256_hex(&p.packet.dnload),
                p.packet.dnload.len()
            );
        }
    }
    println!("  sequence: {}", o.sequence.name());
    for (n, st) in o.sequence.steps(planned.first().map(|p| p.packet.dnload.len()).unwrap_or(0),
                                     planned.first().map(|p| p.packet.upload_len).unwrap_or(0)).iter().enumerate() {
        println!("    step {}: {st}", n + 1);
    }
    if o.sequence != Sequence::Reference {
        println!(
            "  NOTE: this is NOT the reference's full command framing. `--sequence reference` adds \
             the 16-byte suffix DNLOAD, the zero-length DNLOAD and the MANIFEST_SYNC->MANIFEST->\
             MANIFEST_WAIT_RESET walk (gaster.c:977-988, :829-834) before the trigger."
        );
    }
    println!();

    if !live {
        println!("DRY RUN. Nothing below was sent: this build was not asked to open a device, and");
        println!("the default build cannot open one at all.");
        if let Some(path) = &json {
            let rec: evidence::Recorder<DeadTransport> = evidence::Recorder::new(DeadTransport);
            let extras = vec![(
                "planned_packets".to_string(),
                format!("{}", planned.len()),
            )];
            let t = rec.transcript(
                command_line(),
                "dry-run",
                vec!["this was a dry run: the verdict is UNKNOWN because nothing was sent, so \
                      the exchange fields are UNREAD by construction and no value in this file \
                      came from the device"
                    .to_string()],
                extras,
                None,
            );
            write_json(path, &t)?;
        }
        println!("VERDICT       UNKNOWN — nothing was sent (exit 6 by design).");
        return Ok(ExitCode::from(6));
    }

    firstlight_live(&o, json.as_deref())
}

fn firstlight_live(o: &FlOptions, json: Option<&str>) -> Result<ExitCode, (u8, String)> {
    live_gate()?;
    #[cfg(feature = "usb")]
    {
        use a9boot_host::channel::{check_identity, Expect};
        use a9boot_host::evidence::{ParseState, Recorder, Verdict};
        use a9boot_host::transport::live::LiveTransport;
        let t = LiveTransport::open().map_err(|e| (4, e))?;
        let mut rec = Recorder::new(t);

        // Identity, before a single command byte is sent.
        let serial = rec.serial().map_err(|e| (4, e))?;
        if let Err(e) = check_identity(&serial, &Expect::default()) {
            let t = rec.transcript(
                command_line(),
                "live",
                vec![format!(
                    "REFUSED before sending anything: {e}. No command byte was sent; the only \
                     traffic was the serial descriptor read that produced this identity."
                )],
                vec![],
                Some((Verdict::Unknown, Some(format!("identity check refused: {e}")))),
            );
            println!("{}", t.human());
            if let Some(path) = json {
                write_json(path, &t)?;
            }
            return Err((3, format!("identity check refused before sending anything: {e}")));
        }
        rec.note("identity: CPID 0x8003, BDID 0x02, PWND:[checkm8] all present".to_string());

        let report = firstlight::run_on(&mut rec, o);
        for n in &report.notes {
            rec.note(n.clone());
        }
        let mut verdict = rec.verdict();
        let mut reason = rec.verdict_reason();
        if let Some(hard) = &report.hard_fail {
            verdict = Verdict::Fail;
            reason = Some(hard.clone());
        }
        let t = rec.transcript(
            command_line(),
            "live",
            report.warnings.clone(),
            report.extras.clone(),
            Some((verdict, reason)),
        );
        println!("{}", t.human());
        if let Some(path) = json {
            write_json(path, &t)?;
        }
        // Exit codes distinguish the two FAILs this project keeps confusing: the wire did not
        // answer (5) versus the wire answered and the answer failed the contract (7).
        let no_reply = rec
            .records
            .iter()
            .any(|r| r.transport_error.as_deref().is_some_and(|e| !e.contains("STATE_WALK_MISMATCH")));
        let walk_mismatch =
            rec.records.iter().any(|r| r.transport_error.as_deref().is_some_and(|e| e.contains("STATE_WALK_MISMATCH")));
        let malformed = rec.records.iter().any(|r| matches!(r.parse, ParseState::Malformed { .. }));
        // Zero exchanges can never be PASS: an empty run is the "plausible value from a codec that
        // never ran" failure mode with nothing to show for it.
        let verdict = if rec.records.is_empty() { Verdict::Unknown } else { verdict };
        Ok(match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Unknown => ExitCode::from(6),
            Verdict::Fail if walk_mismatch => ExitCode::from(8),
            Verdict::Fail if no_reply => ExitCode::from(5),
            Verdict::Fail if malformed => ExitCode::from(7),
            Verdict::Fail => ExitCode::from(7),
        })
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = (o, json);
        Err((3, "this build has no USB capability. Rebuild with --features usb; device access is \
                 Lead-only."
            .to_string()))
    }
}

/// Pull the command-capacity lower bound out of a ladder's JSON evidence.
///
/// The field names are tried in order and a miss is a refusal: reading a number from the wrong
/// field of an evidence file would be a new way to be confidently wrong.
fn extract_capacity(json: &str) -> Option<usize> {
    for key in [
        "\"lower_bound_command_bytes\":",
        "\"command_lower_bound_command_bytes\":",
        "\"lower_bound\":",
    ] {
        if let Some((_, rest)) = json.split_once(key) {
            let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<usize>() {
                return Some(n);
            }
        }
    }
    None
}

/// The exact command line, for the evidence file's `command` field.
fn command_line() -> String {
    let mut s = String::from("a9boot-host");
    for a in std::env::args().skip(1) {
        s.push(' ');
        s.push_str(&a);
    }
    s
}

/// Write the evidence file. A failure here is an error (exit 4): evidence that was not written is
/// evidence that does not exist, and a run whose record could not be saved must say so.
fn write_json(path: &str, t: &Transcript) -> Result<(), (u8, String)> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| (4, format!("{path}: {e}")))?;
        }
    }
    std::fs::write(path, t.to_json()).map_err(|e| (4, format!("{path}: {e}")))?;
    println!("evidence written to {path} (schema {})", evidence::SCHEMA);
    Ok(())
}

/// A JSON string literal, for the places where a message goes straight into an `extras` value.
/// Used by the `usb`-gated live paths, so the default build sees it as dead code.
#[allow(dead_code)]
fn json_string(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn note_for(name: &str) -> &'static str {
    match name {
        "dtb" => "device tree, own 2 MiB region",
        "image" => "arm64 Image at 2 MiB base + text_offset",
        "initrd" => "initramfs",
        "fb" => "framebuffer (node disabled in rung 1)",
        "loader" => "mailbox, vectors, EL1 stack, spin mailbox",
        _ => "",
    }
}

fn read(path: &str) -> Result<Vec<u8>, (u8, String)> {
    std::fs::read(path).map_err(|e| (4, format!("{path}: {e}")))
}

fn parse_int(s: &str) -> Result<u64, (u8, String)> {
    let (radix, digits) = if let Some(h) = s.strip_prefix("0x") { (16, h) } else { (10, s) };
    u64::from_str_radix(digits, radix).map_err(|_| (2, format!("not a number: {s:?}")))
}

/// Referenced so the layout constants the plan prints stay tied to the module that owns them.
#[allow(dead_code)]
fn layout_anchor() -> u64 {
    layout::DRAM_BASE + Command::Go as u64
}
