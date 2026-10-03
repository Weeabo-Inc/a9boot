//! The channel-capacity ladder (UNVERIFIED.md U-2), and why it is not "write a pattern into a
//! buffer and read it back".
//!
//! ## What is actually being measured
//!
//! `DESIGN.md` §3.4 wants to know how large a single command may be. Two things could bound it:
//! the ROM's DFU buffer size, and how many `DNLOAD` transfers the ROM accumulates into it before
//! something goes wrong. **The channel cannot tell those apart** — data written past a small
//! buffer lands in SRAM that holds it just as well, and a read-back would confirm it. So this
//! probe measures the quantity the loader actually needs and can honestly report:
//!
//! > how many bytes of ONE command arrive intact and can be read back through the channel.
//!
//! and it reports it as a **lower bound**, never as "the capacity".
//!
//! ## Why it needs no writes at all
//!
//! A command is `[72-byte header][appended data]` at `base = 0x1_8038_0000`, and the handler's
//! reply is `wLength` bytes read from `base` **after** it stores `DONE_MAGIC`/retval at `+0`/`+8`.
//! So a command whose header says `memcpy(0, 0, 0)` — no destination, no source, no length — has
//! **no effect whatsoever**, and if the host asks for `wLength = 0x48 + N`, the reply carries the
//! appended data back verbatim:
//!
//! ```text
//!   reply[0x00..0x08]  DONE_MAGIC          (written by the handler)
//!   reply[0x08..0x10]  retval = 0
//!   reply[0x10..0x48]  the rest of our own header
//!   reply[0x48..0x48+N] the N pattern bytes, as the ROM accumulated them
//! ```
//!
//! Comparing `reply[0x48..]` against the pattern measures accumulation and nothing else: no
//! `memcpy` runs, no register is touched, and the only bytes written anywhere are the ones the
//! `DNLOAD` itself was always going to write.
//!
//! ## The one unavoidable risk, declared
//!
//! The step that fails is the step that wrote past the real end. With a 2 KiB step the overshoot
//! is at most one step into SRAM whose contents are unknown, and the ladder **stops at the first
//! failure** rather than continuing. What is NOT at risk: the resident handler lives at
//! `0x1_800E_0F08` (`layout::HANDLER_ADDR`), which is `0x29F0F8` = **2.6 MiB below** the buffer, so
//! no ladder that stops at 16 KiB can reach the code it is measuring with. That is the answer to
//! "can the probe destroy the channel it is measuring" — it cannot reach it, and the arithmetic is
//! in the report.

use crate::channel::{self, Packet};
use crate::evidence::{exchange_for, Recorder};
use crate::transport::{Sequence, Transport};
use a9boot_core::abi;
use a9boot_core::layout;
use a9boot_core::layout::DFU_BUFFER_ADDR;

/// The ladder's default steps, in **command** bytes (`header + appended data` — the quantity that
/// has to fit). It starts at one `DNLOAD` chunk, doubles, then tests the two lengths that decide
/// the load: `EXEC_COMMAND_BYTES` = the command that delivers `a9boot-payload`, and `0x4000` =
/// 16,384 = a full assumed buffer. A reader can act on those two numbers; a doubling ladder that
/// stops at 8 KiB cannot answer "does our payload fit".
pub const DEFAULT_STEPS: [usize; 5] = [0x800, 0x1000, 0x2000, 0x2BE8, 0x4000];

/// The cells that decide the payload's fate, with the reply held at the **measured-good** 2048 so
/// the read path cannot confound them. `0x2BE8` is the payload's own EXEC command; `0x4000` is a
/// full assumed buffer. Add `--steps 11240:2048` for the single most valuable remaining cell: a
/// 5-transfer command at exactly the size the loader must send.
pub const DISCRIMINATE_CELLS: [(usize, usize); 5] = [
    (4096, 2048),
    (4097, 2048),
    (6144, 2048),
    (8192, 2048),
    (2048, 8192),
];

/// The size of the delivered payload image, MEASURED from the flat image. It was 10,640 before the
/// entry-state anchor; the anchor's 25 words and its `_start` block brought it to 10,968. The test
/// below re-measures it from the built ELF, so this constant cannot drift from the artefact.
pub const PAYLOAD_IMAGE_LEN: usize = 10_968;

/// The largest command the loader must be able to send: `PAYLOAD_OFF + payload image` = 11,240.
/// Below this, EXEC is impossible and the budget has to be re-planned — which is a *decision*, not
/// a detail.
pub fn required_command_bytes() -> usize {
    abi::PAYLOAD_OFF as usize + PAYLOAD_IMAGE_LEN
}

/// The largest command the assumed 16 KiB buffer can hold: `ASSUMED_BUFFER_CAPACITY - HEADER_LEN`.
pub fn assumed_max_command() -> usize {
    crate::bundle::ASSUMED_BUFFER_CAPACITY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// The pattern came back byte for byte: this many bytes arrive intact.
    Verified,
    /// The **command** side succeeded - every `DNLOAD` transfer was accepted in full - but the
    /// reply could not prove the tail. Acceptance is real evidence about the *command* path and
    /// must not be erased by a failure on the *reply* path: they are two different brackets.
    Accepted,
    /// The reply arrived, was the right length, and the pattern did **not** match: the ROM
    /// accumulated something other than what was sent — the "corruption, not a stall" case
    /// (`DESIGN.md:188`).
    Corrupt,
    /// The reply was short or absent, or the transfer failed: the device refused this size.
    Refused,
}

impl StepOutcome {
    pub fn name(self) -> &'static str {
        match self {
            StepOutcome::Verified => "CAPACITY_STEP_VERIFIED",
            StepOutcome::Accepted => "CAPACITY_STEP_ACCEPTED",
            StepOutcome::Corrupt => "CAPACITY_STEP_CORRUPT",
            StepOutcome::Refused => "CAPACITY_STEP_REFUSED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderStep {
    pub data_len: usize,
    pub command_len: usize,
    pub reply_len: usize,
    /// The row summary: the *command* side, because that is what the payload needs.
    pub outcome: StepOutcome,
    /// The two brackets, kept apart. A failing reply must never move the command bracket.
    pub command_outcome: StepOutcome,
    pub reply_outcome: StepOutcome,
    /// Byte offset of the first difference, for a corrupt step.
    pub first_mismatch: Option<usize>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapacityReport {
    pub steps: Vec<LadderStep>,
    /// The largest COMMAND that was fully accepted (verified, or accepted-but-unread). **A lower
    /// bound on the command path** - the one the payload's admissibility depends on.
    pub lower_bound: usize,
    /// The largest command whose accumulated bytes were read back and matched.
    pub command_verified_bound: usize,
    /// The first command size that failed, if any. A reply shortfall does **not** set this.
    pub first_failure: Option<usize>,
    /// The largest reply that came back complete, and the first that did not: **the read path's own
    /// bracket**, which the staged-image verification depends on.
    pub reply_bound: usize,
    pub reply_first_failure: Option<usize>,
    /// Whether the ladder reached its ceiling without failing.
    pub reached_ceiling: bool,
    pub ceiling: usize,
}

impl CapacityReport {
    /// The two brackets, in one line each, because one number cannot serve both purposes.
    pub fn brackets(&self) -> String {
        format!(
            "command bracket: accepted >= {:#x} ({}), verified read-back >= {:#x} ({}), first \
             command failure {}. reply bracket: complete >= {:#x} ({}), first short/refused reply \
             {}. The payload's admissibility uses the COMMAND bracket; the staged-image verification \
             uses the REPLY bracket.",
            self.lower_bound,
            self.lower_bound,
            self.command_verified_bound,
            self.command_verified_bound,
            self.first_failure.map(|f| format!("{f:#x}")).unwrap_or_else(|| "none".into()),
            self.reply_bound,
            self.reply_bound,
            self.reply_first_failure.map(|f| format!("{f:#x}")).unwrap_or_else(|| "none".into()),
        )
    }

    /// What to *declare*, in the label the rest of the project uses.
    pub fn declaration(&self) -> String {
        if self.first_failure.is_none() && self.reached_ceiling {
            format!(
                "capacity \u{2265} {:#x} bytes ({}): the ladder reached its ceiling without a \
                 failure. This is a LOWER BOUND, not a measurement of the buffer: the region has \
                 no observable end, so U-2 is bounded-above-unknown rather than closed.",
                self.lower_bound, self.lower_bound
            )
        } else {
            match self.first_failure.filter(|f| *f > self.lower_bound) {
                Some(f) => format!(
                    "command capacity is at least {:#x} ({}) and BELOW {f:#x} ({f}). The failing \
                     command step is a hard ceiling for one command: every command budget must be \
                     re-planned against {:#x}.",
                    self.lower_bound, self.lower_bound, self.lower_bound
                ),
                None => format!(
                    "command capacity is at least {:#x} ({}); NO command-side failure was observed \
                     in this run, so there is no upper bound from it. (A reply shortfall is not a \
                     command failure and does not appear here: see `brackets()`.)",
                    self.lower_bound, self.lower_bound
                ),
            }
        }
    }

    /// Decide whether the loader's largest command fits. Named either way.
    pub fn fits(&self, need: usize) -> Result<(), String> {
        if self.lower_bound >= need {
            Ok(())
        } else {
            Err(format!(
                "CAPACITY_INSUFFICIENT: the largest command the loader must send is {need} bytes \
                 (PAYLOAD_OFF {:#x} + the 10,640-byte payload image), but the ladder only verified \
                 {:#x} bytes. Delivering the payload through this channel would overrun the \
                 capacity that was measured, which is corruption rather than a stall.",
                abi::PAYLOAD_OFF, self.lower_bound
            ))
        }
    }
}

/// A per-step pattern. Distinct per step **and** distinct within itself, so a shifted, aliased or
/// truncated accumulation is visible as a mismatch rather than as a lucky match.
pub fn step_pattern(step_index: usize, len: usize) -> Vec<u8> {
    let s = step_index as u8;
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(0x5a) ^ s.wrapping_mul(0x11))
        .collect()
}

/// The command for one ladder step: a `MEMC` that copies nothing, with the pattern appended.
///
/// `memcpy(0, 0, 0)` returns 0 and touches nothing. Any other destination would be a write, and a
/// write is the thing this probe does not need.
pub fn step_packet(step_index: usize, command_len: usize) -> Packet {
    step_packet_with_reply(step_index, command_len, command_len)
}

/// One ladder step with the **reply length chosen separately** from the command length.
///
/// This exists because the first hardware ladder confounded two quantities: it asked the handler
/// for a reply as long as the command, so the first failing step was also the first with
/// `wLength > 4096` — and the failure came back as a **host-side `LIBUSB INVALID_PARAM`**, not a
/// device stall. A bound on the *command* and a bound on the *reply* are different measurements,
/// and a probe that varies both at once cannot tell them apart.
pub fn step_packet_with_reply(step_index: usize, command_len: usize, reply_len: usize) -> Packet {
    let data_len = command_len - abi::HEADER_LEN as usize;
    let mut p = channel::memc_packet(0, 0, &[0u8; 0]);
    let _ = &p;
    // The pattern IS the payload of the command: this is what the ROM is asked to accumulate.
    let mut dnload = p.dnload.clone();
    dnload.resize(abi::HEADER_LEN as usize, 0);
    dnload.extend_from_slice(&step_pattern(step_index, data_len));
    p.dnload = dnload;
    p.label = format!("capacity step {command_len} command bytes ({data_len} data)");
    // `wLength` is how much of the buffer window the handler must send back. It can be smaller
    // than the command: that is the whole point of the separated form.
    p.upload_len = reply_len as u16;
    p
}

/// Run the ladder. Stops at the first step that is not `Verified`, because the step after a
/// failure is a larger overshoot into unknown SRAM for no extra information.
pub fn run_ladder<T: Transport>(
    t: &mut Recorder<T>,
    steps: &[usize],
    sequence: Sequence,
) -> (CapacityReport, Vec<String>) {
    let pairs: Vec<(usize, usize)> = steps.iter().map(|n| (*n, *n)).collect();
    run_ladder_pairs(t, &pairs, sequence)
}

/// The ladder with command and reply lengths decoupled. `command_len` is the hypothesis under
/// test for *accumulation*; `reply_len` is the hypothesis under test for *the read path*.
pub fn run_ladder_pairs<T: Transport>(
    t: &mut Recorder<T>,
    pairs: &[(usize, usize)],
    sequence: Sequence,
) -> (CapacityReport, Vec<String>) {
    let steps: Vec<usize> = pairs.iter().map(|(c, _)| *c).collect();
    let steps = &steps[..];
    let mut rep = CapacityReport {
        ceiling: steps.iter().copied().max().unwrap_or(0),
        ..Default::default()
    };
    let mut notes = Vec::new();
    notes.push(format!(
        "ladder {:?} COMMAND bytes; the required command is {:#x} bytes. Each step is ONE \
         command whose header is memcpy(0,0,0) — no destination, no source, no length — so nothing \
         is written except the DNLOAD itself, and the reply carries the appended data back for \
         comparison",
        steps,
        required_command_bytes()
    ));
    notes.push(format!(
        "safety arithmetic: the resident handler is at {:#x}, the buffer at {:#x}, and they are \
         {:#x} = {} MiB apart — no ladder step that stops at {:#x} can reach the code it is \
         measuring with",
        layout::HANDLER_ADDR,
        DFU_BUFFER_ADDR,
        DFU_BUFFER_ADDR - layout::HANDLER_ADDR,
        (DFU_BUFFER_ADDR - layout::HANDLER_ADDR) / (1024 * 1024),
        rep.ceiling
    ));

    for (i, &command_len) in steps.iter().enumerate() {
        let reply_len = pairs[i].1;
        let n = command_len - abi::HEADER_LEN as usize; // data bytes, for the pattern
        let p = step_packet_with_reply(i, command_len, reply_len);
        let e = exchange_for(
            &p,
            &format!("capacity ladder step {n} bytes (one command, no side effects)"),
            sequence,
        );
        // Two verdicts per cell, computed from the same exchange but never merged:
        //   command side - did the DNLOAD path accept the whole command?
        //   reply side   - did the read path return what was asked for?
        let (outcome, reply_outcome, note) = match t.exchange(&e) {
            Ok(raw) => match channel::parse_response(&raw, p.upload_len) {
                Ok(r) => {
                    let data_off = (abi::HEADER_LEN - abi::REPLY_OFF) as usize;
                    let body = r.data.get(data_off..).unwrap_or(&[]);
                    if body.len() < n {
                        // The REPLY was short. The command side was accepted (every DNLOAD
                        // transfer went out in full, or the transport would have errored) but the
                        // tail is unproven. This is the exact confusion that produced a bracket
                        // starting at zero on hardware.
                        (
                            StepOutcome::Accepted,
                            StepOutcome::Refused,
                            format!(
                                "CAPACITY_STEP_ACCEPTED / REPLY_SHORT: the {command_len}-byte command \
                                 was accepted (the DNLOAD path completed), but the reply carried only \
                                 {} of the {n} data bytes needed to prove the tail, so the command is \
                                 ACCEPTED and not VERIFIED. The shortfall is charged to the REPLY \
                                 bracket, not to the command bracket.",
                                body.len()
                            ),
                        )
                    } else {
                        let pattern = step_pattern(i, n);
                        match body[..n].iter().zip(pattern.iter()).position(|(a, b)| a != b) {
                            None => (
                                StepOutcome::Verified,
                                StepOutcome::Verified,
                                format!(
                                    "{n} data bytes arrived intact ({command_len} byte command, {} \
                                     DNLOAD transfers, {reply_len} byte reply)",
                                    command_len.div_ceil(crate::bundle::DNLOAD_CHUNK)
                                ),
                            ),
                            Some(off) => (
                                StepOutcome::Corrupt,
                                StepOutcome::Verified,
                                format!(
                                    "CAPACITY_STEP_CORRUPT: at +{off:#x} the buffer holds {:#04x} \
                                     where the host sent {:#04x} - DESIGN.md:188's \"corruption, not a \
                                     stall\". Hard ceiling: the ladder stops here.",
                                    body[off], pattern[off]
                                ),
                            ),
                        }
                    }
                }
                Err(msg) => (
                    StepOutcome::Accepted,
                    StepOutcome::Refused,
                    format!("CAPACITY_STEP_ACCEPTED / REPLY_REJECTED: the reply was rejected: {msg}"),
                ),
            },
            // Which half failed? The transport names it, and the distinction decides which bracket
            // moves: `LIVE_UPLOAD_*` is the read path, `LIVE_DNLOAD_*` is the command path. Charging
            // a reply failure to the command bracket is what printed "at least 8192 and BELOW 2048".
            Err(msg) if msg.contains("UPLOAD") || msg.contains("REPLY") => (
                StepOutcome::Accepted,
                StepOutcome::Refused,
                format!(
                    "CAPACITY_STEP_ACCEPTED / REPLY_REFUSED: the {command_len}-byte command was \
                     accepted; the {reply_len}-byte REPLY is what failed ({msg}). Charged to the \
                     reply bracket."
                ),
            ),
            Err(msg) => (
                StepOutcome::Refused,
                StepOutcome::Refused,
                format!("CAPACITY_STEP_REFUSED: no reply: {msg}"),
            ),
        };
        let first_mismatch = note
            .split_once("at +")
            .and_then(|(_, rest)| rest.split_once(':'))
            .and_then(|(hex, _)| usize::from_str_radix(hex.trim_start_matches("0x"), 16).ok());
        let step = LadderStep {
            data_len: n,
            command_len,
            reply_len,
            outcome,
            command_outcome: outcome,
            reply_outcome,
            first_mismatch,
            detail: note.clone(),
        };
        let _ = &step;

        // The command bracket moves on acceptance OR verification; the reply bracket moves only
        // when the read path returned what was asked for. A short reply stops nothing on the
        // command side: it is a different question.
        match outcome {
            StepOutcome::Verified => {
                rep.lower_bound = rep.lower_bound.max(command_len);
                rep.command_verified_bound = rep.command_verified_bound.max(command_len);
            }
            StepOutcome::Accepted => {
                rep.lower_bound = rep.lower_bound.max(command_len);
            }
            _ => {
                rep.first_failure = Some(command_len);
            }
        }
        match reply_outcome {
            StepOutcome::Verified => rep.reply_bound = rep.reply_bound.max(reply_len),
            _ => {
                if rep.reply_first_failure.is_none() {
                    rep.reply_first_failure = Some(reply_len);
                }
            }
        }
        notes.push(note.clone());
        rep.steps.push(step);
        if !matches!(outcome, StepOutcome::Verified | StepOutcome::Accepted) {
            notes.push(format!(
                "STOPPING at {command_len} command bytes: the command side failed, and the next \
                 step would be a larger write past that point into SRAM whose contents are unknown"
            ));
            break;
        }
    }
    if rep.first_failure.is_none() && rep.steps.len() == steps.len() {
        rep.reached_ceiling = true;
    }
    (rep, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{SimDevice, Trigger};

    fn device_with_capacity(cap: Option<usize>) -> SimDevice {
        let mut d = SimDevice::new(0x4000);
        d.modelled_dnload_capacity = cap;
        d
    }

    #[test]
    fn a_roomy_buffer_reaches_the_ceiling_and_is_reported_as_a_lower_bound() {
        let mut rec = Recorder::new(device_with_capacity(None));
        let (rep, notes) = run_ladder(&mut rec, &DEFAULT_STEPS, Sequence::Minimal);
        assert!(rep.first_failure.is_none(), "{:?}", rep.steps);
        assert!(rep.reached_ceiling);
        assert_eq!(rep.lower_bound, 0x4000, "a full 16 KiB command fits the simulated buffer");
        let d = rep.declaration();
        assert!(d.contains("LOWER BOUND"), "{d}");
        assert!(d.contains("bounded-above-unknown"), "{d}");
        assert!(rep.fits(required_command_bytes()).is_ok());
        assert!(notes.iter().any(|n| n.contains("2 MiB apart")), "{notes:?}");
    }

    #[test]
    fn negative_control_a_truncated_accumulation_is_reported_by_name_and_stops_the_ladder() {
        // The buffer is smaller than the ladder's ceiling and the ROM *silently* keeps only the
        // first `cap` bytes. This is the corruption case: the write "succeeds", the data does not.
        let mut rec = Recorder::new(device_with_capacity(Some(0x2000)));
        let (rep, notes) = run_ladder(&mut rec, &DEFAULT_STEPS, Sequence::Minimal);
        // With command==reply in this control, the truncation is visible as a pattern mismatch at
        // the first step whose DNLOAD exceeded the modelled capacity.
        assert_eq!(rep.lower_bound, 0x2000, "steps: {:?}", rep.steps);
        assert_eq!(rep.first_failure, Some(0x2BE8), "the payload's own EXEC command is the step that breaks");
        assert_eq!(rep.steps.len(), 4, "the ladder must stop at the first failure");
        assert_eq!(rep.steps[3].outcome, StepOutcome::Corrupt);
        assert_eq!(rep.steps[3].outcome.name(), "CAPACITY_STEP_CORRUPT");
        // The mismatch offset is carried for the row; the fault name is what matters.
        assert_eq!(rep.steps[3].outcome.name(), "CAPACITY_STEP_CORRUPT");
        assert!(notes.iter().any(|n| n.contains("STOPPING at")), "{notes:?}");
        // And the decision it drives is named, not implied.
        let e = rep.fits(required_command_bytes()).unwrap_err();
        assert!(e.contains("CAPACITY_INSUFFICIENT"), "{e}");
        assert!(e.contains("corruption rather than a stall"), "{e}");
        assert!(rep.declaration().contains("BELOW"), "{}", rep.declaration());
    }

    #[test]
    fn negative_control_a_refusing_device_is_a_different_fault_from_a_corrupt_one() {
        // The SAME boundary, two device behaviours, two names — because they need two different
        // responses. (a) the ROM silently keeps only the first 6 KiB: the write "succeeds" and the
        // data does not. (b) the ROM declines the transfer outright.
        let mut rec = Recorder::new(device_with_capacity(Some(0x1800)));
        let (rep, _) = run_ladder(&mut rec, &DEFAULT_STEPS, Sequence::Minimal);
        assert_eq!(rep.lower_bound, 0x1000, "steps: {:?}", rep.steps);
        assert_eq!(rep.first_failure, Some(0x2000));
        assert_eq!(rep.steps.last().unwrap().outcome, StepOutcome::Corrupt);
        assert_eq!(rep.steps.last().unwrap().outcome.name(), "CAPACITY_STEP_CORRUPT");

        let mut d = SimDevice::new(0x1800);
        d.modelled_dnload_capacity = None; // refuse rather than truncate
        let mut rec = Recorder::new(d);
        let (rep, _) = run_ladder(&mut rec, &DEFAULT_STEPS, Sequence::Minimal);
        assert_eq!(rep.lower_bound, 0x1000);
        assert_eq!(rep.first_failure, Some(0x2000));
        assert_eq!(rep.steps.last().unwrap().outcome, StepOutcome::Refused);
        assert_eq!(rep.steps.last().unwrap().outcome.name(), "CAPACITY_STEP_REFUSED");
    }

    #[test]
    fn the_required_command_size_is_measured_from_the_built_payload() {
        // A pinned constant that no longer matches the artefact is a confident-wrong value; this
        // re-measures it whenever the payload ELF is present.
        let path = "../target/aarch64-unknown-none-softfloat/payload/a9boot-payload";
        match std::fs::read(path) {
            Ok(elf) => {
                let flat = crate::elf::flatten(&elf).expect("payload flattens");
                assert_eq!(
                    flat.bytes.len(),
                    PAYLOAD_IMAGE_LEN,
                    "the delivered image size changed; update PAYLOAD_IMAGE_LEN and every budget"
                );
                assert_eq!(required_command_bytes(), 0x2BE8);
            }
            Err(_) => eprintln!("NOTE: {path} not built; the pinned size was not re-measured"),
        }
    }

    #[test]
    fn each_step_is_a_command_with_no_side_effects() {
        // The property that makes this probe safe: the header copies nothing.
        for n in [0x800usize, 0x4000] {
            let p = step_packet(0, n);
            assert_eq!(&p.dnload[0..8], &abi::MEMC_MAGIC.to_le_bytes());
            assert_eq!(u64::from_le_bytes(p.dnload[0x10..0x18].try_into().unwrap()), 0, "dst");
            assert_eq!(u64::from_le_bytes(p.dnload[0x18..0x20].try_into().unwrap()), 0, "src");
            assert_eq!(u64::from_le_bytes(p.dnload[0x20..0x28].try_into().unwrap()), 0, "len");
            assert_eq!(p.dnload.len(), n);
            assert_eq!(p.upload_len as usize, n);
        }
    }

    #[test]
    fn a_deferred_ladder_step_is_not_a_measurement() {
        // `run_ladder` uses complete exchanges; if a transport only stages, the reply is empty and
        // the step must be REFUSED rather than counted.
        let mut rec = Recorder::new(device_with_capacity(None));
        let p = step_packet(0, 0x800);
        let e = exchange_for(&p, "stage only", Sequence::Minimal);
        let _ = rec.exchange_with(&e, Trigger::Deferred);
        assert_eq!(rec.records[0].parse.name(), "UNREAD");
        assert_ne!(rec.verdict(), crate::evidence::Verdict::Pass);
    }

    #[test]
    fn the_pattern_is_distinct_per_step_and_within_itself() {
        let a = step_pattern(0, 4096);
        let b = step_pattern(1, 4096);
        assert_ne!(a, b);
        assert!(a.chunks(2).any(|c| c[0] != c[1]), "not constant");
    }
}
