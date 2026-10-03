//! First light: the smallest, safest sequence that can prove the post-pwn channel works, and the
//! interpretation of every way it can fail.
//!
//! ## Why this is a separate module
//!
//! The live path is the last mile, and the last mile is where this project has lost rounds. So
//! the *sequence* lives here as a value ([`Options`] → [`planned_packets`]) and the *execution*
//! lives in [`run_on`], which takes any [`Transport`]. That means the whole first-light flow —
//! ordering, staleness detection, interpretation, the write/read-back verify — is exercised in
//! tests against the simulator and against canned byte strings, with **no device and no USB
//! capability in the build**. The only untested line that remains is `rusb`'s own.
//!
//! ## The sequence, and why each step is where it is
//!
//! 1. `DFU_GET_STATUS` — read-only, does not touch the command buffer, and cannot dispatch
//!    `EXEC`/`MEMC` (`0x3A1 != 0x2A1`). It tells us whether the ROM is in a state that accepts a
//!    `DNLOAD` at all, which is the difference between "our channel is wrong" and "the device is
//!    not where we think it is".
//! 2. `MEMC` **reads** — the only operation that changes nothing outside the ROM's own buffer.
//!    The default address is the AUSB PHY pair, chosen because the SecureROM programmed that PHY
//!    (that is how DFU is talking to us at all), so the address is inside the ROM's own
//!    translation with the highest confidence available — strictly safer than a first read of
//!    DRAM, which is the very thing U-1 says is unknown.
//! 3. An optional `MEMC` **write and read-back** of a per-run-unique pattern. This is the only
//!    step that carries a *content* proof: the bytes read back must equal bytes generated moments
//!    ago, so they cannot be a stale reply. It is also the step that exercises a multi-transfer
//!    `DNLOAD`, which is the mechanism the whole loader depends on.
//!
//! ## Staleness, the failure that would look like success
//!
//! The resident handler reads the command magic from the *start* of the DFU buffer. If the ROM's
//! download offset does not reset between commands, command *N* is written at the wrong offset
//! and the handler sees command *N-1*'s `DONE_MAGIC` — and answers with command *N-1*'s reply.
//! A parser that only checks `DONE_MAGIC` would report a **plausible value from a command that
//! never ran**. So: two reads to *different* addresses that return byte-identical replies are
//! rejected as [`STALE_SUSPECT`]. That check is a negative control in the tests, because a check
//! that has never been shown to fail is not a check.

use crate::bundle::{self, Step, TransferBudget};
use crate::channel::{self, Packet};
use crate::evidence::{exchange_for, Recorder};
use crate::transport::{Sequence, Transport};
use a9boot_core::layout::{AUSB_CFG0_ADDR, AUSB_PHY_BASE, DRAM_BASE, DRAM_SIZE};
use std::time::{SystemTime, UNIX_EPOCH};

/// The one read every first-light run starts with: the AUSB PHY pair the SecureROM programmed.
pub const DEFAULT_READ: ReadSpec = ReadSpec { addr: AUSB_CFG0_ADDR, len: 8 };

/// The read that makes a two-step sequence able to detect a stale reply: a *different* register in
/// the same page (`AUSB_CTL` at `+0x00`, `AUSB_SIG` at `+0x04`).
pub const SECOND_READ: ReadSpec = ReadSpec { addr: AUSB_PHY_BASE, len: 8 };

/// The name of the staleness rejection. Stable, so the runbook can point at it.
pub const STALE_SUSPECT: &str = "SUSPECT_STALE_REPLY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSpec {
    pub addr: u64,
    pub len: usize,
}

impl ReadSpec {
    pub fn parse(s: &str) -> Result<ReadSpec, String> {
        let (a, l) = s
            .split_once(':')
            .ok_or_else(|| format!("--read wants ADDR:LEN, got {s:?}"))?;
        let addr = parse_u64(a).map_err(|e| format!("--read {s:?}: {e}"))?;
        let len = parse_u64(l).map_err(|e| format!("--read {s:?}: {e}"))? as usize;
        // Bounded by the channel, not by taste: a read larger than `TransferBudget::max_read()`
        // would ask for a single UPLOAD longer than a transport chunk, and the reply would land
        // past the reply area. Chunk it as two --read options instead.
        let max = TransferBudget::default().max_read();
        if len == 0 || len > max {
            return Err(format!(
                "--read {s:?}: length {len} is outside 1..={max}. A single read cannot exceed the \
                 channel's read chunk; use two --read options for a larger span."
            ));
        }
        Ok(ReadSpec { addr, len })
    }

    pub fn label(self) -> String {
        format!("memc read {:#x} len {:#x}", self.addr, self.len)
    }

    pub fn purpose(self) -> String {
        let what = if self.addr == AUSB_CFG0_ADDR {
            "AUSB_CFG0/CFG1 (PHY tunables the SecureROM programmed)"
        } else if self.addr == AUSB_PHY_BASE {
            "AUSB_CTL/AUSB_SIG (PHY control and signal state)"
        } else if (DRAM_BASE..DRAM_BASE + DRAM_SIZE).contains(&self.addr) {
            "DRAM: reachability read (U-1). Read-only."
        } else if (0x1_0000_0000..0x1_0000_0000 + 0x10_0000).contains(&self.addr) {
            "boot ROM (VROM)"
        } else if (0x1_8000_0000..0x1_8400_0000).contains(&self.addr) {
            "SRAM (ROM heap / DFU buffer / resident handler)"
        } else {
            "explicit address"
        };
        format!("{what} (read-only; the only bytes written are inside the ROM's DFU buffer)")
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let (radix, digits) = if let Some(h) = s.strip_prefix("0x") { (16, h) } else { (10, s) };
    u64::from_str_radix(digits, radix).map_err(|_| format!("not a number: {s:?}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSpec {
    pub addr: u64,
    pub len: usize,
}

impl WriteSpec {
    /// A write is parsed independently of the read bound: `execute_steps` chunks a write at
    /// `TransferBudget::data_per_command()` (2048 data bytes per command), so a 4 KiB write is two
    /// commands and is exactly the multi-transfer evidence the runbook wants. What is bounded here
    /// is the *address*: only DRAM.
    pub fn parse(s: &str) -> Result<WriteSpec, String> {
        let (a, l) = s
            .split_once(':')
            .ok_or_else(|| format!("--write wants ADDR:LEN, got {s:?}"))?;
        let addr = parse_u64(a).map_err(|e| format!("--write {s:?}: {e}"))?;
        let len = parse_u64(l).map_err(|e| format!("--write {s:?}: {e}"))? as usize;
        let r = ReadSpec { addr, len };
        if len < 8 {
            return Err(format!("--write {s:?}: a write shorter than 8 bytes cannot be told apart \
                                from a stale reply; use at least 8, and 2048+ to exercise a \
                                multi-transfer DNLOAD"));
        }
        if len == 0 || len > 0x40_0000 {
            return Err(format!("--write {s:?}: length {len} is outside 1..=0x400000 (4 MiB)"));
        }
        if r.addr < DRAM_BASE || r.addr.saturating_add(len as u64) > DRAM_BASE + DRAM_SIZE {
            return Err(format!(
                "--write {s:?}: {:#x}..{:#x} is outside DRAM ({:#x}..{:#x}). Only DRAM is written \
                 at first light: a write outside it is how a session is lost.",
                r.addr,
                r.addr + len as u64,
                DRAM_BASE,
                DRAM_BASE + DRAM_SIZE
            ));
        }
        Ok(WriteSpec { addr: r.addr, len })
    }
}

/// Everything the first-light sequence is allowed to do, as a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub reads: Vec<ReadSpec>,
    pub write: Option<WriteSpec>,
    /// The wire shape around each command. Default [`Sequence::Minimal`] (DESIGN.md §2.3), which
    /// is what hardware attempt 1 sent and got no reply; [`Sequence::Reference`] is the reference's
    /// full framing (`gaster.c:977-988` + `:829-834`) and is the leading hypothesis.
    pub sequence: Sequence,
    pub status: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            reads: vec![DEFAULT_READ],
            write: None,
            sequence: Sequence::Minimal,
            status: true,
        }
    }
}

/// One packet, with the purpose it serves, ready to be printed before anything is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub purpose: String,
    pub packet: Packet,
}

/// The exact packets a run will send, in order. **Pure**: printing this is what the dry run does,
/// and a live run sends precisely these.
pub fn planned_packets(o: &Options) -> Vec<Planned> {
    let mut out = Vec::new();
    for r in &o.reads {
        out.push(Planned { purpose: r.purpose(), packet: channel::mem_read(r.addr, r.len) });
    }
    if let Some(w) = &o.write {
        let data = run_pattern(w.seed_for_plan(), w.len);
        let step = Step::WriteVerify { dst: w.addr, data };
        for p in bundle::step_packets(&step, &[], &TransferBudget::default()) {
            out.push(Planned {
                purpose: format!(
                    "DRAM write+read-back verify at {:#x} (unique per-run pattern: a match cannot \
                     be a stale reply)",
                    w.addr
                ),
                packet: p,
            });
        }
    }
    out
}

impl WriteSpec {
    /// The plan/print path has no run seed; the live path derives one. Printing is not a promise
    /// about bytes, and the pattern is recorded in the evidence either way.
    pub fn seed_for_plan(self) -> u64 {
        0
    }
}

/// A pattern that is unique per run, so a reply equal to it *cannot* be a stale buffer.
///
/// `b[i] = seed_bytes[i % 8] ^ ((i * 37) + 0x5a)`. The seed is not cryptographic and does not
/// need to be: its only job is to be a value nothing else on the device could be holding.
pub fn run_pattern(seed: u64, len: usize) -> Vec<u8> {
    let sb = seed.to_le_bytes();
    (0..len)
        .map(|i| sb[i % 8] ^ (i as u8).wrapping_mul(37).wrapping_add(0x5a))
        .collect()
}

/// A seed from the wall clock, stirred once. Documented as **not** security-relevant.
pub fn fresh_seed() -> u64 {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut x = n ^ 0x9E37_79B9_7F4A_7C15;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// What the run produced beyond the raw exchanges: interpretations, and the warnings that must be
/// read next to (not instead of) the verdict.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
    pub extras: Vec<(String, String)>,
    /// A condition that makes the run **not** trustworthy even if every reply parsed. The tool
    /// demotes its verdict to FAIL; nothing is deleted from the record.
    pub hard_fail: Option<String>,
}

/// Run the sequence against any transport. **This is the code path a live run takes**, byte for
/// byte; the tests drive it against the simulator and against canned replies.
pub fn run_on<T: Transport>(t: &mut Recorder<T>, o: &Options) -> RunReport {
    let mut rep = RunReport::default();

    // 1. State, read-only.
    if o.status {
        match t.dfu_status() {
            Ok(s) => {
                rep.notes.push(format!("DFU_GET_STATUS before the first exchange: {}", s.summary()));
                rep.extras.push(("dfu_status_before".into(), format!(
                    "{{\"status\": {}, \"state\": {}, \"state_name\": {}, \"accepts_a_fresh_dnload\": {}}}",
                    s.status, s.state, json_str(s.state_name()), s.accepts_a_fresh_dnload()
                )));
                if !s.looks_healthy() {
                    rep.warnings.push(format!(
                        "DFU status is not OK ({}). The ROM is reporting a condition, not a state; \
                         a command sent now will be interpreted through it. Fix the status before \
                         reading anything into a reply.",
                        s.status
                    ));
                }
                if !s.accepts_a_fresh_dnload() {
                    rep.warnings.push(format!(
                        "the DFU state is {} ({}), not dfuIDLE. A DNLOAD that starts a *fresh* \
                         download is expected only in dfuIDLE; in any other state the ROM may \
                         append at an offset the host cannot see. If the first exchange fails, \
                         that is the first hypothesis to exclude, and a bus reset (`a9boot reset \
                         is Lead-only`) is the way back to dfuIDLE — not a retry.",
                        s.state,
                        s.state_name()
                    ));
                }
            }
            Err(e) => {
                rep.notes.push(format!("DFU_GET_STATUS UNREAD: {e}"));
                rep.extras.push(("dfu_status_before".into(), "null".into()));
                rep.warnings.push(format!(
                    "the DFU state could not be read ({e}). The exchanges below can still run, but \
                     a failure cannot be attributed to the channel alone: the device state is \
                     unknown, and 'unknown' is not 'fine'."
                ));
            }
        }
    }

    // 2. Reads, in the order given.
    let mut previous: Option<(ReadSpec, Vec<u8>)> = None;
    for r in &o.reads {
        let p = channel::mem_read(r.addr, r.len);
        let e = exchange_for(&p, &r.purpose(), o.sequence);
        let result = t.exchange(&e);
        if let Ok(raw) = &result {
            // Content check: a reply to *this* request. Only meaningful for well-formed replies.
            if let Ok(resp) = channel::parse_response(raw, p.upload_len) {
                if let Some((prev_spec, prev_data)) = &previous {
                    if prev_spec.addr != r.addr && *prev_data == resp.data {
                        let msg = format!(
                            "{STALE_SUSPECT}: the read of {:#x} returned exactly the same {} bytes \
                             as the read of {:#x}. Two different requests with byte-identical \
                             replies cannot both be attributed to their own request: either the \
                             reply is stale (the ROM's DNLOAD offset did not reset, so the handler \
                             answered from an older command in the buffer), or the two addresses \
                             genuinely hold identical values. The first must be excluded before \
                             the second is believed. Try `--terminator dfu`, or read an address \
                             whose contents are known to differ.",
                            r.addr,
                            resp.data.len(),
                            prev_spec.addr
                        );
                        rep.warnings.push(msg.clone());
                        rep.hard_fail = Some(msg);
                    }
                }
                if let Some(interp) = interpret(r, &resp.data) {
                    rep.notes.push(interp.clone());
                    rep.extras.push((
                        format!("read_{:#x}", r.addr),
                        format!("{{\"addr\": \"{:#x}\", \"len\": {}, \"interpretation\": {}}}", r.addr, r.len, json_str(&interp)),
                    ));
                }
                previous = Some((*r, resp.data));
            } else {
                previous = None;
            }
        } else {
            previous = None;
        }
    }

    // 2b. Provenance. `DONE_MAGIC` is INSPECTED from the reference, not measured, and the
    //     resident handler re-sends the buffer verbatim when the command magic does not match
    //     (`.S:68-74`). So a *first and only* exchange cannot distinguish "our command ran" from
    //     "the buffer already began with DONE_MAGIC and was echoed". Only a second read to a
    //     different address, or the content-verifiable write, upgrades this — say so in the
    //     transcript rather than letting a single green line carry more than it can.
    if t.record_count() == 1 && o.write.is_none() {
        rep.warnings.push(
            "PROVENANCE UNVERIFIED: this run made a single exchange, so nothing in it separates \
             'our command ran' from 'the buffer already began with DONE_MAGIC and the handler \
             echoed it' (the handler re-sends the buffer unchanged when the command magic does not \
             match, payload_handle_checkm8_request.S:68-74). `DONE_MAGIC` is INSPECTED from the \
             reference, not measured on this device. A second read to a *different* address, or \
             `--write`, is what upgrades this reply from 'the channel answered' to 'the channel \
             answered *this* request'."
                .to_string(),
        );
    }

    // 3. The content-verifiable write, if asked for.
    if let Some(w) = &o.write {
        let seed = fresh_seed();
        let data = run_pattern(seed, w.len);
        rep.extras.push((
            "write_verify".into(),
            format!(
                "{{\"addr\": \"{:#x}\", \"len\": {}, \"seed\": \"{:#018x}\", \"pattern_sha256\": {}, \"pattern_hex\": {}}}",
                w.addr,
                w.len,
                seed,
                json_str(&crate::evidence::sha256_hex(&data)),
                json_str(&crate::evidence::hex_prefix(&data, 32))
            ),
        ));
        rep.notes.push(format!(
            "writing {} bytes to {:#x} with a fresh pattern (seed {seed:#018x}) and reading them \
             back: a match proves the round trip is live, not stale, and exercises a multi-transfer \
             DNLOAD",
            w.len, w.addr
        ));
        let step = Step::WriteVerify { dst: w.addr, data };
        match bundle::execute_steps(t, core::slice::from_ref(&step), &[], &TransferBudget::default()) {
            Ok(_) => rep.notes.push(format!(
                "write+read-back of {:#x} ({}) verified byte for byte",
                w.addr, w.len
            )),
            Err(e) => {
                let msg = format!(
                    "the DRAM write+read-back at {:#x} failed: {e}. This is the measurement, not a \
                     transport hiccup: nothing further is written, and the extent is now known to \
                     exclude this address.",
                    w.addr
                );
                rep.warnings.push(msg.clone());
                rep.hard_fail = Some(msg);
            }
        }
    }

    rep
}

/// Turn raw reply bytes into the operator's answer, where a documented meaning exists. Values that
/// are merely surprising are reported as such, and are never silently promoted to "expected".
pub fn interpret(r: &ReadSpec, data: &[u8]) -> Option<String> {
    if r.addr == AUSB_CFG0_ADDR && data.len() >= 8 {
        let cfg0 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let cfg1 = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let t = bundle::AusbTunables { cfg0_device: cfg0, cfg1_device: cfg1 };
        let verdict = if t.looks_plausible() {
            "non-zero and stable-looking: these are the values to pass as `apple,cfg0-device` / \
             `apple,cfg1-device` (U-13)"
        } else {
            "ZERO OR ALL-ONES. Either the PHY registers really are unprogrammed (contradicting \
             'SecureROM programmed this PHY to talk to us'), or this reply did not come from the \
             registers. Record it; do not pass it to the device tree."
        };
        return Some(format!(
            "AUSB_CFG0 = {cfg0:#010x}, AUSB_CFG1 = {cfg1:#010x} — {verdict}"
        ));
    }
    if r.addr == AUSB_PHY_BASE && data.len() >= 8 {
        let ctl = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let sig = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let mut s = format!("AUSB_CTL = {ctl:#010x} (bit0 RESET, bit2 PWRDOWN, bit3 SIDDQ)");
        if ctl & 0b1_1101 != 0 {
            s.push_str(": a control bit is SET, so the PHY is not in the DFU-idle state and this \
                        read is context, not a tunable");
        } else {
            s.push_str(": all three clear, as DFU expects");
        }
        s.push_str(&format!(
            "; AUSB_SIG = {sig:#010x} (bit1 VBUSDET_FORCE_EN, bit8 CABLE_CONNECTED){}",
            if sig & (1 << 8) != 0 { ": CABLE_CONNECTED is set" } else { ": CABLE_CONNECTED is \
                CLEAR, which contradicts a live USB session" }
        ));
        return Some(s);
    }
    None
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// The exact `DNLOAD` bytes of the first packet of a default run, for the pre-flight printout that
/// the runbook tells the operator to compare against.
pub fn first_packet_hex(o: &Options) -> String {
    planned_packets(o)
        .first()
        .map(|p| crate::evidence::hex(&p.packet.dnload))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Verdict;
    use crate::transport::{DfuStatus, Exchange, SimDevice};

    /// A transport that answers every exchange with the same canned bytes — the shape a stale
    /// reply takes when the ROM answers from an earlier command.
    struct SameReply(Vec<u8>, usize);
    impl Transport for SameReply {
        fn serial(&mut self) -> Result<String, String> {
            Ok("CPID:8003 BDID:02 SRTG:[iBoot-2234.0.0.2.22] PWND:[checkm8]".into())
        }
        fn exchange(&mut self, _e: &Exchange) -> Result<Vec<u8>, String> {
            self.1 += 1;
            Ok(self.0.clone())
        }
        fn describe(&self) -> String {
            "SameReply".into()
        }
    }

    /// A transport that answers each exchange with the next canned reply.
    struct Scripted(Vec<Vec<u8>>, usize, Option<String>);
    impl Transport for Scripted {
        fn serial(&mut self) -> Result<String, String> {
            Ok("CPID:8003 BDID:02 SRTG:[iBoot-2234.0.0.2.22] PWND:[checkm8]".into())
        }
        fn exchange(&mut self, _e: &Exchange) -> Result<Vec<u8>, String> {
            if let Some(e) = &self.2 {
                return Err(e.clone());
            }
            let r = self.0.get(self.1).cloned().unwrap_or_default();
            self.1 += 1;
            Ok(r)
        }
        fn describe(&self) -> String {
            "Scripted".into()
        }
    }

    fn reply_with(retval: u64, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 16 + data.len()];
        v[0..8].copy_from_slice(&a9boot_core::abi::DONE_MAGIC.to_le_bytes());
        v[8..16].copy_from_slice(&retval.to_le_bytes());
        v[16..].copy_from_slice(data);
        v
    }

    fn opts_two_reads() -> Options {
        Options { reads: vec![DEFAULT_READ, SECOND_READ], status: false, ..Default::default() }
    }

    #[test]
    fn the_default_plan_is_one_read_only_packet() {
        let o = Options::default();
        let p = planned_packets(&o);
        assert_eq!(p.len(), 1, "the default first light must be a single exchange");
        let d = &p[0].packet.dnload;
        // MEMC magic, x0 = reply address, x1 = the register, x2 = 8, and *no appended data* —
        // a read cannot write outside the ROM's own buffer.
        assert_eq!(&d[0..8], &a9boot_core::abi::MEMC_MAGIC.to_le_bytes());
        assert_eq!(d.len(), a9boot_core::abi::HEADER_LEN as usize);
        assert_eq!(
            u64::from_le_bytes(d[0x10..0x18].try_into().unwrap()),
            a9boot_core::abi::reply_addr()
        );
        assert_eq!(u64::from_le_bytes(d[0x18..0x20].try_into().unwrap()), AUSB_CFG0_ADDR);
        assert_eq!(u64::from_le_bytes(d[0x20..0x28].try_into().unwrap()), 8);
        assert_eq!(p[0].packet.upload_len, a9boot_core::abi::REPLY_OFF as u16 + 8);
        // The plan is deterministic and printable.
        assert_eq!(first_packet_hex(&o), crate::evidence::hex(d));
    }

    #[test]
    fn no_planned_packet_ever_has_a_non_memc_magic_unless_it_is_an_exec() {
        // The structural safety property of the read/write phases: every packet is a MEMC whose
        // destination is either the reply area (a read) or an address inside DRAM (the write).
        // Nothing can move bytes to a wild address by accident.
        let o = Options {
            reads: vec![DEFAULT_READ, SECOND_READ, ReadSpec { addr: DRAM_BASE, len: 32 }],
            write: Some(WriteSpec { addr: DRAM_BASE, len: 4096 }),
            sequence: Sequence::Reference,
            status: true,
        };
        for p in planned_packets(&o) {
            let d = &p.packet.dnload;
            assert_eq!(
                &d[0..8],
                &a9boot_core::abi::MEMC_MAGIC.to_le_bytes(),
                "packet {:?} is not MEMC",
                p.packet.label
            );
            let dst = u64::from_le_bytes(d[0x10..0x18].try_into().unwrap());
            let ok = dst == a9boot_core::abi::reply_addr()
                || (DRAM_BASE..DRAM_BASE + DRAM_SIZE).contains(&dst);
            assert!(ok, "packet {:?} writes to {dst:#x}", p.packet.label);
        }
    }

    #[test]
    fn a_single_read_against_the_simulator_passes() {
        let mut rec = Recorder::new(SimDevice::new(0x4000));
        crate::channel::check_identity(
            &rec.serial().unwrap(),
            &crate::channel::Expect::default(),
        )
        .unwrap();
        let rep = run_on(&mut rec, &Options::default());
        assert_eq!(rec.verdict(), Verdict::Pass, "{:?}", rep.warnings);
        assert!(rep.hard_fail.is_none(), "{:?}", rep.hard_fail);
        // The simulator's register file is canned and labelled as such; the interpretation must
        // report it as a plausible pair, from the values, not from a default.
        assert!(
            rep.notes.iter().any(|n| n.contains("AUSB_CFG0 = 0x00000030") && n.contains("non-zero")),
            "{:?}",
            rep.notes
        );
        assert!(rep.notes.iter().any(|n| n.contains("DFU_GET_STATUS")));
    }

    #[test]
    fn negative_control_identical_replies_to_different_reads_are_rejected() {
        // The precise shape of the trap: the second command did not reach the buffer, the ROM
        // answered from the first command's reply, and the bytes are perfectly well-formed.
        let same = reply_with(0x1_8038_0010, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut rec = Recorder::new(SameReply(same, 0));
        let _ = rec.serial();
        let rep = run_on(&mut rec, &opts_two_reads());
        // Each exchange parses — that is exactly why the content check is needed.
        assert_eq!(rec.verdict(), Verdict::Pass);
        let fail = rep.hard_fail.expect("the staleness check must fire");
        assert!(fail.starts_with(STALE_SUSPECT), "{fail}");
        assert!(rep.warnings.iter().any(|w| w.contains("byte-identical")));
    }

    #[test]
    fn two_default_reads_against_the_simulator_are_not_stale() {
        // The positive counterpart of the staleness control: two *different* addresses whose
        // replies differ must pass, or the check would reject everything.
        let mut rec = Recorder::new(SimDevice::new(0x4000));
        let _ = rec.serial();
        let rep = run_on(&mut rec, &opts_two_reads());
        assert!(rep.hard_fail.is_none(), "{:?}", rep.hard_fail);
        assert_eq!(rec.verdict(), Verdict::Pass);
        assert!(rep.notes.iter().any(|n| n.contains("AUSB_CTL")));
    }

    #[test]
    fn two_different_reads_with_different_values_pass() {
        let mut rec = Recorder::new(Scripted(
            vec![
                reply_with(0x1_8038_0010, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
                reply_with(0x1_8038_0010, &[0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]),
            ],
            0,
            None,
        ));
        let _ = rec.serial();
        let rep = run_on(&mut rec, &opts_two_reads());
        assert!(rep.hard_fail.is_none(), "{:?}", rep.hard_fail);
        assert_eq!(rec.verdict(), Verdict::Pass);
        assert!(rep.notes.iter().any(|n| n.contains("AUSB_CFG0 = 0x44332211")));
    }

    #[test]
    fn negative_control_a_bad_magic_stops_the_run_by_name() {
        let mut rec = Recorder::new(Scripted(vec![vec![0u8; 24]], 0, None));
        let _ = rec.serial();
        let rep = run_on(&mut rec, &Options::default());
        assert!(rep.hard_fail.is_none(), "a parse fault is a verdict failure, not a hard fail");
        assert_eq!(rec.verdict(), Verdict::Fail);
        assert!(rec.verdict_reason().unwrap().contains("REPLY_BAD_MAGIC"));
    }

    #[test]
    fn negative_control_a_transport_error_leaves_the_value_unread() {
        let mut rec = Recorder::new(Scripted(vec![], 0, Some("LIVE_UPLOAD_FAILED: timeout".into())));
        let _ = rec.serial();
        let rep = run_on(&mut rec, &Options::default());
        assert_eq!(rec.verdict(), Verdict::Fail);
        assert!(rep.notes.iter().any(|n| n.contains("UNREAD")) || rep.warnings.iter().any(|w| w.contains("UNREAD")));
        assert_eq!(rec.records[0].parse.name(), "UNREAD");
    }

    #[test]
    fn a_write_verify_reports_the_failing_address_as_a_measurement() {
        // DRAM unreachable: the simulator names PLAN B, and the report must carry that through as
        // a hard fail rather than as a transport hiccup.
        let mut dev = SimDevice::new(0x4000).with_dram_unreachable();
        dev.dfu_state = 2;
        let mut rec = Recorder::new(dev);
        let _ = rec.serial();
        let o = Options {
            reads: vec![],
            write: Some(WriteSpec { addr: DRAM_BASE, len: 32 }),
            sequence: Sequence::Minimal,
            status: false,
        };
        let rep = run_on(&mut rec, &o);
        assert!(rep.hard_fail.is_some());
        assert!(rep.hard_fail.unwrap().contains("not reachable") || rep.warnings[0].contains("not reachable"));
        assert_eq!(rec.verdict(), Verdict::Fail);
    }

    #[test]
    fn a_write_verify_against_the_simulator_passes_and_records_the_seed() {
        let mut rec = Recorder::new(SimDevice::new(0x4000));
        let _ = rec.serial();
        let o = Options {
            reads: vec![],
            write: Some(WriteSpec { addr: DRAM_BASE, len: 4096 }),
            sequence: Sequence::Minimal,
            status: false,
        };
        let rep = run_on(&mut rec, &o);
        assert!(rep.hard_fail.is_none(), "{:?}", rep.hard_fail);
        assert_eq!(rec.verdict(), Verdict::Pass);
        assert!(rep.extras.iter().any(|(k, v)| k == "write_verify" && v.contains("pattern_sha256")));
        // 4096 bytes is two 2048-byte commands, each 2 DNLOAD transfers plus one read-back.
        assert!(rec.records.len() >= 4, "records: {}", rec.records.len());
        assert!(rec.records.iter().any(|r| r.dnload_chunks == 2));
    }

    #[test]
    fn the_pattern_is_unique_per_run_and_deterministic_in_its_seed() {
        assert_eq!(run_pattern(7, 16), run_pattern(7, 16));
        assert_ne!(run_pattern(7, 4096), run_pattern(8, 4096));
        assert_ne!(fresh_seed(), fresh_seed());
        let p = run_pattern(0, 64);
        assert!(p.chunks(2).any(|c| c[0] != c[1]), "the pattern must not be constant");
    }

    #[test]
    fn write_specs_outside_dram_are_refused_by_name() {
        let e = WriteSpec::parse("0x180380000:4096").unwrap_err();
        assert!(e.contains("outside DRAM"), "{e}");
        assert!(WriteSpec::parse("0x0:4096").unwrap_err().contains("outside DRAM"));
        assert!(WriteSpec::parse("0x800000000:4").unwrap_err().contains("at least 8"));
        assert_eq!(WriteSpec::parse("0x800000000:4096").unwrap().len, 4096);
    }

    #[test]
    fn read_specs_are_parsed_and_bounded() {
        assert_eq!(ReadSpec::parse("0x20c000038:8").unwrap(), DEFAULT_READ);
        assert!(ReadSpec::parse("0x20c000038").unwrap_err().contains("ADDR:LEN"));
        assert!(ReadSpec::parse("0x20c000038:0").unwrap_err().contains("outside 1..="));
        assert!(ReadSpec::parse("0x20c000038:4096").unwrap_err().contains("outside 1..="));
        assert_eq!(ReadSpec::parse("0x20c000038:2048").unwrap().len, 2048);
    }

    #[test]
    fn dfu_state_interpretation_is_spelled_out() {
        let s = DfuStatus { status: 0, poll_timeout: [0; 3], state: 2, str_idx: 0 };
        assert!(s.accepts_a_fresh_dnload());
        assert!(s.looks_healthy());
        assert!(s.summary().contains("dfuIDLE"));
        let s = DfuStatus { status: 0, poll_timeout: [0; 3], state: 7, str_idx: 0 };
        assert!(!s.accepts_a_fresh_dnload());
        assert!(s.summary().contains("dfuMANIFEST"));
        // An unknown state is named as unknown, not defaulted to a name.
        let s = DfuStatus { status: 0, poll_timeout: [0; 3], state: 0xee, str_idx: 0 };
        assert!(s.summary().contains("UNKNOWN-STATE"));
        // A short status record is refused rather than partially decoded.
        assert!(DfuStatus::parse(&[0, 0, 0]).unwrap_err().contains("wanted 6"));
    }

    #[test]
    fn a_wrong_dfu_state_is_a_warning_not_a_silent_assumption() {
        let mut dev = SimDevice::new(0x4000);
        dev.dfu_state = 7; // dfuMANIFEST
        let mut rec = Recorder::new(dev);
        let _ = rec.serial();
        let rep = run_on(&mut rec, &Options::default());
        assert!(rep.warnings.iter().any(|w| w.contains("not dfuIDLE")), "{:?}", rep.warnings);
        assert!(rep.extras.iter().any(|(k, v)| k == "dfu_status_before" && v.contains("\"state\": 7")));
    }
}
