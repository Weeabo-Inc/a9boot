//! Transports: how a `Packet` reaches a device.
//!
//! ## The default build has no USB capability
//!
//! `Transport` is a trait. The only implementation compiled by default is [`SimDevice`], which
//! lives entirely in this process. The real implementation is behind the non-default `usb`
//! feature (`transport_live.rs`), so that:
//!
//! * nothing in a normal `cargo build`/`cargo test` can open a device — the capability is not
//!   merely unused, it is absent;
//! * device access stays Lead-only (HANDOFF §9.1) regardless of the feature: a9boot never opens
//!   the DFU node, and a second agent on one DFU device loses the session.
//!
//! ## What `SimDevice` is and is not
//!
//! It models **the channel**, not the CPU: the DFU buffer, the handler's dispatch on
//! `EXEC_MAGIC`/`MEMC_MAGIC`, the reply layout, and an address space the `MEMC` command copies
//! through. It cannot execute aarch64 code, so `EXEC` calls a registered Rust closure standing
//! in for the payload.
//!
//! That makes it the right place to test the *host's* half of the contract: packet geometry,
//! chunking, verification, reply parsing, and the refusal paths. It is **not** a substitute for
//! the QEMU harness `qemu-validator` owns, and it must never be described as one.

use crate::channel::Packet;
use a9boot_core::abi;
use a9boot_core::layout;
use std::collections::BTreeMap;

/// How the bytes around a command are framed on the wire. **Three named shapes, because two of
/// them have now been run on hardware and both got no reply**, and the difference between them is
/// exactly what the next experiment has to isolate.
///
/// MEASURED on this device (Lead, session 3):
///
/// * [`Sequence::Minimal`] — command `DNLOAD`, then `UPLOAD`: `DNLOAD` accepted (`C 0/72`), the
///   `UPLOAD` unlinked after 1002 ms, no reply.
/// * [`Sequence::Terminated`] — plus a zero-length `DNLOAD`: same, no reply.
///
/// INSPECTED in the reference, and implemented by our own exploit on this device:
///
/// * [`Sequence::Reference`] — the sequence `gaster_command` actually sends
///   (`gaster.c:1478-1493` → `dfu_send_data` `gaster.c:977-988` → `dfu_set_state_wait_reset`
///   `gaster.c:829-834`), which has exactly **one** caller and is therefore the command channel's
///   own framing, not something specific to a firmware upload:
///
///   1. the command `DNLOAD`s (`gaster.c:983`);
///   2. `DNLOAD` of `DFU_FILE_SUFFIX_LEN` = **16 zero bytes** (`gaster.c:41,987`);
///   3. `DNLOAD` with `wLength 0` — the end of the download (`gaster.c:833`);
///   4. `DFU_GET_STATUS` expecting **state 6** (`dfuMANIFEST-SYNC`), then **7** (`dfuMANIFEST`),
///      then **8** (`dfuMANIFEST-WAIT-RESET`) (`gaster.c:833`);
///   5. only then the `UPLOAD` (`gaster.c:1484`).
///
/// `a9pwn`'s `stages.rs` mirrors the same order and it pwned this phone, so the sequence is not
/// hypothetical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sequence {
    /// DESIGN.md §2.3: command, then the trigger. Hardware attempt 1.
    #[default]
    Minimal,
    /// Command, zero-length `DNLOAD`, trigger. Hardware attempt 2.
    Terminated,
    /// The reference's full command framing. Not yet run as a *channel* command on this device.
    Reference,
}

impl Sequence {
    pub fn name(self) -> &'static str {
        match self {
            Sequence::Minimal => "minimal",
            Sequence::Terminated => "terminated",
            Sequence::Reference => "reference",
        }
    }

    /// Parse the wire-shape name. `none`/`dfu` are accepted as aliases for the two shapes that
    /// already went to hardware, so the A/B comparison keeps working.
    pub fn parse(s: &str) -> Option<Sequence> {
        match s {
            "minimal" | "none" => Some(Sequence::Minimal),
            "terminated" | "dfu" => Some(Sequence::Terminated),
            "reference" | "gaster" => Some(Sequence::Reference),
            _ => None,
        }
    }

    /// The transfers this shape puts on the wire, in order, as the operator reads them.
    pub fn steps(self, dnload_len: usize, upload_len: u16) -> Vec<String> {
        let mut v = vec![format!(
            "DNLOAD command ({dnload_len} bytes, {} transfer(s)), bmRequestType 0x21 bRequest 0x01 wValue 0 wIndex 0",
            dnload_len.div_ceil(crate::bundle::DNLOAD_CHUNK)
        )];
        if matches!(self, Sequence::Reference) {
            v.push(
                "DNLOAD 16 zero bytes (DFU_FILE_SUFFIX_LEN) — gaster.c:41,987".to_string(),
            );
        }
        if matches!(self, Sequence::Terminated | Sequence::Reference) {
            v.push("DNLOAD wLength 0 — the end of the download — gaster.c:833".to_string());
        }
        if matches!(self, Sequence::Reference) {
            v.push("DFU_GET_STATUS expect status 0 state 6 (dfuMANIFEST-SYNC) — gaster.c:833".to_string());
            v.push("DFU_GET_STATUS expect status 0 state 7 (dfuMANIFEST)".to_string());
            v.push("DFU_GET_STATUS expect status 0 state 8 (dfuMANIFEST-WAIT-RESET)".to_string());
        }
        v.push(format!(
            "UPLOAD wLength {upload_len} bmRequestType 0xa1 bRequest 0x02 wValue 0xffff wIndex 0 — the trigger"
        ));
        v
    }
}

/// The three states the reference's walk requires, in order (`gaster.c:833`). Public so the live
/// transport, the simulator and the tests cannot disagree about them.
pub const MANIFEST_WALK: [u8; 3] = [6, 7, 8];

/// Perform the reference's MANIFEST walk: three `DFU_GET_STATUS` reads that must see status 0 with
/// state 6, then 7, then 8, in that order.
///
/// Pure, and takes the read as a closure, so the ordering, the messages and the "expected vs saw"
/// reporting are exercised in tests against the simulator **and** used unchanged by the live
/// transport. A mismatch is a named failure that reports the state actually observed, because "the
/// walk failed" is not a diagnosis and "the device is in state 5" is.
pub fn check_manifest_walk<F>(mut status: F) -> Result<u8, String>
where
    F: FnMut() -> Result<DfuStatus, String>,
{
    for expect in MANIFEST_WALK {
        let s = status()?;
        if !s.looks_healthy() || s.state != expect {
            return Err(format!(
                "STATE_WALK_MISMATCH[status=WALK]: expected status 0 state {expect} ({}), saw status \
                 {} state {} ({}). The reference's command framing ends with this walk \
                 (gaster.c:833) and it cannot proceed past a state the device is not in. This is a \
                 *measurement* of where the machine is, not a transport failure: record the state \
                 and re-idle (a bare DFU_CLRSTATUS returns it to 0x02 dfuIDLE and re-enumerates \
                 the device) before the next attempt.",
                state_name(expect),
                s.status,
                s.state,
                s.state_name()
            ));
        }
    }
    Ok(8)
}

/// The DFU 1.1 state name for a number, free-standing so [`check_manifest_walk`] can name an
/// expected state it has not observed.
pub fn state_name(state: u8) -> &'static str {
    DfuStatus { status: 0, poll_timeout: [0; 3], state, str_idx: 0 }.state_name()
}

/// One round trip: `DNLOAD` these bytes, then trigger with `UPLOAD` of this length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    pub dnload: Vec<u8>,
    pub upload_len: u16,
    pub label: String,
    /// Why this exchange exists, in the operator's terms. Evidence only; never sent.
    pub purpose: String,
    /// The wire shape around the command. See [`Sequence`].
    pub sequence: Sequence,
    /// Whether this exchange sends the trigger. Evidence reads it; the transport obeys the
    /// `trigger` argument to `exchange_with`, which is the authority.
    pub trigger: Trigger,
}

impl From<&Packet> for Exchange {
    fn from(p: &Packet) -> Self {
        Exchange {
            dnload: p.dnload.clone(),
            upload_len: p.upload_len,
            label: p.label.clone(),
            purpose: String::new(),
            sequence: Sequence::default(),
            trigger: Trigger::Now,
        }
    }
}

/// Whether the `UPLOAD` trigger is sent as part of this exchange.
///
/// The split exists for **one** reason: `EXEC` must be verifiable *before* it executes. The
/// handler executes whatever the buffer holds the moment the `0xFFFF` `UPLOAD` arrives, so an
/// `EXEC` command is staged without a trigger, read back, compared byte for byte, re-staged, and
/// only then triggered. A transport that cannot defer the trigger says so instead of pretending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Stage the command and send the trigger: the ordinary round trip.
    Now,
    /// Stage the command (and its framing) and stop. Nothing executes; the buffer holds it.
    Deferred,
    /// Send only the trigger and read the reply, for a command already staged.
    Only,
}

pub trait Transport {
    /// The device's serial descriptor. Identity is checked before anything is sent.
    fn serial(&mut self) -> Result<String, String>;
    /// The DNLOAD/UPLOAD pair. The raw `UPLOAD` bytes are returned for `channel::parse_response`.
    fn exchange(&mut self, e: &Exchange) -> Result<Vec<u8>, String>;

    /// The same, with the trigger's timing under the caller's control.
    ///
    /// The default refuses `Deferred`/`Only` by name: a transport that cannot stage without
    /// triggering must not silently trigger.
    fn exchange_with(&mut self, e: &Exchange, trigger: Trigger) -> Result<Vec<u8>, String> {
        match trigger {
            Trigger::Now => self.exchange(e),
            Trigger::Deferred | Trigger::Only => Err(format!(
                "STAGE_UNSUPPORTED: this transport cannot {} — it can only do a complete \
                 DNLOAD+UPLOAD round trip. Refusing rather than triggering when the caller asked \
                 not to.",
                if trigger == Trigger::Deferred { "stage without triggering" } else { "trigger only" }
            )),
        }
    }
    /// One line naming what this transport is, for the plan header.
    fn describe(&self) -> String;

    /// Set the per-attempt timeout in milliseconds. The default is a no-op refusal-by-silence:
    /// a transport that cannot bound an attempt says nothing and keeps its own timeout, and
    /// `bounded::ladder` reports the ladder as unsupported rather than pretending it applied.
    fn set_timeout_ms(&mut self, _ms: u64) {}

    /// `DFU_GET_STATUS` (`bmRequestType 0xa1`, `bRequest 3`, `wLength 6`): the DFU state machine's
    /// own view, read **without touching the command buffer**.
    ///
    /// This is deliberately part of the trait rather than a `firstlight` extra: the state *before*
    /// the first `DNLOAD` is what distinguishes "the channel refused our command" from "the ROM was
    /// not in a state that accepts `DNLOAD`", and those are two different problems with two
    /// different fixes. The request cannot dispatch `EXEC`/`MEMC` either — the resident handler
    /// compares the full halfword `bmRequestType | bRequest << 8` against `0x2A1` and forwards
    /// everything else to the ROM's own handler, and `0x3A1 != 0x2A1`.
    ///
    /// The default is a named refusal, so a transport that cannot do it says so instead of
    /// returning a fabricated state.
    fn dfu_status(&mut self) -> Result<DfuStatus, String> {
        Err("this transport cannot read the DFU status (no GET_STATUS implementation)".to_string())
    }
}

/// The six bytes `DFU_GET_STATUS` returns. Numbering is the DFU 1.1 state table, which is what the
/// reference polls (`gaster.c:39-48`: MANIFEST_SYNC 6, MANIFEST 7, MANIFEST_WAIT_RESET 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfuStatus {
    pub status: u8,
    pub poll_timeout: [u8; 3],
    pub state: u8,
    pub str_idx: u8,
}

impl DfuStatus {
    pub const OK: u8 = 0;

    pub fn parse(b: &[u8]) -> Result<DfuStatus, String> {
        if b.len() < 6 {
            return Err(format!(
                "DFU_GET_STATUS returned {} bytes, wanted 6. The DFU status record is 6 bytes; a \
                 short one is not a state.",
                b.len()
            ));
        }
        Ok(DfuStatus {
            status: b[0],
            poll_timeout: [b[1], b[2], b[3]],
            state: b[4],
            str_idx: b[5],
        })
    }

    pub fn state_name(self) -> &'static str {
        match self.state {
            0 => "appIDLE",
            1 => "appDETACH",
            2 => "dfuIDLE",
            3 => "dfuDNLOAD-SYNC",
            4 => "dfuDNBUSY",
            5 => "dfuDNLOAD-IDLE",
            6 => "dfuMANIFEST-SYNC",
            7 => "dfuMANIFEST",
            8 => "dfuMANIFEST-WAIT-RESET",
            9 => "dfuUPLOAD-IDLE",
            10 => "dfuERROR",
            _ => "UNKNOWN-STATE",
        }
    }

    /// `true` when a `DNLOAD` is expected to be accepted as the start of a fresh download.
    ///
    /// `dfuIDLE` is the state the reference read after a bus reset (`RUNG1-EVIDENCE.md` §3:
    /// `DFU state unread -> 2 (dfuIDLE)`), and it is where a `DNLOAD` begins a new download.
    /// `dfuDNLOAD-IDLE` means a download is already in progress at *some* offset, which is
    /// information the host does not have.
    pub fn accepts_a_fresh_dnload(self) -> bool {
        self.state == 2
    }

    pub fn looks_healthy(self) -> bool {
        self.status == Self::OK
    }

    pub fn summary(self) -> String {
        format!(
            "status {} ({}) state {} ({}) [raw {:#04x} {:02x} {:02x} {:02x} {:#04x} {:#04x}]",
            self.status,
            if self.looks_healthy() { "OK" } else { "NOT OK" },
            self.state,
            self.state_name(),
            self.status,
            self.poll_timeout[0],
            self.poll_timeout[1],
            self.poll_timeout[2],
            self.state,
            self.str_idx
        )
    }
}

// ---------------------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------------------

type ExecFn = Box<dyn FnMut(u64, u64) -> (u64, Vec<u8>)>;

/// Canned AUSB PHY register contents for the simulator. **Canned, not measured** — labelled here
/// so nobody later reads them as a device fact.
pub const SIM_AUSB_CTL: u32 = 0x0000_0000; // RESET/PWRDOWN/SIDDQ clear: what DFU expects
pub const SIM_AUSB_SIG: u32 = 0x0000_0100; // bit8 CABLE_CONNECTED
pub const SIM_AUSB_CFG0: u32 = 0x0000_0030;
pub const SIM_AUSB_CFG1: u32 = 0x0000_3f01;

pub struct SimDevice {
    /// The ROM's DFU buffer. Successive DNLOADs accumulate from offset 0, which is the
    /// behaviour the real ROM is INFERRED to have (that is how a large iBSS arrives).
    pub buffer: Vec<u8>,
    /// Physical address space, sparse. Regions may be declared unreachable, which is how the
    /// DRAM-reachability refusal is tested without hardware.
    mem: BTreeMap<u64, u8>,
    /// Addresses below this are "not mapped by the ROM's EL3 translation".
    pub reachable: Vec<(u64, u64)>,
    pub serial: String,
    /// What `DFU_GET_STATUS` reports. Defaults to `dfuIDLE`, the post-reset state the reference
    /// measured; a test can move it to exercise the "wrong state" diagnosis.
    ///
    /// A `DNLOAD` moves it, exactly as it does on the device: MEASURED, attempt 1 left the machine
    /// in `0x05 dfuDNLOAD-IDLE`. The sequence's suffix/zero-length/walk then drives it to 8.
    pub dfu_state: u8,
    /// The states the modelled MANIFEST walk serves, in order. `MANIFEST_WALK` by default; a test
    /// can stall it to prove the mismatch is caught by name.
    pub manifest_walk_states: Vec<u8>,
    /// A modelled DNLOAD accumulation limit *smaller* than the buffer: bytes past it are silently
    /// dropped, which is the "corruption, not a stall" behaviour `DESIGN.md:188` warns about and
    /// exactly what the capacity ladder has to detect. `None` = the whole buffer accumulates.
    pub modelled_dnload_capacity: Option<usize>,
    /// The walk being served, and how far it has got. Only non-empty while a `Reference` exchange
    /// is in flight.
    dfu_walk: Vec<u8>,
    dfu_walk_served: usize,
    exec_fn: Option<ExecFn>,
    /// Every exchange, in order. The plan/verification tests assert on this.
    pub log: Vec<Exchange>,
}

impl SimDevice {
    pub fn new(buffer_size: usize) -> Self {
        let mut dev = SimDevice {
            buffer: vec![0u8; buffer_size],
            mem: BTreeMap::new(),
            reachable: vec![
                (layout::DFU_BUFFER_ADDR, layout::DFU_BUFFER_ADDR + buffer_size as u64),
                (layout::DRAM_BASE, layout::DRAM_BASE + layout::DRAM_SIZE),
                // The AUSB PHY page. The SecureROM programmed this PHY — that is how the DFU
                // session exists at all — so these addresses are inside its translation with the
                // highest confidence available, and they are where `firstlight` reads by default.
                (layout::AUSB_PHY_BASE, layout::AUSB_PHY_BASE + 0x10),
            ],
            serial: "CPID:8003 CPRV:11 CPFM:03 SCEP:01 BDID:02 ECID:0000 SRTG:[iBoot-2234.0.0.2.22] \
                     PWND:[checkm8]"
                .to_string(),
            dfu_state: 2, // dfuIDLE
            manifest_walk_states: MANIFEST_WALK.to_vec(),
            modelled_dnload_capacity: None,
            dfu_walk: Vec::new(),
            dfu_walk_served: 0,
            exec_fn: None,
            log: Vec::new(),
        };
        // Canned register contents, and labelled canned: the simulator models the *channel*, not
        // the PHY. They exist so a test can exercise the "plausible pair" and "CTL clear,
        // CABLE_CONNECTED set" interpretation branches without a device. A test that needs other
        // values pokes them.
        dev.poke(layout::AUSB_PHY_BASE, &SIM_AUSB_CTL.to_le_bytes());
        dev.poke(layout::AUSB_PHY_BASE + 4, &SIM_AUSB_SIG.to_le_bytes());
        dev.poke(layout::AUSB_CFG0_ADDR, &SIM_AUSB_CFG0.to_le_bytes());
        dev.poke(layout::AUSB_CFG1_ADDR, &SIM_AUSB_CFG1.to_le_bytes());
        dev
    }

    /// Simulate a device whose ROM translation does **not** cover DRAM: the exact condition
    /// PLAN B exists for. Every DRAM access then fails like a fault would.
    pub fn with_dram_unreachable(mut self) -> Self {
        self.reachable.retain(|(b, _)| *b != layout::DRAM_BASE);
        self
    }

    pub fn on_exec(&mut self, f: impl FnMut(u64, u64) -> (u64, Vec<u8>) + 'static) {
        self.exec_fn = Some(Box::new(f));
    }

    /// The DFU buffer is part of the address space, and the resident handler's whole job is
    /// copying in and out of it. Modelling it separately from `mem` was a bug the first time
    /// round: `MEMC` then read zeros from the buffer and every write looked like it had silently
    /// failed. The buffer is the *source* of every staged byte, so it must be addressable.
    fn buffer_offset(&self, addr: u64) -> Option<usize> {
        let end = layout::DFU_BUFFER_ADDR + self.buffer.len() as u64;
        if addr >= layout::DFU_BUFFER_ADDR && addr < end {
            Some((addr - layout::DFU_BUFFER_ADDR) as usize)
        } else {
            None
        }
    }

    fn is_reachable(&self, addr: u64, len: usize) -> bool {
        // A zero-length copy accesses nothing, so it is reachable by definition. The capacity
        // ladder's whole design rests on this: `memcpy(0, 0, 0)` is a command with no side effects.
        if len == 0 {
            return true;
        }
        let end = match addr.checked_add(len as u64) {
            Some(e) => e,
            None => return false,
        };
        self.reachable.iter().any(|(b, e)| addr >= *b && end <= *e)
    }

    pub fn peek(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|i| {
                let a = addr + i;
                match self.buffer_offset(a) {
                    Some(off) => self.buffer[off],
                    None => *self.mem.get(&a).unwrap_or(&0),
                }
            })
            .collect()
    }

    pub fn poke(&mut self, addr: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let a = addr + i as u64;
            match self.buffer_offset(a) {
                Some(off) => self.buffer[off] = *b,
                None => {
                    self.mem.insert(a, *b);
                }
            }
        }
    }

    fn u64_at_buffer(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.buffer[off..off + 8].try_into().unwrap())
    }
}

/// The simulator's implementation of the resident handler, decoded from
/// `payload_handle_checkm8_request.S`. Returns named errors where the real thing would stall,
/// fault, or silently do the wrong thing.
///
/// `exchange_with` splits the two halves the way the device does: a `Deferred` call only writes
/// the buffer and advances the framing (nothing dispatches), and an `Only` call dispatches on
/// **whatever the buffer holds at that moment** — which is what makes a staged-then-triggered
/// `EXEC` testable, and what makes the simulator model "the buffer *is* the command".
impl Transport for SimDevice {
    fn serial(&mut self) -> Result<String, String> {
        Ok(self.serial.clone())
    }

    fn dfu_status(&mut self) -> Result<DfuStatus, String> {
        // While a `Reference` exchange is in flight the walk is served from the modelled
        // transition list, one state per read; otherwise the machine's own state is reported.
        let state = if self.dfu_walk.is_empty() {
            self.dfu_state
        } else {
            let i = self.dfu_walk_served.min(self.dfu_walk.len() - 1);
            self.dfu_walk_served += 1;
            self.dfu_walk[i]
        };
        Ok(DfuStatus { status: 0, poll_timeout: [0, 0, 0], state, str_idx: 0 })
    }

    fn exchange(&mut self, e: &Exchange) -> Result<Vec<u8>, String> {
        self.exchange_with(e, Trigger::Now)
    }

    fn exchange_with(&mut self, e: &Exchange, trigger: Trigger) -> Result<Vec<u8>, String> {
        if e.dnload.len() > self.buffer.len() {
            return Err(format!(
                "DNLOAD of {} bytes does not fit the simulated buffer of {} bytes",
                e.dnload.len(),
                self.buffer.len()
            ));
        }
        // The download *offset* state machine is deliberately NOT modelled: whether the ROM
        // resets its write offset between commands is exactly the question the two-read
        // experiment asks, and inventing the answer here would make the simulator agree with
        // whichever answer we coded. What IS modelled is the DFU *state* sequence, because that
        // is measured on the device (`0x02` idle → `0x05` after a DNLOAD; the reference's walk
        // then drives 6 → 7 → 8) and the walk's ordering is what the reference hangs on.
        self.log.push(e.clone());
        if trigger != Trigger::Only {
            let n = match self.modelled_dnload_capacity {
                Some(cap) => e.dnload.len().min(cap),
                None => e.dnload.len(),
            };
            self.buffer[..n].copy_from_slice(&e.dnload[..n]);
            // Past the modelled capacity the rest of the pattern simply never arrives — silently,
            // because that is what "corruption, not a stall" means.
        }

        // The framing happens on a stage; the reply happens on a trigger.
        if trigger == Trigger::Deferred {
            match e.sequence {
                Sequence::Minimal => self.dfu_state = 5,
                Sequence::Terminated => self.dfu_state = 6,
                Sequence::Reference => {
                    self.dfu_state = 5;
                    self.dfu_walk = self.manifest_walk_states.clone();
                    self.dfu_walk_served = 0;
                    let walk = check_manifest_walk(|| self.dfu_status())?;
                    self.dfu_walk.clear();
                    self.dfu_walk_served = 0;
                    self.dfu_state = walk;
                }
            }
            return Ok(Vec::new());
        }

        let magic = self.u64_at_buffer(0);
        let retval = match magic {
            abi::EXEC_MAGIC => {
                let func = self.u64_at_buffer(8);
                if func != abi::payload_exec_addr() {
                    return Err(format!(
                        "EXEC asked for func {func:#x}, but the a9boot payload executes at {:#x}",
                        abi::payload_exec_addr()
                    ));
                }
                let cmd = self.u64_at_buffer(0x10);
                let desc = self.u64_at_buffer(0x18);
                match self.exec_fn.as_mut() {
                    Some(f) => {
                        let (rv, reply) = f(cmd, desc);
                        let at = abi::REPLY_OFF as usize;
                        let n = reply.len().min(abi::REPLY_CAP as usize);
                        self.buffer[at..at + n].copy_from_slice(&reply[..n]);
                        rv
                    }
                    None => return Err("EXEC with no payload registered in the simulator".into()),
                }
            }
            abi::MEMC_MAGIC => {
                let dst = self.u64_at_buffer(0x10);
                let src = self.u64_at_buffer(0x18);
                let len = self.u64_at_buffer(0x20) as usize;
                // A fault here would take the ROM's EL3 handler with it, which is why the
                // failure is named rather than attempted. Both directions name PLAN B: the
                // question "does the ROM's translation reach DRAM" is the same question.
                if !self.is_reachable(src, len) {
                    return Err(format!(
                        "MEMC read from {src:#x} len {len:#x}: not reachable through the ROM's \
                         translation. That is PLAN B (DESIGN.md §11.1): the ROM's EL3 map does \
                         not cover DRAM, so nothing can be staged and the design stops here."
                    ));
                }
                if !self.is_reachable(dst, len) {
                    return Err(format!(
                        "MEMC write to {dst:#x} len {len:#x}: not reachable through the ROM's \
                         translation. That is PLAN B (DESIGN.md §11.1): the ROM's EL3 map does \
                         not cover DRAM, so nothing can be staged and the design stops here."
                    ));
                }
                let data = self.peek(src, len);
                self.poke(dst, &data);
                // The handler returns memcpy's return value, which is the destination.
                dst
            }
            other => {
                return Err(format!(
                    "command magic {other:#018x} is neither EXEC_MAGIC nor MEMC_MAGIC; the \
                     resident handler would forward this to the ROM's own handler"
                ))
            }
        };

        self.buffer[0..8].copy_from_slice(&abi::DONE_MAGIC.to_le_bytes());
        self.buffer[8..16].copy_from_slice(&retval.to_le_bytes());
        let want = e.upload_len as usize;
        if want > self.buffer.len() {
            return Err(format!(
                "UPLOAD of {} bytes exceeds the simulated buffer of {}",
                want,
                self.buffer.len()
            ));
        }

        // The sequence's framing, modelled from the measurements and the reference.
        match e.sequence {
            Sequence::Minimal => self.dfu_state = 5, // dfuDNLOAD-IDLE after a DNLOAD
            Sequence::Terminated => self.dfu_state = 6,
            Sequence::Reference => {
                self.dfu_state = 5;
                // The zero-length DNLOAD, then the three GET_STATUS reads. A device that does not
                // reach 6/7/8 is modelled by replacing `manifest_walk_states`.
                self.dfu_walk = self.manifest_walk_states.clone();
                self.dfu_walk_served = 0;
                let walk = check_manifest_walk(|| self.dfu_status())?;
                self.dfu_walk.clear();
                self.dfu_walk_served = 0;
                self.dfu_state = walk;
            }
        }
        Ok(self.buffer[..want].to_vec())
    }

    fn describe(&self) -> String {
        format!(
            "SimDevice: buffer {} bytes at {:#x}, DRAM reachable: {}",
            self.buffer.len(),
            layout::DFU_BUFFER_ADDR,
            self.reachable.iter().any(|(b, _)| *b == layout::DRAM_BASE)
        )
    }
}

// ---------------------------------------------------------------------------------------
// The real thing
// ---------------------------------------------------------------------------------------

#[cfg(feature = "usb")]
pub mod live;

/// Refuse to construct a live transport in a build that has no USB capability.
///
/// The default build has no code path that can open a device, and this function exists so that
/// a caller asking for one gets a clear answer instead of a silent no-op.
pub fn open_live() -> Result<(), String> {
    #[cfg(not(feature = "usb"))]
    {
        Err("this build of a9boot-host has no USB capability (built without --features usb). \
             That is deliberate: the default build cannot touch the device. Device access is \
             Lead-only."
            .to_string())
    }
    #[cfg(feature = "usb")]
    {
        // Delegated to `live::LiveTransport::open()`, which is still never called by a9boot
        // itself: no command in this crate opens a device.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{mem_read, mem_write, parse_response};
    use a9boot_core::abi::Command;

    #[test]
    #[cfg(not(feature = "usb"))]
    fn default_build_cannot_open_a_device() {
        let e = open_live().unwrap_err();
        assert!(e.contains("no USB capability"), "{e}");
    }

    /// With the `usb` feature the capability exists, and this test asserts only that: **no test
    /// in this workspace opens a device**, in either build flavour. The live path is reached by
    /// one command-line entry point and by nothing else.
    #[test]
    #[cfg(feature = "usb")]
    fn usb_build_has_the_capability_and_no_test_uses_it() {
        assert!(open_live().is_ok());
    }

    #[test]
    fn memc_round_trips_through_the_simulator() {
        let mut dev = SimDevice::new(0x4000);
        // Write a 4-byte pattern into DRAM.
        let p = mem_write(layout::DRAM_BASE, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let raw = dev.exchange(&Exchange::from(&p)).unwrap();
        let r = parse_response(&raw, p.upload_len).unwrap();
        assert_eq!(r.retval, layout::DRAM_BASE);
        assert_eq!(dev.peek(layout::DRAM_BASE, 4), vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // Read it back through the same channel.
        let p = mem_read(layout::DRAM_BASE, 4);
        let raw = dev.exchange(&Exchange::from(&p)).unwrap();
        let r = parse_response(&raw, p.upload_len).unwrap();
        assert_eq!(&r.data[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// The refusal PLAN B exists for: DRAM not reachable through the ROM's translation.
    #[test]
    fn unreachable_dram_is_a_named_refusal() {
        let mut dev = SimDevice::new(0x4000).with_dram_unreachable();
        let p = mem_write(layout::DRAM_BASE, &[1, 2, 3, 4]);
        let e = dev.exchange(&Exchange::from(&p)).unwrap_err();
        assert!(e.contains("not reachable"), "{e}");
        assert!(e.contains("PLAN B"), "{e}");
    }

    /// A DNLOAD larger than the buffer is refused *before* it can be sent — the capacity probe
    /// is what establishes the real limit, and this is the check that uses it.
    #[test]
    fn oversized_dnload_is_refused_locally() {
        let mut dev = SimDevice::new(0x800);
        let p = mem_write(layout::DRAM_BASE, &vec![0u8; 0x900]);
        let e = dev.exchange(&Exchange::from(&p)).unwrap_err();
        assert!(e.contains("does not fit the simulated buffer"), "{e}");
    }

    #[test]
    fn the_reference_sequence_walks_the_manifest_states_in_order() {
        let mut dev = SimDevice::new(0x4000);
        let mut p = crate::channel::mem_read(layout::AUSB_CFG0_ADDR, 8);
        let mut e = Exchange::from(&p);
        e.sequence = Sequence::Reference;
        let raw = dev.exchange(&e).unwrap();
        assert_eq!(dev.dfu_state, 8, "the walk ends in dfuMANIFEST-WAIT-RESET");
        assert_eq!(raw.len(), p.upload_len as usize);
        // The two exchanges differ only in framing, and the framing is recorded.
        p.upload_len = e.upload_len;
        assert_eq!(e.sequence.name(), "reference");
        assert!(Sequence::Reference.steps(72, 24).iter().any(|s| s.contains("16 zero bytes")));
        assert_eq!(Sequence::Minimal.steps(72, 24).len(), 2);
        assert_eq!(Sequence::Terminated.steps(72, 24).len(), 3);
        assert_eq!(Sequence::Reference.steps(72, 24).len(), 7);
    }

    #[test]
    fn negative_control_a_walk_that_does_not_reach_the_states_fails_by_name() {
        // The device stays in dfuDNLOAD-IDLE: exactly the shape of the two hardware attempts, and
        // the check must name the state it saw instead of reporting a generic failure.
        let mut dev = SimDevice::new(0x4000);
        dev.manifest_walk_states = vec![5, 7, 8];
        let mut e = Exchange::from(&crate::channel::mem_read(layout::AUSB_CFG0_ADDR, 8));
        e.sequence = Sequence::Reference;
        let err = dev.exchange(&e).unwrap_err();
        assert!(err.contains("STATE_WALK_MISMATCH"), "{err}");
        // Its own status token, so the evidence's `status` field can never read `OK` on a walk
        // failure (the transport status and the DFU status are different quantities).
        assert!(err.contains("[status=WALK]"), "{err}");
        assert_eq!(crate::evidence::status_tag_from_error(&err), "WALK");
        assert!(err.contains("state 5"), "{err}");
        assert!(err.contains("dfuDNLOAD-IDLE"), "{err}");
        assert!(err.contains("DFU_CLRSTATUS"), "the recovery must be in the message: {err}");
    }

    #[test]
    fn sequence_names_and_parse_aliases_are_stable() {
        assert_eq!(Sequence::default(), Sequence::Minimal);
        assert_eq!(Sequence::parse("none"), Some(Sequence::Minimal));
        assert_eq!(Sequence::parse("dfu"), Some(Sequence::Terminated));
        assert_eq!(Sequence::parse("gaster"), Some(Sequence::Reference));
        assert_eq!(Sequence::parse("reference"), Some(Sequence::Reference));
        assert_eq!(Sequence::parse("whatever"), None);
        assert_eq!(state_name(6), "dfuMANIFEST-SYNC");
        assert_eq!(state_name(8), "dfuMANIFEST-WAIT-RESET");
    }

    #[test]
    fn identity_and_exec_share_one_simulator() {
        let mut dev = SimDevice::new(0x4000);
        let serial = dev.serial().unwrap();
        crate::channel::check_identity(&serial, &crate::channel::Expect::default()).unwrap();

        dev.on_exec(|cmd, _desc| {
            assert_eq!(cmd, Command::Ping as u64);
            let r = a9boot_core::abi::Reply {
                command: cmd,
                status: a9boot_core::abi::status::OK,
                ..Default::default()
            };
            (a9boot_core::abi::status::OK, r.encode().to_vec())
        });
        let p = crate::channel::exec_packet(&[0u8; 8], Command::Ping);
        let raw = dev.exchange(&Exchange::from(&p)).unwrap();
        let r = parse_response(&raw, p.upload_len).unwrap();
        assert_eq!(r.reply().unwrap().command, Command::Ping as u64);
    }

    #[test]
    fn an_exec_at_the_wrong_address_is_refused() {
        let mut dev = SimDevice::new(0x4000);
        dev.on_exec(|_, _| (0, vec![]));
        let mut p = crate::channel::exec_packet(&[0u8; 8], Command::Ping);
        // A payload linked anywhere else would run with the wrong absolute addresses.
        p.dnload[8..16].copy_from_slice(&(abi::payload_exec_addr() + 0x40).to_le_bytes());
        let e = dev.exchange(&Exchange::from(&p)).unwrap_err();
        assert!(e.contains("executes at"), "{e}");
    }
}
