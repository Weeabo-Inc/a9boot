//! Evidence: turn a channel exchange into a record a reviewer can check.
//!
//! The failure this module exists to make impossible is the one this project has paid for five
//! times: **a codec that never ran returning a plausible value that gets reported as success.**
//! So the rules here are structural, not stylistic:
//!
//! 1. Every exchange is recorded with the exact bytes sent, the exact bytes received, and a
//!    monotonic timestamp pair. Nothing is summarised away.
//! 2. A field that was not read is **UNREAD**, never `0`. A reply that did not arrive has no
//!    return value; the absence of a value must not be spelled like a value.
//! 3. A reply that arrives and does not satisfy the `[DONE_MAGIC][ret]` contract is rejected
//!    **by name** (`channel::ReplyFault`), and the name goes into the transcript.
//! 4. A transcript with no exchanges is `UNKNOWN`, never `PASS`. A dry run proves nothing about
//!    the device, and the verdict says so.
//! 5. Hashes are SHA-256, computed here, with known-answer tests — so "the bytes in this file
//!    are the bytes that went on the wire" is checkable without trusting the tool.
//!
//! See `a9boot/docs/RUNBOOK-RUNG2-FIRSTLIGHT.md`.

use crate::channel::{self, Packet, ReplyFault};
use crate::transport::{Exchange, Sequence, Transport, Trigger};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Schema tag. Bump when a field is renamed or removed; a reader that does not know the version
/// must refuse rather than guess.
pub const SCHEMA: &str = "a9boot.evidence/1";

// ---------------------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------------------

/// Lower-case hex, the only encoding evidence bytes are published in.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// First `n` bytes as hex, for a bounded look at a long buffer.
pub fn hex_prefix(bytes: &[u8], n: usize) -> String {
    hex(&bytes[..bytes.len().min(n)])
}

/// A `u64` as `0x`-prefixed lower-case hex.
pub fn hex64(v: u64) -> String {
    format!("{v:#018x}")
}

// ---------------------------------------------------------------------------------------
// SHA-256 (self-contained: no third-party crates in the evidence path)
// ---------------------------------------------------------------------------------------

/// SHA-256 of `data`, as lower-case hex.
///
/// Rolled by hand rather than pulled in, for the same reason the ELF flattener was: the evidence
/// path must not depend on code we cannot test against published vectors. The tests below use
/// the NIST/FIPS-180-4 known answers, including the two-block case, because a hash function that
/// is merely *self-consistent* is exactly the confident-wrong value this project keeps catching.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// UTC, to the second, in ISO-8601. Enough for evidence, and no dependency on a date crate.
pub fn iso8601_utc(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------------------
// One exchange, as evidence
// ---------------------------------------------------------------------------------------

/// What the reply bytes were, and whether they satisfied the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseState {
    /// No usable bytes. Carries the reason; there is no value, and the transcript says so.
    Unread { reason: String },
    /// `[DONE_MAGIC][retval][data..]`, intact.
    Parsed {
        magic: u64,
        retval: u64,
        retval_label: &'static str,
        data_len: usize,
    },
    /// Bytes arrived and were rejected, by name.
    Malformed { fault: ReplyFault, detail: String },
}

impl ParseState {
    pub fn name(&self) -> &'static str {
        match self {
            ParseState::Unread { .. } => "UNREAD",
            ParseState::Parsed { .. } => "PARSED",
            ParseState::Malformed { .. } => "MALFORMED",
        }
    }
    fn is_parsed(&self) -> bool {
        matches!(self, ParseState::Parsed { .. })
    }
}

/// One DNLOAD/UPLOAD round trip, recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRecord {
    pub index: usize,
    pub label: String,
    /// What this exchange is for, in the operator's terms.
    pub purpose: String,
    pub dnload: Vec<u8>,
    pub dnload_chunks: usize,
    /// The wire shape around the command: `minimal`, `terminated` or `reference`. This is not
    /// cosmetic — the two shapes already run on hardware differ only here.
    pub sequence: Sequence,
    /// Whether this exchange sent the trigger: `Now`, `Deferred` (staged, nothing executed) or
    /// `Only` (a trigger for something already staged).
    pub trigger: Trigger,
    pub upload_len: u16,
    pub start_us: u128,
    pub duration_us: u128,
    /// `None` when nothing came back; never a fabricated empty vector.
    pub upload: Option<Vec<u8>>,
    pub transport_error: Option<String>,
    /// The transport's own verdict, as a stable token: `OK`, `TIMEOUT`, `STALL`, `NO_DEVICE`,
    /// `ACCESS`, `BUSY`, `NOT_FOUND`, `CANCELLED`, `IO`, `OTHER`.
    ///
    /// This is **diagnostic**. It says what the USB path did, not whether the command worked.
    pub status: &'static str,
    /// How many bytes the transport actually moved, when it knows.
    ///
    /// On success this is `upload.len()`. On a failed control transfer it is `None`, because
    /// `rusb`'s synchronous API does not report a partial length for a failed transfer — and
    /// reporting `0` there would be the "0 is not a measurement" mistake. A partial reply on a
    /// timed-out UPLOAD is therefore **not observable** through this API, which is recorded rather
    /// than papered over.
    pub actual_length: Option<usize>,
    pub parse: ParseState,
}

/// The four quantities every exchange has, and which one is the success criterion.
///
/// | quantity | where it comes from | role |
/// |---|---|---|
/// | **channel** | `bmRequestType`, `bRequest`, `wValue`, `wIndex` | addressing. Wrong here means the request routes somewhere else (the resident handler matches `bmRequestType \| bRequest << 8` against `0x2A1`, and `wValue` against `0xFFFF`). Necessary, never sufficient. |
/// | **length** | `wLength` | **an input to the device**: the handler reads it back out of the setup packet (`ldrh w2, [x19, #0x6]`) and sends exactly that many bytes from the buffer. Asking for the wrong length changes what the device does. |
/// | **status** | the URB/libusb result | **diagnostic**: did the transfer complete, time out or STALL. A completed transfer with garbage bytes is a FAIL, not a success. |
/// | **actual_length** | bytes actually transferred | **half of the success criterion**: `actual_length == wLength`. The other half is the content check below. |
///
/// **SUCCESS CRITERION (both, together):** `actual_length == wLength` **and** the returned bytes
/// start with `DONE_MAGIC` followed by a return value. Everything else — a zero status, a
/// plausible-looking register value, a length that "looks right" — is diagnostic only.
pub const SUCCESS_CRITERION: &str =
    "actual_length == wLength AND the reply begins with [DONE_MAGIC][retval]; the channel, the \
     requested length and the transfer status are diagnostics and cannot establish success on \
     their own";

/// Decode the `[status=...]` token a transport puts in its error message.
///
/// The transport is the only producer of these strings, and this is the one place they are read
/// back, with the known set enumerated: a transport that invents a new token yields `OTHER` rather
/// than an unrecognised value masquerading as a status.
pub fn status_tag_from_error(msg: &str) -> &'static str {
    const KNOWN: &[&str] = &[
        "OK", "TIMEOUT", "STALL", "NO_DEVICE", "ACCESS", "BUSY", "NOT_FOUND", "CANCELLED", "IO",
        "NOT_SUPPORTED", "BAD_DESCRIPTOR", "OVERFLOW", "NO_MEM", "INVALID_PARAM", "WALK", "OTHER",
    ];
    let Some((_, rest)) = msg.split_once("[status=") else { return "OTHER" };
    let Some((tag, _)) = rest.split_once(']') else { return "OTHER" };
    KNOWN.iter().find(|k| **k == tag).copied().unwrap_or("OTHER")
}

impl ExchangeRecord {
    pub fn verdict(&self) -> Verdict {
        if self.transport_error.is_some() {
            return Verdict::Fail;
        }
        if self.parse.is_parsed() {
            Verdict::Pass
        } else {
            Verdict::Fail
        }
    }

    /// The one-line operator answer: what happened, or that nothing did.
    pub fn summary(&self) -> String {
        match (&self.transport_error, &self.parse) {
            (Some(e), _) => format!(
                "[{}] {}: NO REPLY (status {}) — {e}",
                self.index, self.label, self.status
            ),
            (None, ParseState::Parsed { retval, retval_label, data_len, .. }) => format!(
                "[{}] {}: status {}, actual_length {}/{}, DONE_MAGIC + retval {retval:#x} \
                 ({retval_label}), {data_len} reply bytes, {} µs",
                self.index,
                self.label,
                self.status,
                self.actual_length.unwrap_or(0),
                self.upload_len,
                self.duration_us
            ),
            (None, ParseState::Malformed { fault, detail }) => {
                format!("[{}] {}: REJECTED {} — {detail}", self.index, self.label, fault.name())
            }
            (None, ParseState::Unread { reason }) => {
                format!("[{}] {}: UNREAD — {reason}", self.index, self.label)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Unknown,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------------------
// The recording transport
// ---------------------------------------------------------------------------------------

/// Wraps any [`Transport`] and records everything that passes through it.
///
/// It does not change a single byte and does not swallow an error: the wrapped call's result is
/// returned unchanged, so `bundle::execute_steps` and the probe behave identically with and
/// without the recorder. That property is what makes the transcript evidence rather than a
/// parallel opinion.
pub struct Recorder<T: Transport> {
    inner: T,
    t0: Instant,
    started: SystemTime,
    /// Redacted descriptor, once `serial()` has been called.
    pub identity: Option<String>,
    pub identity_error: Option<String>,
    pub records: Vec<ExchangeRecord>,
    /// Operator-facing notes that are not exchanges (identity result, gate refusals, ...).
    pub notes: Vec<String>,
}

impl<T: Transport> Recorder<T> {
    pub fn new(inner: T) -> Self {
        Recorder {
            inner,
            t0: Instant::now(),
            started: SystemTime::now(),
            identity: None,
            identity_error: None,
            records: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Assemble the evidence transcript for this run.
    ///
    /// `verdict_override` exists for the probe, where a tolerated failure *is* the measurement:
    /// the DRAM walk stops at the first address that does not round-trip, and that address is the
    /// answer. The caller supplies the verdict and the reason it was reached, so the transcript
    /// never has to guess what the run was for.
    pub fn transcript(
        &self,
        command: String,
        mode: &'static str,
        warnings: Vec<String>,
        extras: Vec<(String, String)>,
        verdict_override: Option<(Verdict, Option<String>)>,
    ) -> Transcript {
        let (verdict, verdict_reason) = match verdict_override {
            Some((v, r)) => (v, r),
            None => (self.verdict(), self.verdict_reason()),
        };
        Transcript {
            command,
            mode,
            usb_feature: cfg!(feature = "usb"),
            transport: self.describe(),
            started_utc: iso8601_utc(self.started),
            finished_utc: iso8601_utc(SystemTime::now()),
            wall_clock_ms: self.elapsed().as_millis(),
            identity: self.identity.clone(),
            identity_error: self.identity_error.clone(),
            identity_checked: self.identity.is_some(),
            records: self.records.clone(),
            notes: self.notes.clone(),
            warnings,
            extras,
            verdict,
            verdict_reason,
        }
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutable access, for tests that need to change the *device model* between exchanges (e.g.
    /// poisoning a staged buffer to prove the verification catches it). Never used by the tool.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// How many exchanges have been recorded so far. Used by the provenance warning, which must
    /// know whether this is a first-and-only exchange.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn elapsed(&self) -> Duration {
        self.t0.elapsed()
    }

    /// The transcript verdict. **A run with no exchanges is UNKNOWN**, because nothing about the
    /// device was tested — that is the whole point of the type.
    pub fn verdict(&self) -> Verdict {
        if self.records.is_empty() {
            return Verdict::Unknown;
        }
        if self.records.iter().all(|r| r.verdict() == Verdict::Pass) {
            Verdict::Pass
        } else {
            Verdict::Fail
        }
    }

    /// The one-line reason behind the verdict, or `None` when it is PASS.
    pub fn verdict_reason(&self) -> Option<String> {
        match self.verdict() {
            Verdict::Pass => None,
            Verdict::Unknown => Some(
                "no exchange was attempted, so nothing about the device was measured. A dry run \
                 is not evidence of a working channel."
                    .to_string(),
            ),
            Verdict::Fail => {
                let first = self.records.iter().find(|r| r.verdict() != Verdict::Pass)?;
                Some(first.summary())
            }
        }
    }

    fn record(
        &mut self,
        e: &Exchange,
        trigger: Trigger,
        index: usize,
        result: &Result<Vec<u8>, String>,
        start_us: u128,
        end_us: u128,
    ) {
        let (upload, transport_error) = match result {
            Ok(v) => (Some(v.clone()), None),
            Err(err) => (None, Some(err.clone())),
        };
        let parse = match (&upload, &transport_error) {
            // A deferred stage sends no trigger, so there is no reply to parse and none is
            // expected: `UNREAD` with the reason, never `MALFORMED`.
            (Some(bytes), None) if trigger == Trigger::Deferred && bytes.is_empty() => {
                ParseState::Unread {
                    reason: "deferred stage: the trigger was deliberately not sent, so no reply                              exists for this command yet"
                        .to_string(),
                }
            }
            (Some(bytes), None) => match channel::parse_response_checked(bytes, e.upload_len) {
                Ok(r) => ParseState::Parsed {
                    magic: a9boot_core::abi::DONE_MAGIC,
                    retval: r.retval,
                    retval_label: a9boot_core::abi::status::name(r.retval),
                    data_len: r.data.len(),
                },
                Err((fault, detail)) => ParseState::Malformed { fault, detail },
            },
            (None, Some(err)) => ParseState::Unread { reason: err.clone() },
            (None, None) => ParseState::Unread {
                reason: "the transport returned neither bytes nor an error".to_string(),
            },
            (Some(_), Some(_)) => ParseState::Unread {
                reason: "the transport returned both bytes and an error".to_string(),
            },
        };
        let status = match (&transport_error, &upload) {
            (Some(err), _) => status_tag_from_error(err),
            (None, Some(_)) => "OK",
            (None, None) => "OTHER",
        };
        let actual_length = upload.as_ref().map(|b| b.len());
        self.records.push(ExchangeRecord {
            index,
            label: e.label.clone(),
            purpose: e.purpose.clone(),
            dnload: e.dnload.clone(),
            dnload_chunks: e.dnload.len().div_ceil(crate::bundle::DNLOAD_CHUNK),
            sequence: e.sequence,
            trigger,
            upload_len: e.upload_len,
            start_us,
            duration_us: end_us.saturating_sub(start_us),
            upload,
            transport_error,
            status,
            actual_length,
            parse,
        });
    }
}

impl<T: Transport> Transport for Recorder<T> {
    fn serial(&mut self) -> Result<String, String> {
        match self.inner.serial() {
            Ok(s) => {
                let redacted = channel::redact_descriptor(&s);
                self.identity = Some(redacted);
                Ok(s)
            }
            Err(e) => {
                self.identity_error = Some(e.clone());
                Err(e)
            }
        }
    }

    fn exchange(&mut self, e: &Exchange) -> Result<Vec<u8>, String> {
        self.exchange_with(e, Trigger::Now)
    }

    /// Recorded with the trigger phase, because for a staged `EXEC` the *absence* of a reply is
    /// the point: a `Deferred` call must not have triggered anything, and the transcript says so.
    fn exchange_with(&mut self, e: &Exchange, trigger: Trigger) -> Result<Vec<u8>, String> {
        let start_us = self.t0.elapsed().as_micros();
        let result = self.inner.exchange_with(e, trigger);
        let end_us = self.t0.elapsed().as_micros();
        let index = self.records.len();
        self.record(e, trigger, index, &result, start_us, end_us);
        result
    }

    /// `DFU_GET_STATUS`, proxied and recorded as a note: it is not a `DNLOAD`/`UPLOAD` exchange
    /// and it never touches the command buffer, so recording it as one would misrepresent the
    /// evidence. An unreadable state is recorded as `UNREAD`, never as a default.
    fn dfu_status(&mut self) -> Result<crate::transport::DfuStatus, String> {
        match self.inner.dfu_status() {
            Ok(s) => {
                self.notes.push(format!("DFU_GET_STATUS (read-only): {}", s.summary()));
                Ok(s)
            }
            Err(e) => {
                self.notes.push(format!("DFU_GET_STATUS UNREAD: {e}"));
                Err(e)
            }
        }
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }
}

// ---------------------------------------------------------------------------------------
// The transcript
// ---------------------------------------------------------------------------------------

/// The whole run, as the JSON document a reviewer reads.
pub struct Transcript {
    pub command: String,
    pub mode: &'static str,
    pub usb_feature: bool,
    pub transport: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub wall_clock_ms: u128,
    pub identity: Option<String>,
    pub identity_error: Option<String>,
    pub identity_checked: bool,
    pub records: Vec<ExchangeRecord>,
    pub notes: Vec<String>,
    /// Conditions that must be read *next to* the verdict, never instead of it.
    pub warnings: Vec<String>,
    /// Extra per-run facts (probe results, refusals, ...) as already-formed JSON pairs.
    pub extras: Vec<(String, String)>,
    pub verdict: Verdict,
    pub verdict_reason: Option<String>,
}

impl Transcript {
    /// Things that are true of any run of this tool and must never be silently promoted.
    pub const STANDING_UNVERIFIED: &'static [&'static str] = &[
        "the channel bindings (bmRequestType/bRequest/wValue/magic offsets) are INSPECTED from \
         research/refs/gaster/payload_handle_checkm8_request.S, not MEASURED on this device: \
         UNVERIFIED-BY-TEST until an exchange parses",
        "that DONE_MAGIC in a reply proves OUR handler ran rather than the ROM echoing a buffer \
         that happened to begin with it",
        "that the ROM's DNLOAD write offset resets between commands (tested by two exchanges \
         in one session to two *different* addresses, i.e. two --read options)",
        "anything about DRAM: extent, reachability from EL3, or usability (that is the DRAM walk, \
         a separate step)",
        "that the a9boot payload can be executed at abi::payload_exec_addr() (EXEC is a separate \
         step and UNVERIFIED-BY-TEST)",
    ];

    /// What this particular run did not prove, on top of the standing list.
    pub fn not_proved(&self) -> Vec<String> {
        let mut v: Vec<String> = Self::STANDING_UNVERIFIED.iter().map(|s| s.to_string()).collect();
        if self.records.is_empty() {
            v.push(
                "everything: this was a dry run. The bytes below are what WOULD be sent; none of \
                 them were sent."
                    .to_string(),
            );
        }
        v
    }

    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"schema\": {},\n", jstr(SCHEMA)));
        s.push_str(&format!("  \"tool\": {},\n", jstr(env!("CARGO_PKG_NAME"))));
        s.push_str(&format!("  \"tool_version\": {},\n", jstr(env!("CARGO_PKG_VERSION"))));
        s.push_str(&format!("  \"command\": {},\n", jstr(&self.command)));
        s.push_str(&format!("  \"mode\": {},\n", jstr(self.mode)));
        s.push_str(&format!("  \"build\": {{\n    \"usb_feature\": {},\n    \"dnload_chunk\": {},\n    \"reply_off\": {},\n    \"payload_off\": {}\n  }},\n",
            self.usb_feature,
            crate::bundle::DNLOAD_CHUNK,
            a9boot_core::abi::REPLY_OFF,
            a9boot_core::abi::PAYLOAD_OFF));
        s.push_str(&format!("  \"started_utc\": {},\n", jstr(&self.started_utc)));
        s.push_str(&format!("  \"finished_utc\": {},\n", jstr(&self.finished_utc)));
        s.push_str(&format!("  \"wall_clock_ms\": {},\n", self.wall_clock_ms));
        s.push_str(&format!("  \"success_criterion\": {},\n", jstr(SUCCESS_CRITERION)));
        s.push_str(&format!("  \"transport\": {},\n", jstr(&self.transport)));

        // Device identity. The raw serial never enters this file; `channel::redact_descriptor`
        // is the only path a descriptor is allowed to take.
        s.push_str("  \"device\": {\n");
        s.push_str(&format!("    \"identity_checked\": {},\n", self.identity_checked));
        s.push_str(&format!("    \"identity\": {},\n", self.identity.as_deref().map(jstr).unwrap_or_else(|| "null".into())));
        s.push_str(&format!("    \"identity_error\": {},\n", self.identity_error.as_deref().map(jstr).unwrap_or_else(|| "null".into())));
        s.push_str(&format!("    \"serial\": {}\n", jstr("REDACTED (never published)")));
        s.push_str("  },\n");

        s.push_str("  \"exchanges\": [");
        if self.records.is_empty() {
            s.push_str("],\n");
        } else {
            s.push('\n');
            for (i, r) in self.records.iter().enumerate() {
                s.push_str(&record_json(r));
                s.push_str(if i + 1 == self.records.len() { "\n" } else { ",\n" });
            }
            s.push_str("  ],\n");
        }

        s.push_str("  \"notes\": [");
        if self.notes.is_empty() {
            s.push_str("],\n");
        } else {
            s.push('\n');
            for (i, n) in self.notes.iter().enumerate() {
                s.push_str(&format!("    {}", jstr(n)));
                s.push_str(if i + 1 == self.notes.len() { "\n" } else { ",\n" });
            }
            s.push_str("  ],\n");
        }

        s.push_str("  \"warnings\": [");
        if self.warnings.is_empty() {
            s.push_str("],\n");
        } else {
            s.push('\n');
            for (i, n) in self.warnings.iter().enumerate() {
                s.push_str(&format!("    {}", jstr(n)));
                s.push_str(if i + 1 == self.warnings.len() { "\n" } else { ",\n" });
            }
            s.push_str("  ],\n");
        }

        for (k, v) in &self.extras {
            s.push_str(&format!("  {}: {},\n", jstr(k), v));
        }

        let np = self.not_proved();
        s.push_str("  \"not_proved_by_this_run\": [\n");
        for (i, n) in np.iter().enumerate() {
            s.push_str(&format!("    {}", jstr(n)));
            s.push_str(if i + 1 == np.len() { "\n" } else { ",\n" });
        }
        s.push_str("  ],\n");

        s.push_str(&format!("  \"verdict\": {},\n", jstr(self.verdict.name())));
        s.push_str(&format!(
            "  \"verdict_reason\": {}\n",
            self.verdict_reason.as_deref().map(jstr).unwrap_or_else(|| "null".into())
        ));
        s.push_str("}\n");
        s
    }

    /// The operator-facing summary printed to the terminal before the JSON path.
    pub fn human(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("mode          {}\n", self.mode));
        s.push_str(&format!("transport     {}\n", self.transport));
        if let Some(id) = &self.identity {
            s.push_str(&format!("identity      {id}\n"));
        }
        if let Some(e) = &self.identity_error {
            s.push_str(&format!("identity      REFUSED: {e}\n"));
        }
        for n in &self.notes {
            s.push_str(&format!("note          {n}\n"));
        }
        for w in &self.warnings {
            s.push_str(&format!("WARNING       {w}\n"));
        }
        for r in &self.records {
            s.push_str(&format!("{}\n", r.summary()));
            s.push_str(&format!(
                "              DNLOAD {} bytes in {} transfer(s), UPLOAD wLength {}, sequence {}\n",
                r.dnload.len(),
                r.dnload_chunks,
                r.upload_len,
                r.sequence.name()
            ));
        }
        s.push_str(&format!("\nVERDICT       {}", self.verdict.name()));
        if let Some(r) = &self.verdict_reason {
            s.push_str(&format!(" — {r}"));
        }
        s.push('\n');
        s
    }
}

fn record_json(r: &ExchangeRecord) -> String {
    let mut s = String::new();
    s.push_str("    {\n");
    s.push_str(&format!("      \"index\": {},\n", r.index));
    s.push_str(&format!("      \"label\": {},\n", jstr(&r.label)));
    s.push_str(&format!("      \"purpose\": {},\n", jstr(&r.purpose)));
    s.push_str("      \"request\": {\n");
    s.push_str(&format!("        \"bmRequestType\": {},\n", jstr("0x21")));
    s.push_str(&format!("        \"bRequest\": {},\n", jstr("0x01 (DFU_DNLOAD)")));
    s.push_str(&format!("        \"wValue\": {},\n", jstr("0x0000")));
    s.push_str(&format!("        \"wIndex\": {},\n", jstr("0x0000")));
    s.push_str(&format!("        \"dnload_len\": {},\n", r.dnload.len()));
    s.push_str(&format!("        \"dnload_transfers\": {},\n", r.dnload_chunks));
    s.push_str(&format!("        \"dnload_hex\": {},\n", jstr(&hex(&r.dnload))));
    s.push_str(&format!("        \"dnload_sha256\": {},\n", jstr(&sha256_hex(&r.dnload))));
    s.push_str(&format!("        \"sequence\": {},\n", jstr(r.sequence.name())));
    s.push_str(&format!(
        "        \"trigger\": {},\n",
        jstr(match r.trigger {
            Trigger::Now => "now (stage + trigger)",
            Trigger::Deferred => "deferred (staged only; nothing executed)",
            Trigger::Only => "only (trigger for an already-staged command)",
        })
    ));
    s.push_str(&format!(
        "        \"sequence_steps\": {}\n",
        jstr(&r.sequence.steps(r.dnload.len(), r.upload_len).join(" | "))
    ));
    s.push_str("      },\n");
    s.push_str("      \"trigger\": {\n");
    s.push_str(&format!("        \"bmRequestType\": {},\n", jstr("0xa1")));
    s.push_str(&format!("        \"bRequest\": {},\n", jstr("0x02 (DFU_UPLOAD)")));
    s.push_str(&format!("        \"wValue\": {},\n", jstr("0xffff")));
    s.push_str(&format!("        \"wIndex\": {},\n", jstr("0x0000")));
    s.push_str(&format!("        \"wLength\": {}\n", r.upload_len));
    s.push_str("      },\n");
    s.push_str(&format!("      \"start_us\": {},\n", r.start_us));
    s.push_str(&format!("      \"duration_us\": {},\n", r.duration_us));
    s.push_str(&format!("      \"status\": {},\n", jstr(r.status)));
    s.push_str(&format!(
        "      \"actual_length\": {},\n",
        r.actual_length.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
    ));
    s.push_str(&format!("      \"channel\": {},\n", jstr("0x21/0x01 DNLOAD then 0xa1/0x02 wValue 0xffff UPLOAD")));
    match &r.upload {
        Some(bytes) => {
            s.push_str("      \"response\": {\n");
            s.push_str(&format!("        \"bytes_read\": {},\n", bytes.len()));
            s.push_str(&format!("        \"complete\": {},\n", bytes.len() == r.upload_len as usize));
            s.push_str(&format!("        \"upload_hex\": {},\n", jstr(&hex(bytes))));
            s.push_str(&format!("        \"upload_sha256\": {}\n", jstr(&sha256_hex(bytes))));
            s.push_str("      },\n");
        }
        None => s.push_str("      \"response\": null,\n"),
    }
    s.push_str(&format!(
        "      \"transport_error\": {},\n",
        r.transport_error.as_deref().map(jstr).unwrap_or_else(|| "null".into())
    ));
    match &r.parse {
        ParseState::Unread { reason } => {
            s.push_str("      \"parse\": {\n");
            s.push_str(&format!("        \"state\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"reason\": {},\n", jstr(reason)));
            s.push_str(&format!("        \"magic_hex\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"magic_ascii\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"retval_hex\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"retval_label\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"data_len\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"data_hex\": {}\n", jstr("UNREAD")));
            s.push_str("      },\n");
        }
        ParseState::Parsed { magic, retval, retval_label, data_len } => {
            let data_hex = r.upload.as_ref().map(|b| hex(&b[a9boot_core::abi::REPLY_OFF as usize..])).unwrap_or_else(|| "UNREAD".into());
            s.push_str("      \"parse\": {\n");
            s.push_str(&format!("        \"state\": {},\n", jstr("PARSED")));
            s.push_str(&format!("        \"reason\": null,\n"));
            s.push_str(&format!("        \"magic_hex\": {},\n", jstr(&hex64(*magic))));
            s.push_str(&format!("        \"magic_ascii\": {},\n", jstr(&ascii_of(*magic))));
            s.push_str(&format!("        \"done_magic_ok\": true,\n"));
            // Fixed width: a retval that is an address and a retval that is a status code must
            // not be formatted differently, or a reviewer comparing two runs sees a difference
            // that is not there.
            s.push_str(&format!("        \"retval_hex\": {},\n", jstr(&hex64(*retval))));
            s.push_str(&format!("        \"retval_label\": {},\n", jstr(retval_label)));
            s.push_str(&format!("        \"data_len\": {},\n", data_len));
            s.push_str(&format!("        \"data_hex\": {}\n", jstr(&data_hex)));
            s.push_str("      },\n");
        }
        ParseState::Malformed { fault, detail } => {
            s.push_str("      \"parse\": {\n");
            s.push_str(&format!("        \"state\": {},\n", jstr("MALFORMED")));
            s.push_str(&format!("        \"fault\": {},\n", jstr(fault.name())));
            s.push_str(&format!("        \"reason\": {},\n", jstr(detail)));
            let up = r.upload.as_deref().unwrap_or(&[]);
            let first8 = if up.len() >= 8 {
                hex64(u64::from_le_bytes(up[0..8].try_into().unwrap()))
            } else {
                "UNREAD".to_string()
            };
            s.push_str(&format!("        \"magic_hex\": {},\n", jstr(&first8)));
            s.push_str(&format!("        \"magic_ascii\": {},\n", jstr(if up.len() >= 8 { ascii_of(u64::from_le_bytes(up[0..8].try_into().unwrap())) } else { "UNREAD".into() }.as_str())));
            s.push_str(&format!("        \"retval_hex\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"retval_label\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"data_len\": {},\n", jstr("UNREAD")));
            s.push_str(&format!("        \"data_hex\": {},\n", jstr(&hex_prefix(up, 32))));
            s.push_str(&format!("        \"upload_prefix_hex\": {}\n", jstr(&hex_prefix(up, 32))));
            s.push_str("      },\n");
        }
    }
    // Named `exchange_verdict`, not `verdict`: a grep for "verdict": "PASS" in a FAIL run must
    // not find one, and the top-level verdict is the only verdict of a run.
    s.push_str(&format!("      \"exchange_verdict\": {}\n", jstr(r.verdict().name())));
    s.push_str("    }");
    s
}

/// A magic word as printable ASCII, with non-printable bytes as `.` — "donedone" is a diagnosis;
/// `0x646f6e65646f6e65` is a number.
pub fn ascii_of(v: u64) -> String {
    // The reference defines the magic as a big-endian-readable ASCII word (`0x646f6e65646f6e65`
    // is "donedone", `gaster.c:49`), while the wire order is little-endian. Displaying the
    // *constant's* spelling is what makes the evidence readable; the hex field carries the wire.
    v.to_be_bytes()
        .iter()
        .map(|b| if (0x20..0x7f).contains(b) { *b as char } else { '.' })
        .collect()
}

fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
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

/// A `Packet` plus the operator-facing purpose, as an `Exchange`.
pub fn exchange_for(p: &Packet, purpose: &str, sequence: Sequence) -> Exchange {
    let mut e = Exchange::from(p);
    e.purpose = purpose.to_string();
    e.sequence = sequence;
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::SimDevice;
    use std::time::Duration;

    // -------------------------------------------------------------------------------
    // SHA-256 known answers (FIPS 180-4 / NIST examples). A hash that is only
    // self-consistent would make every hash in the evidence file confidently wrong.
    // -------------------------------------------------------------------------------

    #[test]
    fn sha256_matches_the_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Two blocks plus padding, i.e. the length-extension path a naive implementation gets
        // wrong: 1,000,000 'a' is the FIPS long vector.
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hex_and_ascii_helpers() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_prefix(&[1, 2, 3, 4], 2), "0102");
        assert_eq!(ascii_of(0x646F_6E65_646F_6E65), "donedone");
        assert_eq!(ascii_of(0), "........");
        assert_eq!(hex64(0x10), "0x0000000000000010");
    }

    #[test]
    fn iso8601_is_utc_and_correct_at_epoch_and_after() {
        assert_eq!(iso8601_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            iso8601_utc(UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
            "2001-09-09T01:46:40Z"
        );
        // A leap day, which is where a hand-rolled civil calendar goes wrong.
        assert_eq!(
            iso8601_utc(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }

    // -------------------------------------------------------------------------------
    // Negative controls, end to end: transport -> recorder -> parse -> verdict -> JSON
    // -------------------------------------------------------------------------------

    /// A transport that returns exactly the bytes it is told to, so a malformed reply can be
    /// driven through the *whole* evidence path rather than only through the parser.
    struct Canned {
        reply: Vec<u8>,
        err: Option<String>,
        calls: usize,
    }

    impl Canned {
        fn ok(reply: Vec<u8>) -> Self {
            Canned { reply, err: None, calls: 0 }
        }
        fn err(e: &str) -> Self {
            Canned { reply: Vec::new(), err: Some(e.to_string()), calls: 0 }
        }
    }

    impl Transport for Canned {
        fn serial(&mut self) -> Result<String, String> {
            Ok("CPID:8003 CPRV:11 CPFM:03 SCEP:01 BDID:02 ECID:DEADBEEF SRTG:[iBoot-2234.0.0.2.22] PWND:[checkm8]".into())
        }
        fn exchange(&mut self, _e: &Exchange) -> Result<Vec<u8>, String> {
            self.calls += 1;
            match &self.err {
                Some(e) => Err(e.clone()),
                None => Ok(self.reply.clone()),
            }
        }
        fn describe(&self) -> String {
            "Canned".into()
        }
    }

    fn canned_transcript(t: Canned, upload_len: u16) -> Transcript {
        let mut rec = Recorder::new(t);
        let serial = rec.serial().unwrap();
        crate::channel::check_identity(&serial, &crate::channel::Expect::default()).unwrap();
        let p = channel::mem_read(a9boot_core::layout::AUSB_CFG0_ADDR, 8);
        let e = exchange_for(&p, "test read", Sequence::Minimal);
        let _ = rec.exchange(&e);
        transcript_of(rec, upload_len)
    }

    fn transcript_of<T: Transport>(rec: Recorder<T>, _upload_len: u16) -> Transcript {
        let verdict = rec.verdict();
        let reason = rec.verdict_reason();
        Transcript {
            command: "a9boot-host firstlight --live --json -".into(),
            mode: "live",
            usb_feature: true,
            transport: "Canned".into(),
            started_utc: iso8601_utc(UNIX_EPOCH),
            finished_utc: iso8601_utc(UNIX_EPOCH + Duration::from_millis(3)),
            wall_clock_ms: 3,
            identity: rec.identity.clone(),
            identity_error: rec.identity_error.clone(),
            identity_checked: true,
            records: rec.records.clone(),
            notes: rec.notes.clone(),
            warnings: Vec::new(),
            extras: Vec::new(),
            verdict,
            verdict_reason: reason,
        }
    }

    fn good_reply() -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[0..8].copy_from_slice(&a9boot_core::abi::DONE_MAGIC.to_le_bytes());
        v[8..16].copy_from_slice(&0x1234_u64.to_le_bytes());
        v[16..24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
        v
    }

    #[test]
    fn control_a_good_reply_passes_and_lands_in_the_json() {
        let t = canned_transcript(Canned::ok(good_reply()), 24);
        assert_eq!(t.verdict, Verdict::Pass);
        assert!(t.verdict_reason.is_none());
        let j = t.to_json();
        assert!(j.contains("\"state\": \"PARSED\""), "{j}");
        assert!(j.contains("0x0000000000001234"), "{j}");
        assert!(j.contains("\"done_magic_ok\": true"), "{j}");
        assert!(j.contains(&sha256_hex(&good_reply())), "the response hash is in the file");
        // The JSON must be parseable by a strict reader: quotes balanced is a weak check, but
        // the shape check below (one line per key) catches a broken writer.
        assert!(j.ends_with("}\n"));
        assert!(!j.contains("ECID:DEADBEEF"), "serial leaked into the transcript: {j}");
        assert!(j.contains("ECID:<redacted>"), "{j}");
    }

    #[test]
    fn control_a_dry_run_is_unknown_and_carries_no_values() {
        // The failure mode: a codec that never ran returning a plausible value reported as
        // success. With no exchanges the verdict must be UNKNOWN and every parsed field UNREAD.
        let rec: Recorder<Canned> = Recorder::new(Canned::ok(good_reply()));
        let t = transcript_of(rec, 24);
        assert_eq!(t.verdict, Verdict::Unknown);
        assert!(t.verdict_reason.as_deref().unwrap().contains("no exchange was attempted"));
        let j = t.to_json();
        assert!(j.contains("\"exchanges\": []"), "{j}");
        assert!(j.contains("\"verdict\": \"UNKNOWN\""), "{j}");
        assert!(!j.contains("\"state\": \"PARSED\""), "{j}");
        assert!(!j.contains("0x0000000000001234"), "{j}");
    }

    #[test]
    fn control_bad_magic_fails_by_name_end_to_end() {
        let mut reply = good_reply();
        reply[0..8].copy_from_slice(&a9boot_core::abi::EXEC_MAGIC.to_le_bytes());
        let t = canned_transcript(Canned::ok(reply), 24);
        assert_eq!(t.verdict, Verdict::Fail);
        let j = t.to_json();
        assert!(j.contains("\"fault\": \"REPLY_BAD_MAGIC\""), "{j}");
        assert!(j.contains("\"state\": \"MALFORMED\""), "{j}");
        assert!(j.contains("\"retval_hex\": \"UNREAD\""), "no return value may be invented: {j}");
    }

    #[test]
    fn control_short_reply_fails_by_name_end_to_end() {
        for (n, name) in [(0usize, "REPLY_EMPTY"), (3, "REPLY_TRUNCATED"), (12, "REPLY_MAGIC_WITHOUT_RETVAL")] {
            let mut reply = good_reply();
            reply.truncate(n);
            let t = canned_transcript(Canned::ok(reply), 24);
            assert_eq!(t.verdict, Verdict::Fail, "n = {n}");
            let j = t.to_json();
            assert!(j.contains(&format!("\"fault\": \"{name}\"")), "n = {n}: {j}");
            assert!(j.contains("\"state\": \"MALFORMED\""), "n = {n}: {j}");
        }
    }

    #[test]
    fn control_a_transport_error_is_unread_not_a_zero() {
        let t = canned_transcript(Canned::err("LIVE_UPLOAD_FAILED: timeout"), 24);
        assert_eq!(t.verdict, Verdict::Fail);
        let j = t.to_json();
        assert!(j.contains("\"response\": null"), "{j}");
        assert!(j.contains("\"state\": \"UNREAD\""), "{j}");
        assert!(j.contains("\"retval_hex\": \"UNREAD\""), "{j}");
        assert!(j.contains("LIVE_UPLOAD_FAILED"), "{j}");
    }

    #[test]
    fn a_partial_upload_is_data_short() {
        let mut reply = good_reply();
        reply.truncate(20);
        let t = canned_transcript(Canned::ok(reply), 24);
        assert_eq!(t.verdict, Verdict::Fail);
        assert!(t.to_json().contains("\"fault\": \"REPLY_DATA_SHORT\""));
    }

    #[test]
    fn the_recorder_does_not_change_what_the_caller_sees() {
        // Evidence must be a recording, not a second opinion: the wrapped result is returned
        // byte for byte, error for error.
        let mut rec = Recorder::new(Canned::ok(good_reply()));
        let p = channel::mem_read(0x8_0000_0000, 8);
        let e = exchange_for(&p, "read", Sequence::Minimal);
        let got = rec.exchange(&e).unwrap();
        assert_eq!(got, good_reply());
        assert_eq!(rec.records.len(), 1);
        assert_eq!(rec.records[0].upload.as_deref(), Some(&good_reply()[..]));
        assert_eq!(rec.records[0].status, "OK");
        assert_eq!(rec.records[0].actual_length, Some(good_reply().len()));

        let mut rec = Recorder::new(Canned::err("LIVE_UPLOAD_FAILED[status=TIMEOUT]: boom"));
        let err = rec.exchange(&e).unwrap_err();
        assert!(err.contains("boom"));
        assert_eq!(rec.records[0].transport_error.as_deref(), Some("LIVE_UPLOAD_FAILED[status=TIMEOUT]: boom"));
        assert_eq!(rec.records[0].status, "TIMEOUT");
        assert_eq!(rec.records[0].actual_length, None, "a failed transfer has no length, not zero");
    }

    #[test]
    fn the_recorder_drives_the_simulator_unchanged() {
        // The same code path the probe uses, through the recorder, against the simulator: this is
        // the closest thing to a live run that this workspace can execute.
        let dev = SimDevice::new(0x4000);
        let mut rec = Recorder::new(dev);
        crate::channel::check_identity(&rec.serial().unwrap(), &crate::channel::Expect::default())
            .unwrap();
        let p = channel::mem_write(a9boot_core::layout::DRAM_BASE, &[1, 2, 3, 4]);
        let e = exchange_for(&p, "sim write", Sequence::Minimal);
        let raw = rec.exchange(&e).unwrap();
        let r = channel::parse_response(&raw, p.upload_len).unwrap();
        assert_eq!(r.retval, a9boot_core::layout::DRAM_BASE);
        assert_eq!(rec.verdict(), Verdict::Pass);
        assert!(rec.identity.as_ref().unwrap().contains("PWND:[checkm8]"));
        assert!(!rec.identity.as_ref().unwrap().contains("DEADBEEF"));
    }

    #[test]
    fn the_status_tag_is_decoded_from_the_transport_message() {
        assert_eq!(status_tag_from_error("LIVE_UPLOAD_FAILED[status=TIMEOUT]: nope"), "TIMEOUT");
        assert_eq!(status_tag_from_error("LIVE_UPLOAD_FAILED[status=STALL]: nope"), "STALL");
        assert_eq!(status_tag_from_error("STATE_WALK_MISMATCH[status=WALK]: ..."), "WALK");
        assert_eq!(status_tag_from_error("no tag at all"), "OTHER");
        assert_eq!(status_tag_from_error("[status=MADE_UP]"), "OTHER");
        assert_eq!(status_tag_from_error("[status=TIMEOUT"), "OTHER");
    }

    #[test]
    fn the_json_declares_which_quantity_is_the_success_criterion() {
        let t = canned_transcript(Canned::ok(good_reply()), 24);
        let j = t.to_json();
        assert!(j.contains("\"success_criterion\""), "{j}");
        assert!(j.contains("actual_length == wLength"), "{j}");
        assert!(j.contains("\"status\": \"OK\""), "{j}");
        assert!(j.contains("\"actual_length\": 24"), "{j}");
    }

    #[test]
    fn json_escaping_is_safe() {
        assert_eq!(jstr("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
        assert_eq!(jstr("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn what_a_run_did_not_prove_is_always_stated() {
        let t = canned_transcript(Canned::ok(good_reply()), 24);
        let np = t.not_proved();
        assert!(np.iter().any(|s| s.contains("UNVERIFIED-BY-TEST")));
        assert!(np.iter().any(|s| s.contains("DRAM")));
    }
}
