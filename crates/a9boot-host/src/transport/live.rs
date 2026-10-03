//! The live transport: `rusb` on a pwned DFU device, behind the non-default `usb` feature.
//!
//! # UNVERIFIED-BY-TEST
//!
//! **No test in this workspace can exercise a single line of this file.** Every path here is
//! UNVERIFIED-BY-TEST, and it stays that way until the Lead runs it against a pwned device. What
//! *is* verified is everything around it: the packet bytes it sends (`channel`, tested), the step
//! sequence it drives (`bundle::run_probe`/`execute_steps`, tested against the simulator), and the
//! refusal the default build produces instead of this file (`transport::open_live`, asserted by
//! `selftest`). This module is the last mile, and it is labelled as such.
//!
//! # Scope, deliberately small
//!
//! Two control transfers and nothing else:
//!
//! * `DNLOAD` — `bmRequestType 0x21`, `bRequest 0x01`, `wValue 0`, `wIndex 0`, in `DNLOAD_CHUNK`
//!   transfers, because a command larger than EP0 becomes consecutive transfers that the ROM
//!   accumulates into its buffer (DESIGN.md §3.3).
//! * `UPLOAD` — `bmRequestType 0xA1`, `bRequest 0x02`, `wValue 0xFFFF`: the trigger the resident
//!   checkm8 handler dispatches on (`payload_handle_checkm8_request.S`).
//!
//! There is no reset, no driver binding, no `a9pwn` invocation, no retry loop and no descriptor
//! parsing beyond the serial string. Device access is Lead-only (HANDOFF §9.1); nothing in this
//! crate calls into this module on its own — `a9boot-host probe --live` is the only entry point,
//! and it is compiled out entirely unless `--features usb` is given.
//!
//! # Failure modes are four messages, not one
//!
//! This project's rule (§9.6): four different problems get four different messages. Here they are
//! — device not found, handle/interface not obtained, short or failed `DNLOAD`, short or failed
//! `UPLOAD` — plus the two the channel already distinguishes for us: an unexpected `DONE_MAGIC`
//! and a short reply are both named by `channel::parse_response`, in one place rather than two.

use super::{DfuStatus, Exchange, Sequence, Transport, Trigger};
use crate::bundle::DNLOAD_CHUNK;
use rusb::{Context, DeviceHandle, UsbContext};
use std::time::Duration;

/// Apple's vendor ID and the SecureROM DFU product ID. After pwn the device re-enumerates with the
/// same pair and a serial containing `PWND:[checkm8]`.
const APPLE_VID: u16 = 0x05AC;
const DFU_PID: u16 = 0x1227;

/// Per-transfer timeout. Deliberately generous: this is the *probe*, where a slow reply is
/// interesting information, not the exploit, where a microsecond budget is the whole game.
const TIMEOUT: Duration = Duration::from_millis(1000);

/// `DFU_DNLOAD` with a host-to-device class request to the interface.
const DNLOAD: u8 = 0x01;
const DNLOAD_TYPE: u8 = 0x21;
/// `DFU_UPLOAD`, device-to-host. `wValue = 0xFFFF` is the checkm8 handler's trigger.
const UPLOAD: u8 = 0x02;
const UPLOAD_TYPE: u8 = 0xA1;
const UPLOAD_VALUE: u16 = 0xFFFF;
/// `DFU_FILE_SUFFIX_LEN` = 16 (`gaster.c:41`): the reference sends exactly this many zero bytes
/// after a command's data and before the end-of-download `DNLOAD` (`gaster.c:987`).
const DFU_FILE_SUFFIX_LEN: usize = 16;

/// `DFU_GET_STATUS` (`gaster.c:35`): read-only, six bytes, and not a trigger.
const GET_STATUS: u8 = 0x03;
const GET_STATUS_TYPE: u8 = 0xA1;

/// The transfer status, as a stable token, for the evidence file's `status` field.
///
/// This is **diagnostic**: a completed transfer with the wrong bytes is still a failure, and the
/// success criterion is `actual_length == wLength` **and** a reply that begins with
/// `[DONE_MAGIC][retval]` (see `evidence::SUCCESS_CRITERION`). `Timeout` is the one to read
/// carefully: on this bootrom a cancelled/timeout control transfer can wedge EP0
/// (`RUNG1-EVIDENCE.md` §3), so a timeout is a **stop**, not a retry.
fn status_of(e: &rusb::Error) -> &'static str {
    match e {
        rusb::Error::Timeout => "TIMEOUT",
        rusb::Error::Pipe => "STALL",
        rusb::Error::NoDevice => "NO_DEVICE",
        rusb::Error::Access => "ACCESS",
        rusb::Error::Busy => "BUSY",
        rusb::Error::NotFound => "NOT_FOUND",
        rusb::Error::Interrupted => "CANCELLED",
        rusb::Error::Io => "IO",
        rusb::Error::NotSupported => "NOT_SUPPORTED",
        rusb::Error::BadDescriptor => "BAD_DESCRIPTOR",
        rusb::Error::Overflow => "OVERFLOW",
        rusb::Error::NoMem => "NO_MEM",
        rusb::Error::InvalidParam => "INVALID_PARAM",
        _ => "OTHER",
    }
}

pub struct LiveTransport {
    handle: DeviceHandle<Context>,
    serial: String,
    /// The per-attempt timeout. `bounded::ladder` raises it step by step, so a device that is
    /// merely slow is given a longer chance before a hang is declared — and a device that never
    /// answers is declared, by name, instead of wedging a session with an unbounded wait.
    timeout_ms: u64,
}

impl LiveTransport {
    /// Open the pwned DFU device. **UNVERIFIED-BY-TEST.**
    ///
    /// Four distinct failures, because they have four distinct fixes: not plugged in or not in
    /// DFU; present but unopenable (a driver other than libusbK/WinUSB is bound — see HANDOFF §3);
    /// openable but interface 0 unclaimable (something else holds it); no serial descriptor (the
    /// device is not pwned, so there is no command channel).
    pub fn open() -> Result<LiveTransport, String> {
        let ctx = Context::new()
            .map_err(|e| format!("LIVE_NO_USB_CONTEXT[status={}]: {e}", status_of(&e)))?;
        let listed = ctx
            .devices()
            .map_err(|e| format!("LIVE_ENUM_FAILED[status={}]: {e}", status_of(&e)))?;
        let mut found = None;
        for d in listed.iter() {
            let desc = match d.device_descriptor() {
                Ok(x) => x,
                Err(_) => continue,
            };
            if desc.vendor_id() == APPLE_VID && desc.product_id() == DFU_PID {
                // `serial_number_string_index()` is the accessor in rusb 0.9.4 — checked in the
                // crate's own source (`device_descriptor.rs:50`) rather than guessed.
                found = Some((d, desc.serial_number_string_index()));
            }
        }
        let (dev, serial_idx) = found.ok_or_else(|| {
            format!("LIVE_NO_DEVICE[status=NOT_FOUND]: no {APPLE_VID:04x}:{DFU_PID:04x} on the bus. \
                     Plug the phone in and put it in DFU mode.")
        })?;
        // No `mut`: every rusb handle method this module uses takes `&self` (checked in
        // `device_handle.rs`).
        let handle = dev
            .open()
            .map_err(|e| {
                format!(
                    "LIVE_OPEN_FAILED[status={}]: {e}. Permissions, or another process holds the \
                     device.",
                    status_of(&e)
                )
            })?;
        handle
            .claim_interface(0)
            .map_err(|e| {
                format!(
                    "LIVE_CLAIM_FAILED[status={}]: {e}. Another process may hold interface 0 — on a \
                     DFU device a second holder loses the session.",
                    status_of(&e)
                )
            })?;
        let idx = serial_idx.ok_or_else(|| {
            "LIVE_NO_SERIAL_INDEX[status=OTHER]: the device descriptor declares no serial string \
             index, so there is no PWND state to check and no command channel. (Note: the declared \
             index MOVES between re-enumerations on this device — never hardcode one; it is 4 or 6 \
             depending on the session.)"
                .to_string()
        })?;
        let serial = handle
            .read_string_descriptor_ascii(idx)
            .map_err(|e| {
                format!(
                    "LIVE_NO_SERIAL[status={}]: {e}. Without a serial descriptor there is no PWND \
                     state to check, so there is no command channel.",
                    status_of(&e)
                )
            })?;
        Ok(LiveTransport { handle, serial, timeout_ms: TIMEOUT.as_millis() as u64 })
    }
}

impl Transport for LiveTransport {
    fn set_timeout_ms(&mut self, ms: u64) {
        self.timeout_ms = ms.max(1);
    }

    fn serial(&mut self) -> Result<String, String> {
        Ok(self.serial.clone())
    }

    /// `DFU_GET_STATUS`. Read-only, six bytes, and it cannot dispatch `EXEC`/`MEMC`: the resident
    /// handler matches the halfword `bmRequestType | bRequest << 8` against `0x2A1` and forwards
    /// `0x3A1` to the ROM. **UNVERIFIED-BY-TEST**, like everything in this file.
    fn dfu_status(&mut self) -> Result<DfuStatus, String> {
        let mut buf = [0u8; 6];
        let n = self
            .handle
            .read_control(GET_STATUS_TYPE, GET_STATUS, 0, 0, &mut buf, Duration::from_millis(self.timeout_ms))
            .map_err(|e| format!("LIVE_GET_STATUS_FAILED[status={}]: {e}", status_of(&e)))?;
        if n != buf.len() {
            return Err(format!(
                "LIVE_GET_STATUS_SHORT[status=OK]: read {n} of {} bytes; a partial status record is \
                 not a state and must not be decoded as one.",
                buf.len()
            ));
        }
        DfuStatus::parse(&buf)
    }

    fn exchange(&mut self, e: &Exchange) -> Result<Vec<u8>, String> {
        self.exchange_with(e, Trigger::Now)
    }

    /// `Deferred` sends the command and its framing and **stops** — no `UPLOAD`, so nothing
    /// executes and the buffer holds the staged command. `Only` sends just the `UPLOAD`, for a
    /// command staged by an earlier `Deferred` call. This is what makes it possible to verify an
    /// `EXEC` payload in the buffer before allowing it to run.
    fn exchange_with(&mut self, e: &Exchange, trigger: Trigger) -> Result<Vec<u8>, String> {
        // 1. DNLOAD, chunked. A short write is not a slow write: the ROM's buffer would then hold
        //    a half command, and the trigger would execute whatever the header happened to say.
        let mut sent = 0usize;
        while sent < e.dnload.len() {
            let end = (sent + DNLOAD_CHUNK).min(e.dnload.len());
            let n = self
                .handle
                .write_control(DNLOAD_TYPE, DNLOAD, 0, 0, &e.dnload[sent..end], Duration::from_millis(self.timeout_ms))
                .map_err(|err| {
                    format!(
                        "LIVE_DNLOAD_FAILED[status={}] at +{sent:#x} of {}: {err}",
                        status_of(&err),
                        e.dnload.len()
                    )
                })?;
            if n != end - sent {
                return Err(format!(
                    "LIVE_DNLOAD_SHORT[status=OK] at +{sent:#x}: wrote {n} of {} bytes. The buffer \
                     now holds a partial command; nothing further is sent.",
                    end - sent
                ));
            }
            sent = end;
        }

        // 1b. The reference's framing (`dfu_send_data` → `dfu_set_state_wait_reset`,
        //     `gaster.c:977-988` and `:829-834`). The order is the reference's and our own
        //     exploit's (`a9pwn/src/stages.rs`), and it is the *only* difference between the two
        //     shapes that have already been run on hardware and got no reply:
        //
        //       command DNLOAD  ->  16 zero bytes  ->  zero-length DNLOAD  ->  6, 7, 8  ->  UPLOAD
        //
        //     `Minimal` (DESIGN.md §2.3) sends only the first and last of those.
        if e.sequence == Sequence::Reference {
            let suffix = [0u8; DFU_FILE_SUFFIX_LEN];
            let n = self
                .handle
                .write_control(DNLOAD_TYPE, DNLOAD, 0, 0, &suffix, Duration::from_millis(self.timeout_ms))
                .map_err(|err| {
                    format!(
                        "LIVE_SUFFIX_FAILED[status={}]: the {DFU_FILE_SUFFIX_LEN}-byte zero suffix \
                         (gaster.c:41,987) did not go out: {err}",
                        status_of(&err)
                    )
                })?;
            if n != DFU_FILE_SUFFIX_LEN {
                return Err(format!(
                    "LIVE_SUFFIX_SHORT[status=OK]: wrote {n} of {DFU_FILE_SUFFIX_LEN} suffix bytes. \
                     The reference sends exactly DFU_FILE_SUFFIX_LEN zero bytes here (gaster.c:987) \
                     and the state walk that follows is only meaningful after a whole download; \
                     nothing further is sent."
                ));
            }
        }
        if matches!(e.sequence, Sequence::Terminated | Sequence::Reference) {
            let n = self
                .handle
                .write_control(DNLOAD_TYPE, DNLOAD, 0, 0, &[], Duration::from_millis(self.timeout_ms))
                .map_err(|err| {
                    format!(
                        "LIVE_TERMINATOR_FAILED[status={}] ({}): {err}",
                        status_of(&err),
                        e.sequence.name()
                    )
                })?;
            if n != 0 {
                return Err(format!(
                    "LIVE_TERMINATOR_SHORT[status=OK] ({}): the zero-length DNLOAD reported {n} \
                     bytes written, which is not a thing the wire can do; treating the session as \
                     inconsistent and sending nothing further.",
                    e.sequence.name()
                ));
            }
        }

        // 1c. The MANIFEST walk, before the trigger. Same function the simulator and the tests
        //     use, so the ordering and the "expected vs saw" reporting cannot drift.
        if e.sequence == Sequence::Reference {
            let mut read = 0usize;
            crate::transport::check_manifest_walk(|| {
                read += 1;
                self.dfu_status().map_err(|err| {
                    format!(
                        "the MANIFEST walk stopped on read {read} of 3 (expected state {} {}): {err}",
                        crate::transport::MANIFEST_WALK[read - 1],
                        crate::transport::state_name(crate::transport::MANIFEST_WALK[read - 1])
                    )
                })
            })?;
        }

        if trigger == Trigger::Deferred {
            // Staged, deliberately not executed. Returning empty bytes is the honest answer:
            // there is no reply because no command ran.
            return Ok(Vec::new());
        }

        // 2. UPLOAD: the trigger and the reply in one transfer.
        let mut buf = vec![0u8; e.upload_len as usize];
        let n = self
            .handle
            .read_control(UPLOAD_TYPE, UPLOAD, UPLOAD_VALUE, 0, &mut buf, Duration::from_millis(self.timeout_ms))
            .map_err(|err| {
                format!(
                    "LIVE_UPLOAD_FAILED[status={}] ({}): {err}. A timeout means the handler did not \
                     answer. STOP rather than retry: a cancelled control transfer can wedge EP0 on \
                     this bootrom (RUNG1-EVIDENCE.md §3), and a retry sends a second DNLOAD on top \
                     of a buffer whose state is now unknown. Check the serial still contains \
                     PWND:[checkm8] before deciding anything.",
                    status_of(&err),
                    e.label
                )
            })?;
        if n != buf.len() {
            // A short reply is *evidence*, and the parser can name it: returning the bytes we did
            // receive makes `REPLY_TRUNCATED` / `REPLY_MAGIC_WITHOUT_RETVAL` / `REPLY_DATA_SHORT`
            // reachable on the live path, and puts the partial bytes in the evidence file instead
            // of throwing them away. The length criterion is still failed: actual_length (n) !=
            // wLength (buf.len()), which is half of the success criterion.
            buf.truncate(n);
            return Ok(buf);
        }
        Ok(buf)
    }

    /// Redacted on purpose: the serial descriptor carries `ECID`, and this string goes to the
    /// terminal and into the evidence file. `channel::redact_descriptor` is the only path.
    fn describe(&self) -> String {
        format!(
            "LiveTransport: {APPLE_VID:04x}:{DFU_PID:04x}, {} byte DNLOAD chunks, {} ms timeout, \
             descriptor [{}]. UNVERIFIED-BY-TEST.",
            DNLOAD_CHUNK,
            TIMEOUT.as_millis(),
            crate::channel::redact_descriptor(&self.serial)
        )
    }
}
