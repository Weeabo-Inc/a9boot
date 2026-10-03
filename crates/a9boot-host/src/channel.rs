//! The post-pwn channel, host side: byte-exact command construction and reply parsing.
//!
//! Everything here is a pure function from bytes to bytes. It never touches a device; the
//! transport does that, and the default transport cannot (see `transport.rs`).
//!
//! The geometry it encodes is `a9boot_core::abi`, which in turn is decoded from the resident
//! checkm8 handler (`research/refs/gaster/payload_handle_checkm8_request.S`).

use a9boot_core::abi::{self, Command, Reply};
use a9boot_core::layout::{self, DESCRIPTOR_ADDR};
use a9boot_core::Result;

/// One command: the bytes to `DFU_DNLOAD`, and the `wLength` to ask for on the `DFU_UPLOAD`
/// that triggers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub dnload: Vec<u8>,
    pub upload_len: u16,
    /// What this packet is for. Carried so a failure can name itself.
    pub label: String,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The handler's return value, i.e. what the callee left in `x0`.
    pub retval: u64,
    /// The bytes the callee wrote at `base + REPLY_OFF`.
    pub data: Vec<u8>,
}

impl Response {
    /// Decode the structured reply the a9boot payload writes.
    pub fn reply(&self) -> Result<Reply> {
        Reply::decode(&self.data)
    }

    pub fn status_name(&self) -> &'static str {
        abi::status::name(self.retval)
    }
}

/// Where the DNLOAD data begins to be meaningful: after the 72-byte header.
pub const DATA_OFF: usize = abi::HEADER_LEN as usize;

/// Build a command header, zero-filled up to `len`.
///
/// `len` is not cosmetic. For `EXEC` it must be `abi::PAYLOAD_OFF`, because the payload has to
/// sit at `abi::payload_exec_addr()` — past the reply area. For `MEMC` it must be exactly
/// `abi::HEADER_LEN` (72 bytes), because the appended data must start where `x1` says it does
/// (`DFU_BUFFER_ADDR + HEADER_LEN`) — exactly as the reference sends it (`gaster.c:1518-1521`
/// appends `src` after a 72-byte header). Getting this wrong makes the ROM copy zeros from the
/// wrong offset, which the read-back verification catches but only on the device.
fn header_sized(magic: u64, func: u64, args: [u64; 3], len: usize) -> Vec<u8> {
    debug_assert!(len >= abi::HEADER_LEN as usize);
    let mut v = vec![0u8; len];
    v[0..8].copy_from_slice(&magic.to_le_bytes());
    v[8..16].copy_from_slice(&func.to_le_bytes());
    // x0..x2 at +0x10, +0x18, +0x20. x3..x6 stay zero, and x7 is *not* set: the handler loads
    // it from +0x48, which is where appended data lives. See a9boot_core::abi docs.
    for (i, a) in args.iter().enumerate() {
        let off = 0x10 + i * 8;
        v[off..off + 8].copy_from_slice(&a.to_le_bytes());
    }
    v
}

/// `EXEC`: call `func` with `x0 = cmd`, `x1 = descriptor PA`, `x2 = reply PA`.
///
/// The payload image is appended after the header and the reply gap, and executes **in place**
/// at `abi::payload_exec_addr()` — which is why the linker address and this offset must agree.
pub fn exec_packet(payload: &[u8], cmd: Command) -> Packet {
    let mut dnload = header_sized(
        abi::EXEC_MAGIC,
        abi::payload_exec_addr(),
        [cmd as u64, DESCRIPTOR_ADDR, abi::reply_addr()],
        abi::PAYLOAD_OFF as usize,
    );
    dnload.extend_from_slice(payload);
    Packet {
        dnload,
        upload_len: abi::upload_len_for(abi::REPLY_SIZE as u64) as u16,
        label: format!("exec {}", cmd.name()),
    }
}

/// `EXEC` with a fourth argument in `x3`.
///
/// The handler loads `x0..x7` from the command header (`ldp x0, x1, [x20, #0x10]` …), so `x3` is
/// a real input even though a9boot's own commands never needed one until `ANCHOR`, whose window
/// number travels there.
pub fn exec_packet_ext(payload: &[u8], cmd: Command, x3: u64) -> Packet {
    let mut dnload = header_sized(
        abi::EXEC_MAGIC,
        abi::payload_exec_addr(),
        [cmd as u64, DESCRIPTOR_ADDR, abi::reply_addr()],
        abi::PAYLOAD_OFF as usize,
    );
    dnload[0x28..0x30].copy_from_slice(&x3.to_le_bytes());
    dnload.extend_from_slice(payload);
    Packet {
        dnload,
        upload_len: abi::upload_len_for(abi::REPLY_SIZE as u64) as u16,
        label: format!("exec {} x3={x3:#x}", cmd.name()),
    }
}

/// `MEMC`: `memcpy(dst, src, len)` inside the ROM's EL3 translation.
pub fn memc_packet(dst: u64, src: u64, data: &[u8]) -> Packet {
    let mut dnload = header_sized(abi::MEMC_MAGIC, 0, [dst, src, data.len() as u64], abi::HEADER_LEN as usize);
    dnload.extend_from_slice(data);
    Packet {
        dnload,
        upload_len: abi::REPLY_OFF as u16,
        label: format!("memc {:#x} <- {:#x} len {:#x}", dst, src, data.len()),
    }
}

/// Write `data` to a DRAM address. The source is the copy of `data` appended to this very
/// command, at `buffer + DATA_OFF`.
pub fn mem_write(dst: u64, data: &[u8]) -> Packet {
    memc_packet(dst, layout::DFU_BUFFER_ADDR + abi::HEADER_LEN, data)
}

/// Read `len` bytes from a DRAM address back into the reply area, so the following `UPLOAD`
/// returns them. `len` may exceed the reply cap: at this moment no payload is resident, so the
/// only limit is the buffer itself.
pub fn mem_read(src: u64, len: usize) -> Packet {
    let mut p = memc_packet(abi::reply_addr(), src, &[]);
    // The length lives in x2; `memc_packet` took it from `data.len()`, so patch it in.
    p.dnload[0x20..0x28].copy_from_slice(&(len as u64).to_le_bytes());
    p.upload_len = (abi::REPLY_OFF as usize + len) as u16;
    p.label = format!("memc read {:#x} len {:#x}", src, len);
    p
}

/// **Why** a reply was rejected. One variant per distinct wire condition, because "the device
/// returned something odd" is not a diagnosis and four different problems get four different
/// messages (HANDOFF §9.6).
///
/// Every variant has a stable `name()`, and the negative-control tests assert the *name* rather
/// than a substring of prose — so a check earns trust by having been shown to fail **as itself**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyFault {
    /// Zero bytes came back. Nothing can be said about the handler.
    Empty,
    /// Fewer than 8 bytes: not even `DONE_MAGIC` could be present.
    TruncatedBeforeMagic,
    /// 8 or more bytes, but the first word is not `DONE_MAGIC`. The handler either did not run
    /// (the ROM's own handler answered), or the command magic at the buffer was not ours.
    BadMagic,
    /// `DONE_MAGIC` is present but the return value is absent: the reply stopped between 8 and 15
    /// bytes. The exchange **did** reach our handler, so this is a transport/geometry fault, not
    /// a dead channel — and it must never be read as "no data".
    MagicWithoutRetval,
    /// `[DONE_MAGIC][retval]` is intact but the reply is shorter than the `wLength` that was
    /// asked for: the payload data is incomplete.
    DataShort,
}

impl ReplyFault {
    pub const fn name(self) -> &'static str {
        match self {
            ReplyFault::Empty => "REPLY_EMPTY",
            ReplyFault::TruncatedBeforeMagic => "REPLY_TRUNCATED",
            ReplyFault::BadMagic => "REPLY_BAD_MAGIC",
            ReplyFault::MagicWithoutRetval => "REPLY_MAGIC_WITHOUT_RETVAL",
            ReplyFault::DataShort => "REPLY_DATA_SHORT",
        }
    }
}

/// Parse an `UPLOAD` response, naming the fault.
///
/// The *order* of the checks is the contract:
///
/// 1. zero bytes → `Empty`;
/// 2. fewer than 8 → `TruncatedBeforeMagic`;
/// 3. the first word is not `DONE_MAGIC` → `BadMagic`;
/// 4. `DONE_MAGIC` present but under 16 bytes → `MagicWithoutRetval`;
/// 5. fewer bytes than `expected_upload` → `DataShort`;
/// 6. otherwise the reply is whole.
pub fn parse_response_checked(
    bytes: &[u8],
    expected_upload: u16,
) -> std::result::Result<Response, (ReplyFault, String)> {
    if bytes.is_empty() {
        return Err((
            ReplyFault::Empty,
            format!("REPLY_EMPTY: the UPLOAD returned 0 bytes (asked for {expected_upload}). \
                     Nothing was verified: this is not a value, it is the absence of one."),
        ));
    }
    if bytes.len() < 8 {
        return Err((
            ReplyFault::TruncatedBeforeMagic,
            format!(
                "REPLY_TRUNCATED: short UPLOAD reply: got {} bytes, wanted at least 8 for \
                 DONE_MAGIC (asked for {}). A partial reply must never be parsed as if whole.",
                bytes.len(),
                expected_upload
            ),
        ));
    }
    let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if magic != abi::DONE_MAGIC {
        return Err((
            ReplyFault::BadMagic,
            format!(
                "REPLY_BAD_MAGIC: UPLOAD reply does not start with DONE_MAGIC: got {magic:#018x}, \
                 expected {:#018x}. The device's DFU state is not what this command assumed.",
                abi::DONE_MAGIC
            ),
        ));
    }
    if bytes.len() < abi::REPLY_OFF as usize {
        return Err((
            ReplyFault::MagicWithoutRetval,
            format!(
                "REPLY_MAGIC_WITHOUT_RETVAL: DONE_MAGIC is present but the return value is \
                 absent: got {} bytes, the `[DONE_MAGIC][ret]` pair needs {}. The handler ran; \
                 the reply is incomplete, so no return value may be reported.",
                bytes.len(),
                abi::REPLY_OFF
            ),
        ));
    }
    if bytes.len() < expected_upload as usize {
        return Err((
            ReplyFault::DataShort,
            format!(
                "REPLY_DATA_SHORT: the reply carries {} bytes but the command asked for {}: the \
                 payload data is incomplete and must not be treated as a short value.",
                bytes.len(),
                expected_upload
            ),
        ));
    }
    let retval = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok(Response { retval, data: bytes[abi::REPLY_OFF as usize..].to_vec() })
}

/// Parse an `UPLOAD` response. Named failures, because "the device returned something odd" is
/// not a diagnosis.
///
/// The prose form of [`parse_response_checked`]; call sites that only need to propagate a
/// message use this, and the evidence recorder uses the checked form so it can carry the fault
/// *name* into the JSON.
pub fn parse_response(bytes: &[u8], expected_upload: u16) -> std::result::Result<Response, String> {
    parse_response_checked(bytes, expected_upload).map_err(|(_, msg)| msg)
}

/// The identity checks that must pass before any command is sent.
///
/// Four different problems, four different messages (HANDOFF §9.6): wrong chip, wrong board,
/// not pwned, and wrong boot stage are four distinct conditions with four distinct fixes.
pub struct Expect {
    pub cpid: u32,
    pub bdid: u32,
    pub require_pwnd: bool,
}

impl Default for Expect {
    fn default() -> Self {
        // n69ap: A9 s8003. HANDOFF §3.
        Self { cpid: 0x8003, bdid: 0x02, require_pwnd: true }
    }
}

/// Parse the serial descriptor the way the pwned device presents it.
///
/// Windows replaces spaces in the serial string with underscores, so both forms are accepted
/// (`a9pwn`'s `DeviceIdentity::parse` has the same tolerance).
pub fn parse_identity(serial: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let normalised = serial.replace('_', " ");
    for field in normalised.split_whitespace() {
        if let Some((k, v)) = field.split_once(':') {
            out.insert(k.trim_matches(|c| c == '[' || c == ']').to_string(), v.to_string());
        }
    }
    out
}

pub fn check_identity(serial: &str, expect: &Expect) -> std::result::Result<(), String> {
    let id = parse_identity(serial);
    let cpid = id.get("CPID").and_then(|v| u32::from_str_radix(v, 16).ok());
    let bdid = id.get("BDID").and_then(|v| u32::from_str_radix(v, 16).ok());
    match cpid {
        None => {
            return Err(format!(
                "no CPID in the serial descriptor ({serial:?}): this is not a device a9boot \
                 knows how to talk to."
            ))
        }
        Some(c) if c != expect.cpid => {
            return Err(format!("CPID {c:#06x}, expected {:#06x}", expect.cpid))
        }
        _ => {}
    }
    match bdid {
        None => return Err("CPID present but no BDID: refusing to guess the board".to_string()),
        Some(b) if b != expect.bdid => {
            return Err(format!("BDID {b:#04x}, expected {:#04x}", expect.bdid))
        }
        _ => {}
    }
    if expect.require_pwnd && !id.get("PWND").map(|s| s.contains("checkm8")).unwrap_or(false) {
        return Err(format!(
            "device reports {:?} but not PWND:[checkm8]: the checkm8 payload is not resident, \
             so there is no command channel. Run a9pwn first.",
            id.get("PWND")
        ));
    }
    Ok(())
}

/// Fields that may appear in evidence. Everything else — `ECID`, `UDID`, and any field not on
/// this list — is replaced before the descriptor reaches a terminal, a log or an evidence file.
pub const PUBLISHABLE_DESCRIPTOR_FIELDS: &[&str] =
    &["CPID", "CPRV", "CPFM", "SCEP", "BDID", "SRTG", "PWND"];

/// Redact a device serial descriptor for publication.
///
/// The serial descriptor on a SecureROM DFU device carries `ECID`, which is a stable device
/// identifier and must never be published (HANDOFF §9.5 / this project's hard rule). This
/// function is the *only* path by which a descriptor is allowed to reach a terminal or an
/// evidence file, so there is one place to review rather than a grep for `serial` at every call
/// site. Allowed fields keep their value; every other `NAME:value` token becomes
/// `NAME:<redacted>`; anything without a `:` is dropped.
///
/// The underscore form Windows produces (`CPID:8003_BDID:02_...`) is handled, because a
/// redactor that misses a separator is a redactor that leaks.
pub fn redact_descriptor(serial: &str) -> String {
    let normalised = serial.replace('_', " ");
    let mut out: Vec<String> = Vec::new();
    for field in normalised.split_whitespace() {
        let Some((k, _v)) = field.split_once(':') else { continue };
        let key = k.trim_matches(|c| c == '[' || c == ']').to_string();
        if key.is_empty() {
            continue;
        }
        if PUBLISHABLE_DESCRIPTOR_FIELDS.contains(&key.as_str()) {
            // Re-emit the value with its brackets, if it had any, so the shape stays readable.
            out.push(field.to_string());
        } else {
            out.push(format!("{key}:<redacted>"));
        }
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_packet_layout() {
        let payload = [0xAAu8; 16];
        let p = exec_packet(&payload, Command::Describe);
        assert_eq!(p.upload_len as u64, abi::upload_len_for(abi::REPLY_SIZE as u64));
        assert_eq!(&p.dnload[0..8], &abi::EXEC_MAGIC.to_le_bytes());
        assert_eq!(&p.dnload[8..16], &abi::payload_exec_addr().to_le_bytes());
        assert_eq!(u64::from_le_bytes(p.dnload[0x10..0x18].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(p.dnload[0x18..0x20].try_into().unwrap()), DESCRIPTOR_ADDR);
        assert_eq!(u64::from_le_bytes(p.dnload[0x20..0x28].try_into().unwrap()), abi::reply_addr());
        // x3..x6 zero, and the payload correctly placed.
        assert_eq!(&p.dnload[0x28..abi::PAYLOAD_OFF as usize], &vec![0u8; (abi::PAYLOAD_OFF - 0x28) as usize][..]);
        assert_eq!(&p.dnload[abi::PAYLOAD_OFF as usize..], &payload[..]);
    }

    #[test]
    fn memc_packet_puts_len_in_x2() {
        let p = memc_packet(0x8_0000_0000, 0x1_8038_0048, &[1, 2, 3, 4]);
        assert_eq!(&p.dnload[0..8], &abi::MEMC_MAGIC.to_le_bytes());
        assert_eq!(u64::from_le_bytes(p.dnload[0x10..0x18].try_into().unwrap()), 0x8_0000_0000);
        assert_eq!(u64::from_le_bytes(p.dnload[0x18..0x20].try_into().unwrap()), 0x1_8038_0048);
        assert_eq!(u64::from_le_bytes(p.dnload[0x20..0x28].try_into().unwrap()), 4);
        // The appended data must start exactly where x1 points, i.e. right after the 72-byte
        // header. If this is wrong, the ROM copies zeros and the read-back catches it.
        assert_eq!(p.dnload.len(), DATA_OFF + 4);
        assert_eq!(&p.dnload[DATA_OFF..], &[1, 2, 3, 4]);
        assert_eq!(u64::from_le_bytes(p.dnload[0x18..0x20].try_into().unwrap()), layout::DFU_BUFFER_ADDR + abi::HEADER_LEN);
    }

    #[test]
    fn mem_read_patches_the_length_and_asks_for_it_back() {
        let p = mem_read(0x8_0000_0000, 0x800);
        assert_eq!(u64::from_le_bytes(p.dnload[0x20..0x28].try_into().unwrap()), 0x800);
        assert_eq!(u64::from_le_bytes(p.dnload[0x10..0x18].try_into().unwrap()), abi::reply_addr());
        assert_eq!(p.upload_len as u64, 0x10 + 0x800);
    }

    #[test]
    fn response_parsing_names_its_failures() {
        let mut good = vec![0u8; 16 + abi::REPLY_SIZE];
        good[0..8].copy_from_slice(&abi::DONE_MAGIC.to_le_bytes());
        good[8..16].copy_from_slice(&7u64.to_le_bytes());
        let r = parse_response(&good, 16 + abi::REPLY_SIZE as u16).unwrap();
        assert_eq!(r.retval, 7);
        assert_eq!(r.status_name(), "FB_ENABLE_UNSUPPORTED");
        assert_eq!(r.data.len(), abi::REPLY_SIZE);

        assert!(parse_response(&[0u8; 4], 16).unwrap_err().contains("short UPLOAD reply"));
        let mut bad = good.clone();
        bad[0] = 0;
        assert!(parse_response(&bad, 16).unwrap_err().contains("DONE_MAGIC"));
    }

    #[test]
    fn identity_checks_are_four_distinct_messages() {
        let expect = Expect::default();
        let good = "CPID:8003 CPRV:11 CPFM:03 SCEP:01 BDID:02 ECID:... SRTG:[iBoot-2234.0.0.2.22] PWND:[checkm8]";
        check_identity(good, &expect).unwrap();
        // Windows' underscore form.
        check_identity(&good.replace(' ', "_"), &expect).unwrap();

        assert!(check_identity("CPID:8000 BDID:02 PWND:[checkm8]", &expect).unwrap_err().contains("CPID"));
        assert!(check_identity("CPID:8003 BDID:08 PWND:[checkm8]", &expect).unwrap_err().contains("BDID"));
        assert!(check_identity("CPID:8003 BDID:02 SRTG:[iBoot-2234]", &expect)
            .unwrap_err()
            .contains("not PWND"));
        assert!(check_identity("CPID:8003 PWND:[checkm8]", &expect).unwrap_err().contains("no BDID"));
        assert!(check_identity("SRTG:[iBoot-2234]", &expect).unwrap_err().contains("no CPID"));
    }

    /// A `PING` payload stub proving the reply path end-to-end through the simulator.
    #[test]
    fn reply_round_trip_through_the_simulator() {
        use crate::transport::{Exchange, SimDevice, Transport};
        let payload = vec![0u8; 64];
        let mut dev = SimDevice::new(0x4000);
        dev.on_exec(|_cmd, _desc| {
            let r = Reply { command: 1, status: abi::status::OK, current_el: 0xc, ..Default::default() };
            (abi::status::OK, r.encode().to_vec())
        });
        let p = exec_packet(&payload, Command::Ping);
        let raw = dev.exchange(&Exchange::from(&p)).unwrap();
        let r = parse_response(&raw, p.upload_len).unwrap();
        assert_eq!(r.retval, abi::status::OK);
        assert_eq!(r.reply().unwrap().current_el, 0xc);
    }

    // -----------------------------------------------------------------------------------
    // NEGATIVE CONTROLS
    //
    // Each of these is a *malformed* reply that a naiver parser would accept as data. The test
    // asserts the fault **by name**, so a future edit that merges two faults into one message
    // breaks the test rather than the diagnosis.
    // -----------------------------------------------------------------------------------

    /// The canonical good reply: `[DONE_MAGIC][retval][8 bytes]`, i.e. what
    /// `mem_read(addr, 8)` produces for `wLength = 24`.
    fn good_reply() -> Vec<u8> {
        let mut v = vec![0u8; abi::REPLY_OFF as usize + 8];
        v[0..8].copy_from_slice(&abi::DONE_MAGIC.to_le_bytes());
        v[8..16].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        for (i, b) in v[16..].iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        v
    }

    #[test]
    fn control_good_reply_parses() {
        // The positive control for every negative control below: same parser, same length, and
        // it must succeed — otherwise "it failed" would prove nothing.
        let r = parse_response_checked(&good_reply(), 24).unwrap();
        assert_eq!(r.retval, 0xDEAD_BEEF);
        assert_eq!(r.data.len(), 8);
    }

    #[test]
    fn empty_reply_is_reply_empty_not_a_zero_value() {
        let (fault, msg) = parse_response_checked(&[], 24).unwrap_err();
        assert_eq!(fault, ReplyFault::Empty);
        assert_eq!(fault.name(), "REPLY_EMPTY");
        assert!(msg.contains("nothing was verified") || msg.contains("Nothing was verified"), "{msg}");
    }

    #[test]
    fn a_reply_too_short_for_the_magic_is_rejected_by_name() {
        for n in 1..8usize {
            let (fault, msg) = parse_response_checked(&vec![0u8; n], 24).unwrap_err();
            assert_eq!(fault, ReplyFault::TruncatedBeforeMagic, "n = {n}");
            assert_eq!(fault.name(), "REPLY_TRUNCATED");
            assert!(msg.contains("short UPLOAD reply"), "{msg}");
        }
    }

    #[test]
    fn bad_magic_is_rejected_by_name() {
        // A reply that is otherwise well-formed and long enough: only the magic is wrong. This is
        // the shape a "the command never reached our handler" run produces (the ROM's own handler
        // answers and echoes the buffer), so it is the single most likely live failure.
        let mut bad = good_reply();
        bad[0..8].copy_from_slice(&abi::EXEC_MAGIC.to_le_bytes());
        let (fault, msg) = parse_response_checked(&bad, 24).unwrap_err();
        assert_eq!(fault, ReplyFault::BadMagic);
        assert_eq!(fault.name(), "REPLY_BAD_MAGIC");
        assert!(msg.contains("DONE_MAGIC"), "{msg}");
    }

    #[test]
    fn all_zero_bytes_are_not_accepted_as_a_reply() {
        // The trap this closes: a buffer of zeros is what an untouched DFU buffer looks like, and
        // a parser that returns "retval = 0, status = OK" from it would report a payload that
        // never ran as a success.
        let (fault, _) = parse_response_checked(&vec![0u8; 24], 24).unwrap_err();
        assert_eq!(fault, ReplyFault::BadMagic);
        assert_eq!(parse_response(&vec![0u8; 24], 24).unwrap_err().contains("REPLY_BAD_MAGIC"), true);
    }

    #[test]
    fn magic_present_without_the_return_value_is_its_own_fault() {
        // `DONE_MAGIC` and nothing else: the handler ran, so this is NOT "no data" and it is NOT
        // a return value of zero. 8..16 bytes, all lengths.
        for n in 8..16usize {
            let mut b = vec![0u8; n];
            b[0..8].copy_from_slice(&abi::DONE_MAGIC.to_le_bytes());
            let (fault, msg) = parse_response_checked(&b, 24).unwrap_err();
            assert_eq!(fault, ReplyFault::MagicWithoutRetval, "n = {n}");
            assert_eq!(fault.name(), "REPLY_MAGIC_WITHOUT_RETVAL");
            assert!(msg.contains("return value is absent"), "{msg}");
        }
    }

    #[test]
    fn a_complete_pair_with_short_data_is_its_own_fault() {
        // 16 bytes: magic + retval, intact, but the command asked for 24.
        let mut b = good_reply();
        b.truncate(16);
        let (fault, msg) = parse_response_checked(&b, 24).unwrap_err();
        assert_eq!(fault, ReplyFault::DataShort);
        assert_eq!(fault.name(), "REPLY_DATA_SHORT");
        assert!(msg.contains("incomplete"), "{msg}");
    }

    /// Every fault name is distinct: a diagnosis that shares a name with another diagnosis is
    /// not a diagnosis.
    #[test]
    fn fault_names_are_distinct() {
        let all = [
            ReplyFault::Empty,
            ReplyFault::TruncatedBeforeMagic,
            ReplyFault::BadMagic,
            ReplyFault::MagicWithoutRetval,
            ReplyFault::DataShort,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn redaction_hides_ecid_and_keeps_the_fields_that_matter() {
        let serial = "CPID:8003 CPRV:11 CPFM:03 SCEP:01 BDID:02 \
                      ECID:0123456789ABCDEF SRTG:[iBoot-2234.0.0.2.22] PWND:[checkm8]";
        let red = redact_descriptor(serial);
        assert!(!red.contains("0123456789ABCDEF"), "ECID leaked: {red}");
        assert!(red.contains("ECID:<redacted>"), "{red}");
        assert!(red.contains("CPID:8003"), "{red}");
        assert!(red.contains("BDID:02"), "{red}");
        assert!(red.contains("SRTG:[iBoot-2234.0.0.2.22]"), "{red}");
        assert!(red.contains("PWND:[checkm8]"), "{red}");
        // The redacted form must still satisfy the identity check, or redaction would break the
        // gate that protects the device.
        check_identity(&red, &Expect::default()).unwrap();
        // Windows' underscore form is redacted too.
        let win = redact_descriptor(&serial.replace(' ', "_"));
        assert!(!win.contains("0123456789ABCDEF"), "ECID leaked in underscore form: {win}");
        // Unknown fields are dropped, not passed through.
        assert!(!redact_descriptor("ECID:AA SECRET:BB").contains("SECRET:BB"));
    }
}
