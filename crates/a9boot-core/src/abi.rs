//! The post-pwn command channel: byte-exact, and the only ABI a9boot shares with the device.
//!
//! ## Where this comes from
//!
//! The resident checkm8 handler is 248 bytes copied to `layout::HANDLER_ADDR` by the exploit
//! payload. It is `research/refs/gaster/payload_handle_checkm8_request.S` (Apache-2.0), and it
//! is a complete, if terse, specification. Decoded:
//!
//! ```text
//!   ldrh w2, [x0]       ; w2 = bmRequestType | (bRequest << 8)
//!   cmp  w2, #0x2A1     ; 0xA1 = class/interface/device-to-host ; 0x02 = DFU_UPLOAD
//!   bne  <original ROM handler>
//!   ldrh w2, [x19, #2]  ; wValue ; must be 0xFFFF
//!   ldr  x0, [base]     ; command magic
//!   cmp  x0, EXEC_MAGIC ; -> load x0..x7 from base+0x10..0x50, x8 = [base+8], blr x8
//!   cmp  x0, MEMC_MAGIC ; -> memcpy(x0=[base+0x10] dst, x1=[base+0x18] src, x2=[base+0x20] len)
//!   stp  x8, x0, [base] ; DONE_MAGIC at base+0, return value at base+8
//!   usb_core_do_transfer(0x80, base, wLength, 0)   ; reply = wLength bytes read from base
//! ```
//!
//! Two consequences that a9boot is built around:
//!
//! 1. **`x7` is not a free argument.** The handler loads it from `base + 0x48`, which is where
//!    the appended payload data starts. a9boot uses `x0`, `x1`, `x2` only.
//! 2. **The reply is the same buffer the command arrived in**, so every command can return
//!    telemetry in the same round trip. That is the observability primitive in DESIGN.md §5.3 —
//!    measured, not inferred.
//!
//! ## Buffer geometry
//!
//! ```text
//!   base + 0x000 .. 0x010   DONE_MAGIC, return value      (written by the handler)
//!   base + 0x010 .. 0x110   reply data, REPLY_CAP bytes   (written by the payload)
//!   base + 0x110 ..         the payload's own image       (delivered with the command)
//! ```
//!
//! The reply area ends before the payload's first instruction on purpose: a reply must never be
//! able to overwrite the code that is still running. (`REPLY_CAP` is 256 bytes; the payload
//! writes the reply *last*, after it has read everything it needs.)

use crate::layout::{DFU_BUFFER_ADDR, DESCRIPTOR_ADDR};
use crate::{Error, Result};

// ---------------------------------------------------------------------------------------
// Magic values — INSPECTED, gaster.c:49-51
// ---------------------------------------------------------------------------------------

/// `0x646F6E65646F6E65` ("donedone"), `gaster.c:49`.
pub const DONE_MAGIC: u64 = 0x646F_6E65_646F_6E65;
/// `0x6578656365786563` ("execexec"), `gaster.c:50`.
pub const EXEC_MAGIC: u64 = 0x6578_6563_6578_6563;
/// `0x6D656D636D656D63` ("memcmemc"), `gaster.c:51`.
pub const MEMC_MAGIC: u64 = 0x6D65_6D63_6D65_6D63;

/// Arbitrary tag, ours. "A9BOOTMB" read as a big-endian word; the byte order on the wire is
/// little-endian like every other u64 here, and the test pins the exact bytes.
pub const MAILBOX_MAGIC: u64 = 0x4139_424F_4F54_4D42;
/// Arbitrary tag, ours. "A9BDESC1" read as a big-endian word.
pub const DESCRIPTOR_MAGIC: u64 = 0x4139_4244_4553_4331;
/// Bumped when the descriptor layout changes. A payload that does not know the version it is
/// handed must refuse rather than guess.
pub const DESCRIPTOR_VERSION: u64 = 1;

// ---------------------------------------------------------------------------------------
// Buffer geometry
// ---------------------------------------------------------------------------------------

/// 72 bytes: magic, func, x0..x6. (`gaster.c:1518-1521` sends exactly
/// `sizeof(exec_cmd) - sizeof(r)` = 80 - 8 = 72 bytes of header.)
pub const HEADER_LEN: u64 = 0x48;
/// Where the handler sends the callee's reply data back from.
pub const REPLY_OFF: u64 = 0x10;
/// How much room a reply may use before it would run into the payload's own code.
pub const REPLY_CAP: u64 = 0x100;
/// The payload's first instruction, relative to the buffer base. 16-byte aligned, and exactly
/// where the reply area ends, so a reply can never reach into the code that is still running.
pub const PAYLOAD_OFF: u64 = REPLY_OFF + REPLY_CAP; // = 0x110

/// Where the a9boot payload executes: inside the ROM's DFU buffer, in place.
/// The payload is linked here, so it needs no relocation and no bootstrap stage.
pub const fn payload_exec_addr() -> u64 {
    DFU_BUFFER_ADDR + PAYLOAD_OFF
}

/// Absolute address of the reply area, which is what `x2` carries.
pub const fn reply_addr() -> u64 {
    DFU_BUFFER_ADDR + REPLY_OFF
}

/// The largest reply the host may request, in bytes of payload data (the response also
/// carries the 16-byte `{DONE_MAGIC, return value}` prefix, so the UPLOAD `wLength` is
/// `16 + reply_len`).
pub const fn max_reply_len() -> u64 {
    REPLY_CAP
}

/// The `wLength` the host asks for when it wants a `reply_len`-byte reply.
pub const fn upload_len_for(reply_len: u64) -> u64 {
    REPLY_OFF + reply_len
}

// ---------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------

/// `x0` on entry to the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Command {
    /// No side effects. Proves the payload ran and that the channel works.
    Ping = 1,
    /// Report the exception-level picture into the reply. Read-only. This is the command
    /// that answers UNVERIFIED items U-3 and U-4 with data instead of an assumption.
    Describe = 2,
    /// Validate the descriptor and the planned ranges, without touching the CPU state.
    Prepare = 3,
    /// Final: cache maintenance, EL1 setup, `eret`. Never returns.
    Go = 4,
    /// Dump the CPU state the payload was entered with, in windows of `ANCHOR_WORDS` words.
    /// `x3` selects the window (the handler loads `x3` from `header + 0x28`), and the words are
    /// returned in the structured reply. Read-only, and it writes nothing outside the reply area:
    /// `LOADER-FILL.md` §12 step 1 needs an anchor for the ADT/`boot_args` pointer, and this is
    /// how the loader supplies one without guessing an address.
    Anchor = 5,
}

impl Command {
    pub const fn from_u64(v: u64) -> Option<Command> {
        match v {
            1 => Some(Command::Ping),
            2 => Some(Command::Describe),
            3 => Some(Command::Prepare),
            4 => Some(Command::Go),
            5 => Some(Command::Anchor),
            _ => None,
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Command::Ping => "PING",
            Command::Describe => "DESCRIBE",
            Command::Prepare => "PREPARE",
            Command::Go => "GO",
            Command::Anchor => "ANCHOR",
        }
    }
}

/// The payload's return value, which the handler stores at `base + 8`. Stable, greppable,
/// and never merged: four different problems get four different names.
pub mod status {
    pub const OK: u64 = 0;
    pub const BAD_COMMAND: u64 = 1;
    pub const BAD_DESCRIPTOR_MAGIC: u64 = 2;
    pub const BAD_DESCRIPTOR_VERSION: u64 = 3;
    pub const BAD_DESCRIPTOR_FIELD: u64 = 4;
    pub const BAD_ALIGNMENT: u64 = 5;
    pub const OUT_OF_RANGE: u64 = 6;
    pub const FB_ENABLE_UNSUPPORTED: u64 = 7;
    pub const INTERNAL: u64 = 8;

    pub const fn name(s: u64) -> &'static str {
        match s {
            OK => "OK",
            BAD_COMMAND => "BAD_COMMAND",
            BAD_DESCRIPTOR_MAGIC => "BAD_DESCRIPTOR_MAGIC",
            BAD_DESCRIPTOR_VERSION => "BAD_DESCRIPTOR_VERSION",
            BAD_DESCRIPTOR_FIELD => "BAD_DESCRIPTOR_FIELD",
            BAD_ALIGNMENT => "BAD_ALIGNMENT",
            OUT_OF_RANGE => "OUT_OF_RANGE",
            FB_ENABLE_UNSUPPORTED => "FB_ENABLE_UNSUPPORTED",
            INTERNAL => "INTERNAL",
            _ => "UNKNOWN_STATUS",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------------------

/// Flags word of the descriptor.
pub mod flags {
    /// Bit 0. **Must stay clear in rung 1.** It is set only by a display-init module that has
    /// actually lit the panel; it is what flips `framebuffer@0` to `status = "okay"`.
    /// Claiming a framebuffer we did not light produces a blank screen instead of an error,
    /// which is this project's most expensive failure mode. DESIGN.md §4.4, §5.2.
    pub const FB_ENABLE: u64 = 1 << 0;
    /// Bit 1. The initrd region must be cleaned to PoC. Set by the host when an initramfs is
    /// present; clear when it is not, so the payload does not clean a range nothing wrote.
    pub const INITRD_PRESENT: u64 = 1 << 1;
}

/// The small struct the host writes at `layout::DESCRIPTOR_ADDR` and the payload validates.
///
/// Field order is fixed and serialised little-endian through `encode`/`decode`, so the bytes
/// are testable without `unsafe` and without relying on Rust's `repr(C)` layout matching the
/// wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Descriptor {
    pub magic: u64,
    pub version: u64,
    pub flags: u64,
    pub dram_base: u64,
    pub dram_size: u64,
    pub dtb_addr: u64,
    pub dtb_size: u64,
    pub image_addr: u64,
    pub image_size: u64,
    pub image_text_offset: u64,
    pub initrd_addr: u64,
    pub initrd_size: u64,
    pub kernel_entry: u64,
    pub mailbox_addr: u64,
    pub vectors_addr: u64,
    pub vectors_size: u64,
    pub stack_top: u64,
    pub spin_addr: u64,
    pub fb_addr: u64,
    pub fb_size: u64,
    pub fb_width: u64,
    pub fb_height: u64,
    pub fb_stride: u64,
    pub wdt_addr: u64,
    pub uart_addr: u64,
    /// Reserved: must be zero. Present so a descriptor from a *newer* host is still a fixed
    /// size and an older payload refuses on version rather than reading garbage.
    pub reserved: [u64; 8],
}

/// How many words one `ANCHOR` window carries. The reply holds `REPLY_WORDS` (14) words, and the
/// first two are `command` and `status`, so a window is the remaining twelve — a round number that
/// keeps the payload's copy loop trivial and the host's decode obvious.
pub const ANCHOR_WORDS: usize = 12;

/// How many windows `ANCHOR` can address: the entry registers (`x0..x30`, `sp`, `lr`, `spsr_el3`,
/// `elr_el3` = 35 words → 3 windows) and then the stack, `ANCHOR_WORDS * 8` bytes per window.
pub const ANCHOR_REG_WINDOWS: u64 = 3;

/// Number of u64 words in the wire form. Keep in sync with `Descriptor`.
pub const DESCRIPTOR_WORDS: usize = 33;
/// Wire size in bytes.
pub const DESCRIPTOR_SIZE: usize = DESCRIPTOR_WORDS * 8;

impl Descriptor {
    pub fn encode(&self) -> [u8; DESCRIPTOR_SIZE] {
        let words = [
            self.magic,
            self.version,
            self.flags,
            self.dram_base,
            self.dram_size,
            self.dtb_addr,
            self.dtb_size,
            self.image_addr,
            self.image_size,
            self.image_text_offset,
            self.initrd_addr,
            self.initrd_size,
            self.kernel_entry,
            self.mailbox_addr,
            self.vectors_addr,
            self.vectors_size,
            self.stack_top,
            self.spin_addr,
            self.fb_addr,
            self.fb_size,
            self.fb_width,
            self.fb_height,
            self.fb_stride,
            self.wdt_addr,
            self.uart_addr,
            self.reserved[0],
            self.reserved[1],
            self.reserved[2],
            self.reserved[3],
            self.reserved[4],
            self.reserved[5],
            self.reserved[6],
            self.reserved[7],
        ];
        let mut out = [0u8; DESCRIPTOR_SIZE];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Descriptor> {
        if bytes.len() < DESCRIPTOR_SIZE {
            return Err(Error::new("DESCRIPTOR_SHORT", bytes.len() as u64));
        }
        let w = |i: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Descriptor {
            magic: w(0),
            version: w(1),
            flags: w(2),
            dram_base: w(3),
            dram_size: w(4),
            dtb_addr: w(5),
            dtb_size: w(6),
            image_addr: w(7),
            image_size: w(8),
            image_text_offset: w(9),
            initrd_addr: w(10),
            initrd_size: w(11),
            kernel_entry: w(12),
            mailbox_addr: w(13),
            vectors_addr: w(14),
            vectors_size: w(15),
            stack_top: w(16),
            spin_addr: w(17),
            fb_addr: w(18),
            fb_size: w(19),
            fb_width: w(20),
            fb_height: w(21),
            fb_stride: w(22),
            wdt_addr: w(23),
            uart_addr: w(24),
            reserved: [w(25), w(26), w(27), w(28), w(29), w(30), w(31), w(32)],
        })
    }

    /// Every check runs **on the device**, before anything irreversible happens, and returns a
    /// named status rather than continuing into an unknown state. The host runs the same
    /// function before upload, so a failure here means a disagreement between two builds —
    /// which is exactly what `DESCRIPTOR_VERSION` exists to catch.
    pub fn validate(&self) -> core::result::Result<(), (u64, u64)> {
        if self.magic != DESCRIPTOR_MAGIC {
            return Err((status::BAD_DESCRIPTOR_MAGIC, self.magic));
        }
        if self.version != DESCRIPTOR_VERSION {
            return Err((status::BAD_DESCRIPTOR_VERSION, self.version));
        }
        if self.dram_base == 0 || self.dram_size == 0 {
            return Err((status::BAD_DESCRIPTOR_FIELD, 0));
        }
        // Every range must be inside DRAM and must not wrap.
        let dram_end = self
            .dram_base
            .checked_add(self.dram_size)
            .ok_or((status::OUT_OF_RANGE, self.dram_base))?;
        for (name, addr, size) in [
            (1u64, self.dtb_addr, self.dtb_size),
            (2, self.image_addr, self.image_size),
            (3, self.mailbox_addr, 0x1000),
            (4, self.vectors_addr, self.vectors_size),
        ] {
            let end = addr.checked_add(size).ok_or((status::OUT_OF_RANGE, addr))?;
            if addr < self.dram_base || end > dram_end {
                return Err((status::OUT_OF_RANGE, name));
            }
        }
        if self.flags & flags::INITRD_PRESENT != 0 {
            let end = self
                .initrd_addr
                .checked_add(self.initrd_size)
                .ok_or((status::OUT_OF_RANGE, self.initrd_addr))?;
            if self.initrd_size == 0 || self.initrd_addr < self.dram_base || end > dram_end {
                return Err((status::OUT_OF_RANGE, self.initrd_addr));
            }
        }
        if self.image_size == 0 || self.kernel_entry != self.image_addr {
            // booting.rst: "The primary CPU must jump directly to the first instruction of the
            // kernel image." Anything else is a bug, not a configuration.
            return Err((status::BAD_DESCRIPTOR_FIELD, self.kernel_entry));
        }
        if self.image_addr % 4 != 0 || self.dtb_addr % 8 != 0 {
            return Err((status::BAD_ALIGNMENT, self.dtb_addr));
        }
        if self.vectors_addr % 0x800 != 0 {
            return Err((status::BAD_ALIGNMENT, self.vectors_addr));
        }
        if self.stack_top % 16 != 0 || self.stack_top == 0 {
            return Err((status::BAD_ALIGNMENT, self.stack_top));
        }
        if self.flags & flags::FB_ENABLE != 0 {
            // Rung 1 refuses this outright rather than half-supporting it: a framebuffer node
            // that says "okay" while the panel is dark is worse than no framebuffer node.
            return Err((status::FB_ENABLE_UNSUPPORTED, self.fb_addr));
        }
        if self.reserved.iter().any(|w| *w != 0) {
            return Err((status::BAD_DESCRIPTOR_FIELD, self.reserved[0]));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------------------

/// What kind of record the mailbox holds. The host reads this back after handoff, so the
/// numbers are part of the interface and must not be renumbered.
pub mod record {
    /// The payload reached the point of no return and is about to `eret`. Written *before*
    /// `eret`, so "we jumped" and "we died on entry" are distinguishable.
    pub const HANDOFF: u64 = 1;
    /// EL1 took a synchronous exception and the vector recorded it.
    pub const EL1_FAULT: u64 = 2;
    /// The payload panicked (Rust). `detail` = panic location id, `esr_el1` field = status.
    pub const PAYLOAD_PANIC: u64 = 3;
    /// EL1 came up in a state a9boot did not set, i.e. the writes made from EL3 with
    /// `SCR_EL3.NS = 1` did not reach the Non-secure bank. `detail` names which register
    /// disagreed. See DESIGN.md §4.3 and UNVERIFIED.md U-4: this record is how the design's
    /// riskiest architectural assumption gets *measured* instead of trusted.
    pub const EL1_STATE_UNEXPECTED: u64 = 4;
}

/// The telemetry record. Fixed offsets, so the host can decode it without knowing anything
/// about the payload build. 8-byte aligned fields only, little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mailbox {
    /// `MAILBOX_MAGIC` once a record has been written. Zero means "nothing happened yet",
    /// which is itself information: the payload never got as far as writing it.
    pub magic: u64,
    /// One of `record::*`.
    pub kind: u64,
    /// Command or vector index that produced this record.
    pub detail: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub cntfrq_el0: u64,
    pub scr_el3: u64,
    pub current_el: u64,
    pub sctlr_el3: u64,
    pub ttbr0_el3: u64,
    pub tcr_el3: u64,
    pub cptr_el3: u64,
    pub midr_el1: u64,
    pub mpidr_el1: u64,
}

pub const MAILBOX_SIZE: usize = 16 * 8;

impl Mailbox {
    pub fn encode(&self) -> [u8; MAILBOX_SIZE] {
        let words = [
            self.magic,
            self.kind,
            self.detail,
            self.esr_el1,
            self.far_el1,
            self.elr_el1,
            self.spsr_el1,
            self.cntfrq_el0,
            self.scr_el3,
            self.current_el,
            self.sctlr_el3,
            self.ttbr0_el3,
            self.tcr_el3,
            self.cptr_el3,
            self.midr_el1,
            self.mpidr_el1,
        ];
        let mut out = [0u8; MAILBOX_SIZE];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Mailbox> {
        if bytes.len() < MAILBOX_SIZE {
            return Err(Error::new("MAILBOX_SHORT", bytes.len() as u64));
        }
        let w = |i: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Mailbox {
            magic: w(0),
            kind: w(1),
            detail: w(2),
            esr_el1: w(3),
            far_el1: w(4),
            elr_el1: w(5),
            spsr_el1: w(6),
            cntfrq_el0: w(7),
            scr_el3: w(8),
            current_el: w(9),
            sctlr_el3: w(10),
            ttbr0_el3: w(11),
            tcr_el3: w(12),
            cptr_el3: w(13),
            midr_el1: w(14),
            mpidr_el1: w(15),
        })
    }
}

// ---------------------------------------------------------------------------------------
// Reply
// ---------------------------------------------------------------------------------------

/// The structured reply the host parses out of the UPLOAD response. Fixed layout, 8-byte
/// words, so the payload writes it with plain stores and the host reads it with `decode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reply {
    /// Echo of the command, so a stale reply cannot be mistaken for a fresh one.
    pub command: u64,
    /// `status::*` again (the same value the handler stored at `base + 8`).
    pub status: u64,
    pub current_el: u64,
    /// NOTE on the wire order: the ROM's EXEC-trigger reply is a FIXED 64 bytes (MEASURED,
    /// three runs), i.e. `DONE_MAGIC + retval + 6 Reply words`. The granule-critical registers
    /// for the page walk (`TCR_EL3` = TG0/T0SZ, `SCTLR_EL3` = M, `TTBR0_EL3` = root) must
    /// therefore sit in the first 6 words, so `tcr_el3` moved up past `scr_el3` (the least
    /// needed): words 0..6 are command, status, current_el, tcr_el3, sctlr_el3, ttbr0_el3.
    pub tcr_el3: u64,
    pub sctlr_el3: u64,
    pub ttbr0_el3: u64,
    pub scr_el3: u64,
    pub cptr_el3: u64,
    pub midr_el1: u64,
    pub mpidr_el1: u64,
    pub cntfrq_el0: u64,
    pub sctlr_el1: u64,
    pub esr_el1: u64,
    pub detail: u64,
}

pub const REPLY_WORDS: usize = 14;
pub const REPLY_SIZE: usize = REPLY_WORDS * 8;

impl Reply {
    pub fn encode(&self) -> [u8; REPLY_SIZE] {
        let words = [
            self.command,
            self.status,
            self.current_el,
            self.tcr_el3,
            self.sctlr_el3,
            self.ttbr0_el3,
            self.scr_el3,
            self.cptr_el3,
            self.midr_el1,
            self.mpidr_el1,
            self.cntfrq_el0,
            self.sctlr_el1,
            self.esr_el1,
            self.detail,
        ];
        let mut out = [0u8; REPLY_SIZE];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Reply> {
        if bytes.len() < REPLY_SIZE {
            return Err(Error::new("REPLY_SHORT", bytes.len() as u64));
        }
        let w = |i: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Reply {
            command: w(0),
            status: w(1),
            current_el: w(2),
            tcr_el3: w(3),
            sctlr_el3: w(4),
            ttbr0_el3: w(5),
            scr_el3: w(6),
            cptr_el3: w(7),
            midr_el1: w(8),
            mpidr_el1: w(9),
            cntfrq_el0: w(10),
            sctlr_el1: w(11),
            esr_el1: w(12),
            detail: w(13),
        })
    }
}

/// Where the descriptor lives, as the payload sees it. Passed in `x1` as well; this is the
/// value the host must use.
pub const fn descriptor_addr() -> u64 {
    DESCRIPTOR_ADDR
}

/// Sanity: the reply must fit in the reply area, and a full reply must be requestable.
pub fn check() -> Result<()> {
    if REPLY_SIZE as u64 > max_reply_len() {
        return Err(Error::new("REPLY_EXCEEDS_REPLY_CAP", REPLY_SIZE as u64));
    }
    if PAYLOAD_OFF < REPLY_OFF + REPLY_CAP {
        return Err(Error::new("PAYLOAD_OFF_OVERLAPS_REPLY", PAYLOAD_OFF));
    }
    if DESCRIPTOR_SIZE as u64 > crate::layout::DESCRIPTOR_SIZE {
        return Err(Error::new("DESCRIPTOR_EXCEEDS_REGION", DESCRIPTOR_SIZE as u64));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_is_self_consistent() {
        check().unwrap();
        assert_eq!(DESCRIPTOR_WORDS * 8, DESCRIPTOR_SIZE);
        assert_eq!(DESCRIPTOR_SIZE, 264);
    }

    /// The three magic values, against the reference: `gaster.c:49-51`.
    ///
    /// Note the byte order, because it is a trap: the constant spells `execexec` when written
    /// **big-endian**, and on the wire (little-endian) the bytes appear reversed. That is
    /// harmless — both sides compare the 64-bit *value* — but a test that asserted the memory
    /// bytes spelled the word would be asserting the wrong thing.
    #[test]
    fn magics_match_the_reference() {
        assert_eq!(DONE_MAGIC, 0x646F_6E65_646F_6E65);
        assert_eq!(EXEC_MAGIC, 0x6578_6563_6578_6563);
        assert_eq!(MEMC_MAGIC, 0x6D65_6D63_6D65_6D63);
        assert_eq!(&EXEC_MAGIC.to_be_bytes(), b"execexec");
        assert_eq!(&MEMC_MAGIC.to_be_bytes(), b"memcmemc");
        assert_eq!(&DONE_MAGIC.to_be_bytes(), b"donedone");
        // Ours, and the same convention: "A9BOOTMB" as a big-endian word.
        assert_eq!(&MAILBOX_MAGIC.to_be_bytes(), b"A9BOOTMB");
        assert_eq!(&DESCRIPTOR_MAGIC.to_be_bytes(), b"A9BDESC1");
        // And the wire form really is the reverse, so the distinction above is not hypothetical:
        // "execexec" reversed is "cexecexe".
        assert_eq!(&EXEC_MAGIC.to_le_bytes(), b"cexecexe");
    }

    /// The buffer geometry, spelled out. A reply must never be able to reach the payload's
    /// first instruction — that code is still executing while the reply is being written.
    #[test]
    fn reply_cannot_overwrite_the_payload() {
        assert_eq!(HEADER_LEN, 72);
        assert_eq!(REPLY_OFF, 0x10);
        assert_eq!(PAYLOAD_OFF, 0x110);
        assert_eq!(REPLY_OFF + REPLY_CAP, PAYLOAD_OFF);
        assert!(REPLY_SIZE as u64 <= REPLY_CAP);
        assert_eq!(payload_exec_addr(), 0x1_8038_0110);
    }

    /// `x7` overlaps the first 8 bytes of the payload image: the header must therefore end
    /// before `PAYLOAD_OFF`, and the payload must not read `x7`.
    #[test]
    fn header_ends_before_the_payload() {
        assert!(HEADER_LEN <= PAYLOAD_OFF);
        assert_eq!(HEADER_LEN, 9 * 8);
    }

    /// The `wLength` the host asks for, including the handler's `{DONE_MAGIC, retval}` prefix.
    #[test]
    fn upload_length_includes_the_prefix() {
        assert_eq!(upload_len_for(REPLY_SIZE as u64), 0x10 + REPLY_SIZE as u64);
        assert_eq!(upload_len_for(0), 0x10);
    }

    #[test]
    fn descriptor_round_trips() {
        let d = Descriptor {
            magic: DESCRIPTOR_MAGIC,
            version: DESCRIPTOR_VERSION,
            flags: flags::INITRD_PRESENT,
            dram_base: crate::layout::DRAM_BASE,
            dram_size: crate::layout::DRAM_SIZE,
            dtb_addr: crate::layout::DTB_ADDR,
            dtb_size: 0x4000,
            image_addr: crate::layout::IMAGE_2M_BASE + 0x80000,
            image_size: 0x1000_000,
            image_text_offset: 0x80000,
            initrd_addr: 0x8_1000_0000,
            initrd_size: 0x300000,
            kernel_entry: crate::layout::IMAGE_2M_BASE + 0x80000,
            mailbox_addr: crate::layout::MAILBOX_ADDR,
            vectors_addr: crate::layout::VECTORS_ADDR,
            vectors_size: crate::layout::VECTORS_SIZE,
            stack_top: crate::layout::EL1_STACK_TOP,
            spin_addr: crate::layout::SPIN_MAILBOX_ADDR,
            fb_addr: crate::layout::FB_ADDR,
            fb_size: crate::layout::FB_SIZE,
            fb_width: crate::layout::FB_WIDTH as u64,
            fb_height: crate::layout::FB_HEIGHT as u64,
            fb_stride: crate::layout::FB_STRIDE as u64,
            wdt_addr: crate::layout::WDT_ADDR,
            uart_addr: crate::layout::UART_ADDR,
            reserved: [0; 8],
        };
        let bytes = d.encode();
        assert_eq!(bytes.len(), DESCRIPTOR_SIZE);
        assert_eq!(Descriptor::decode(&bytes).unwrap(), d);
        d.validate().expect("valid descriptor");
    }

    /// Every rejection is a *named* status, and the checks are what the payload relies on.
    #[test]
    fn descriptor_validation_names_its_failures() {
        let base = valid_descriptor();

        let mut bad = base;
        bad.magic = 0;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_DESCRIPTOR_MAGIC);

        let mut bad = base;
        bad.version = 99;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_DESCRIPTOR_VERSION);

        let mut bad = base;
        bad.flags = flags::FB_ENABLE;
        assert_eq!(bad.validate().unwrap_err().0, status::FB_ENABLE_UNSUPPORTED);

        let mut bad = base;
        bad.image_size = 0;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_DESCRIPTOR_FIELD);

        // The kernel must be entered at the start of the Image; an offset is a bug.
        let mut bad = base;
        bad.kernel_entry += 0x80000;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_DESCRIPTOR_FIELD);

        // An image that runs off the end of DRAM.
        let mut bad = base;
        bad.image_size = crate::layout::DRAM_SIZE;
        assert_eq!(bad.validate().unwrap_err().0, status::OUT_OF_RANGE);

        // A DT base that is not 8-byte aligned.
        let mut bad = base;
        bad.dtb_addr += 4;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_ALIGNMENT);

        // A vectors address that would break VBAR_EL1's alignment requirement.
        let mut bad = base;
        bad.vectors_addr += 0x400;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_ALIGNMENT);

        // A stack that is not 16-byte aligned.
        let mut bad = base;
        bad.stack_top -= 8;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_ALIGNMENT);

        // A non-zero reserved word means a newer host and an older payload.
        let mut bad = base;
        bad.reserved[3] = 1;
        assert_eq!(bad.validate().unwrap_err().0, status::BAD_DESCRIPTOR_FIELD);
    }

    fn valid_descriptor() -> Descriptor {
        Descriptor {
            magic: DESCRIPTOR_MAGIC,
            version: DESCRIPTOR_VERSION,
            flags: 0,
            dram_base: crate::layout::DRAM_BASE,
            dram_size: crate::layout::DRAM_SIZE,
            dtb_addr: crate::layout::DTB_ADDR,
            dtb_size: 0x4000,
            image_addr: crate::layout::IMAGE_2M_BASE + 0x80000,
            image_size: 0x1000_000,
            image_text_offset: 0x80000,
            initrd_addr: 0,
            initrd_size: 0,
            kernel_entry: crate::layout::IMAGE_2M_BASE + 0x80000,
            mailbox_addr: crate::layout::MAILBOX_ADDR,
            vectors_addr: crate::layout::VECTORS_ADDR,
            vectors_size: crate::layout::VECTORS_SIZE,
            stack_top: crate::layout::EL1_STACK_TOP,
            spin_addr: crate::layout::SPIN_MAILBOX_ADDR,
            fb_addr: crate::layout::FB_ADDR,
            fb_size: crate::layout::FB_SIZE,
            fb_width: crate::layout::FB_WIDTH as u64,
            fb_height: crate::layout::FB_HEIGHT as u64,
            fb_stride: crate::layout::FB_STRIDE as u64,
            wdt_addr: crate::layout::WDT_ADDR,
            uart_addr: crate::layout::UART_ADDR,
            reserved: [0; 8],
        }
    }

    #[test]
    fn mailbox_round_trips() {
        let m = Mailbox {
            magic: MAILBOX_MAGIC,
            kind: record::EL1_FAULT,
            detail: 0x200,
            esr_el1: 0x9600_0006,
            far_el1: 0xdead_beef,
            ..Default::default()
        };
        let bytes = m.encode();
        assert_eq!(Mailbox::decode(&bytes).unwrap(), m);
        assert_eq!(bytes.len(), MAILBOX_SIZE);
        // Field order is the interface: magic first, then the record kind.
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), MAILBOX_MAGIC);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), record::EL1_FAULT);
    }

    #[test]
    fn reply_round_trips() {
        let r = Reply {
            command: Command::Describe as u64,
            status: status::OK,
            current_el: 0xc,
            scr_el3: 0x30,
            ..Default::default()
        };
        let bytes = r.encode();
        assert_eq!(Reply::decode(&bytes).unwrap(), r);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 2);
    }

    #[test]
    fn short_buffers_are_named_failures() {
        assert_eq!(Descriptor::decode(&[0u8; 8]).unwrap_err().code, "DESCRIPTOR_SHORT");
        assert_eq!(Mailbox::decode(&[0u8; 8]).unwrap_err().code, "MAILBOX_SHORT");
        assert_eq!(Reply::decode(&[0u8; 8]).unwrap_err().code, "REPLY_SHORT");
    }

    #[test]
    fn command_names_are_stable() {
        assert_eq!(Command::from_u64(4), Some(Command::Go));
        assert_eq!(Command::from_u64(0), None);
        assert_eq!(Command::Go.name(), "GO");
        assert_eq!(status::name(status::FB_ENABLE_UNSUPPORTED), "FB_ENABLE_UNSUPPORTED");
        assert_eq!(status::name(999), "UNKNOWN_STATUS");
    }
}
