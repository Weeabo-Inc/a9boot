//! a9boot's on-device payload.
//!
//! ## What this is
//!
//! A **stateless** Rust `no_std` binary that the host delivers inside the same DFU command that
//! invokes it, and which executes **in place** inside the ROM's DFU buffer in SRAM
//! (`a9boot_core::abi::payload_exec_addr()`). It is therefore never resident, needs no
//! relocation, and cannot be clobbered by the blob streaming that happens between commands.
//!
//! It is invoked by the resident checkm8 handler with `x0 = command`, `x1 = descriptor physical
//! address`, `x2 = reply physical address`, and it returns a status in `x0` which the handler
//! stores for the host. That round trip is the loader's *measured* liveness signal.
//!
//! ## What it deliberately does not do
//!
//! * No USB stack. The channel already exists and is owned by the resident handler.
//! * No device-tree editing. Every value is known at plan time, so the host produces the final
//!   DTB and prints it for review before anything is uploaded — and the payload stays small.
//! * No page tables. Linux must be entered with the MMU **off** and builds its own 16 KiB-granule
//!   tables (booting.rst: "The MMU must be off"). Providing tables would be worse than useless.
//! * No display initialisation. `framebuffer@0` stays `status = "disabled"` until a display
//!   module actually lights the panel, because a framebuffer node that lies produces a blank
//!   screen instead of an error.

#![no_std]
#![no_main]

use a9boot_core::abi::{self, record, status, Command, Descriptor, Mailbox, Reply};
use a9boot_core::layout::*;
use core::panic::PanicInfo;

mod asm;
mod el;

/// The payload is entered with `x0 = command`, `x1 = descriptor PA`, `x2 = reply PA`.
///
/// `x7` holds the first 8 bytes of our own image (the handler loads `[base+0x48]` into it) and
/// `x8` holds our entry address, so neither is an argument. `asm::_start` has already switched
/// to our own stack before this prologue runs.
#[no_mangle]
pub extern "C" fn a9boot_main(cmd: u64, descriptor_pa: u64, reply_pa: u64) -> u64 {
    let (reply, code) = run(cmd, descriptor_pa, slot_from_header());
    write_reply(reply_pa, &reply);
    code
}

/// `x3` at entry: the handler loads `x0..x6` from the command header, so `x3` is
/// `[header + 0x28]` — the host's second argument word. Read before anything clobbers it.
///
/// `_start` deliberately does not touch `x3`, so reading it here in the prologue is exact.
#[inline(always)]
fn slot_from_header() -> u64 {
    let v: u64;
    // SAFETY: `x3` still holds what the resident handler loaded for us; nothing has written it.
    unsafe { core::arch::asm!("mov {}, x3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// The entry-state anchor (`LOADER-FILL.md` §12 step 1).
///
/// Windows 0..3 are the entry registers `x9..x30`, the incoming `SP`, `SPSR_EL3` and `ELR_EL3`,
/// as `_start` saved them before any Rust code ran. Windows 3 and up read `ANCHOR_WORDS * 8`
/// bytes of the *handler's* stack at `SP + (slot - 3) * 96` — the 4 KiB dump §12 asks for, without
/// the payload guessing an address: the address is the stack pointer the ROM itself was using.
fn anchor(slot: u64) -> (Reply, u64) {
    let regs = unsafe { &*core::ptr::addr_of!(crate::asm::__anchor_regs) };
    let mut words = [0u64; abi::ANCHOR_WORDS];
    if slot < abi::ANCHOR_REG_WINDOWS {
        for (i, w) in words.iter_mut().enumerate() {
            *w = regs[(slot as usize) * abi::ANCHOR_WORDS + i];
        }
    } else {
        let sp = regs[22]; // the handler's SP, saved at offset 176
        let base = sp + (slot - abi::ANCHOR_REG_WINDOWS) * (abi::ANCHOR_WORDS as u64 * 8);
        // SAFETY: reading the ROM's own stack, which is mapped by definition — it is in use.
        for (i, w) in words.iter_mut().enumerate() {
            *w = unsafe { core::ptr::read_volatile((base + (i as u64) * 8) as *const u64) };
        }
    }
    let mut r = Reply { command: Command::Anchor as u64, status: status::OK, detail: slot, ..Default::default() };
    // The window travels in the reply's tail fields; the host reads them by name.
    r.esr_el1 = words[0];
    r.sctlr_el1 = if words.len() > 1 { words[1] } else { 0 };
    r.cntfrq_el0 = if words.len() > 2 { words[2] } else { 0 };
    r.mpidr_el1 = if words.len() > 3 { words[3] } else { 0 };
    r.midr_el1 = if words.len() > 4 { words[4] } else { 0 };
    r.cptr_el3 = if words.len() > 5 { words[5] } else { 0 };
    r.tcr_el3 = if words.len() > 6 { words[6] } else { 0 };
    r.ttbr0_el3 = if words.len() > 7 { words[7] } else { 0 };
    r.sctlr_el3 = if words.len() > 8 { words[8] } else { 0 };
    r.scr_el3 = if words.len() > 9 { words[9] } else { 0 };
    r.current_el = if words.len() > 10 { words[10] } else { 0 };
    r.status = status::OK;
    let _ = words[11];
    (r, status::OK)
}

fn run(cmd: u64, descriptor_pa: u64, slot: u64) -> (Reply, u64) {
    let command = match Command::from_u64(cmd) {
        Some(c) => c,
        None => {
            return (
                Reply { command: cmd, status: status::BAD_COMMAND, ..Default::default() },
                status::BAD_COMMAND,
            )
        }
    };

    match command {
        Command::Ping => {
            // Proves the payload ran, from where, and on which core. `current_el` should read
            // 0xc (EL3) — the first thing that makes the EL claim a measurement.
            let (el, scr, _, ttbr0_el3, _, _, midr, mpidr, cntfrq, sctlr1) = el::describe_fields();
            let r = Reply {
                command: cmd,
                status: status::OK,
                current_el: el,
                scr_el3: scr,
                ttbr0_el3,
                midr_el1: midr,
                mpidr_el1: mpidr,
                cntfrq_el0: cntfrq,
                sctlr_el1: sctlr1,
                ..Default::default()
            };
            (r, status::OK)
        }
        Command::Describe => {
            // The whole exception-level picture, so U-3 and U-4 in UNVERIFIED.md are answered
            // with data instead of an assumption.
            let (el, scr, sctlr3, ttbr0_el3, tcr3, cptr3, midr, mpidr, cntfrq, sctlr1) =
                el::describe_fields();
            let r = Reply {
                command: cmd,
                status: status::OK,
                current_el: el,
                scr_el3: scr,
                sctlr_el3: sctlr3,
                ttbr0_el3,
                tcr_el3: tcr3,
                cptr_el3: cptr3,
                midr_el1: midr,
                mpidr_el1: mpidr,
                cntfrq_el0: cntfrq,
                sctlr_el1: sctlr1,
                ..Default::default()
            };
            (r, status::OK)
        }
        Command::Anchor => anchor(slot),
        Command::Prepare | Command::Go => match load_and_check(descriptor_pa) {
            Err((code, detail)) => {
                (Reply { command: cmd, status: code, detail, ..Default::default() }, code)
            }
            Ok(d) => {
                if command == Command::Prepare {
                    // A dry run of every check that GO will perform, with nothing irreversible.
                    // Returns the descriptor's own numbers so the host can compare them against
                    // what it planned, byte for byte.
                    let r = Reply {
                        command: cmd,
                        status: status::OK,
                        detail: d.image_size,
                        scr_el3: d.dtb_addr,
                        sctlr_el3: d.vectors_addr,
                        ttbr0_el3: d.stack_top,
                        tcr_el3: d.kernel_entry,
                        cptr_el3: d.flags,
                        ..Default::default()
                    };
                    (r, status::OK)
                } else {
                    go(&d)
                }
            }
        },
    }
}

/// Read and validate the descriptor. Every failure is a *named* status, so a refusal on the
/// device never looks like a hang.
fn load_and_check(descriptor_pa: u64) -> core::result::Result<Descriptor, (u64, u64)> {
    if descriptor_pa == 0 || descriptor_pa % 8 != 0 {
        return Err((status::BAD_ALIGNMENT, descriptor_pa));
    }
    // SAFETY: the host placed a DESCRIPTOR_SIZE-byte struct at this physical address and cleaned
    // it to the PoC. The read happens at EL3 through the ROM's translation, which is why the
    // host probes DRAM reachability before issuing PREPARE or GO.
    let bytes = unsafe {
        core::slice::from_raw_parts(descriptor_pa as *const u8, abi::DESCRIPTOR_SIZE)
    };
    let d = Descriptor::decode(bytes).map_err(|e| (status::BAD_DESCRIPTOR_FIELD, e.detail))?;
    d.validate()?;
    Ok(d)
}

/// The point of no return. Never returns: either `eret` to Non-secure EL1, or a recorded failure
/// and a parked core.
fn go(d: &Descriptor) -> (Reply, u64) {
    // SAFETY: `d` has been validated. The mailbox and vector destinations are inside the reserved
    // loader area; the ranges cleaned are the blobs the host staged.
    unsafe {
        // 1. The vector block, copied to DRAM so that a fault at EL1 *after* the handoff is
        //    recorded somewhere the host can still read. The block is written to be
        //    position-independent precisely so this copy is valid (see `asm.rs`).
        let vectors_len = asm::install_vectors(d.vectors_addr);
        if vectors_len > VECTORS_SIZE {
            return (
                Reply { command: Command::Go as u64, status: status::OUT_OF_RANGE, detail: vectors_len, ..Default::default() },
                status::OUT_OF_RANGE,
            );
        }

        // 2. Everything the kernel will read must be cleaned to the PoC, because the ROM's
        //    `memcpy` may have left it in a cache the kernel is about to disable.
        el::clean_to_poc(d.dtb_addr, d.dtb_size);
        el::clean_to_poc(d.image_addr, d.image_size);
        if d.flags & abi::flags::INITRD_PRESENT != 0 {
            el::clean_to_poc(d.initrd_addr, d.initrd_size);
        }
        el::clean_to_poc(d.vectors_addr, vectors_len);
        el::clean_to_poc(d.mailbox_addr, abi::MAILBOX_SIZE as u64);
        // The spin-table mailbox must be zero before the kernel looks at it (booting.rst:
        // "a naturally-aligned 64-bit zero-initalised memory location"), and it is inside the
        // loader area, so zero it here rather than trusting whatever the DRAM powered up with.
        if d.spin_addr != 0 {
            core::ptr::write_volatile(d.spin_addr as *mut u64, 0);
            el::clean_to_poc(d.spin_addr, 8);
        }
        el::invalidate_icache();

        // 3. The handoff record, written *before* the eret so that "we jumped" and "we died on
        //    entry" are distinguishable in the mailbox rather than being the same silence.
        let cntfrq = el::ensure_cntfrq();
        let (cur_el, scr, sctlr3, ttbr0_3, tcr3, cptr3, midr, mpidr, _, sctlr1) = el::describe_fields();
        let m = Mailbox {
            magic: abi::MAILBOX_MAGIC,
            kind: record::HANDOFF,
            detail: Command::Go as u64,
            cntfrq_el0: cntfrq,
            scr_el3: scr,
            current_el: cur_el,
            sctlr_el3: sctlr3,
            ttbr0_el3: ttbr0_3,
            tcr_el3: tcr3,
            cptr_el3: cptr3,
            midr_el1: midr,
            mpidr_el1: mpidr,
            elr_el1: d.kernel_entry,
            ..Default::default()
        };
        el::write_mailbox(&m);
        let _ = sctlr1;

        // 4. Go. This does not return.
        el::enter_el1(d)
    }
}

/// Copy a reply into the reply area the handler sends back. Must not exceed `REPLY_CAP`, or it
/// would reach into the payload's own code (`a9boot_core::abi` asserts the geometry).
fn write_reply(reply_pa: u64, r: &Reply) {
    if reply_pa == 0 {
        return;
    }
    let bytes = r.encode();
    debug_assert!(bytes.len() as u64 <= abi::REPLY_CAP);
    // SAFETY: `reply_pa` is the reply area inside the DFU buffer, passed by the handler.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), reply_pa as *mut u8, bytes.len());
    }
}

/// A Rust panic is a bug in the payload, and on this device a bug must still be *visible*. Record
/// it where the host can read it and park, rather than spinning in the default handler.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let detail = info
        .location()
        .map(|l| ((l.line() as u64) << 16) | (l.column() as u64 & 0xffff))
        .unwrap_or(0);
    let m = Mailbox {
        magic: abi::MAILBOX_MAGIC,
        kind: record::PAYLOAD_PANIC,
        detail,
        current_el: el::current_el(),
        ..Default::default()
    };
    // SAFETY: writing a fixed-size record into the reserved loader area.
    unsafe {
        el::write_mailbox(&m);
    }
    loop {
        core::hint::spin_loop();
    }
}
