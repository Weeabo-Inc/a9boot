//! System registers, cache maintenance, and the EL3 → Non-secure EL1 transition.
//!
//! Everything in this file is `asm!` for one of exactly three reasons, stated at each site:
//! there is no Rust intrinsic for a system register, none for cache/TLB maintenance, and none
//! for `eret` — the only instruction that changes exception level.
//!
//! ## The EL question, in one paragraph
//!
//! The payload arrives at **EL3, AArch64, with the ROM's MMU on** — evidence: the exploit
//! payload that places us executes `tlbi alle3` and edits the page-table entry at
//! `ttbr0_vrom_addr` (`research/refs/gaster/payload_A9.S:59-64`), both of which are only
//! meaningful at EL3. Linux must be entered at **Non-secure EL1** (booting.rst: "The CPU must be
//! in non-secure state, either in EL2 … or in EL1"; A9 implements no EL2 — `s800-0-3.dtsi:299`).
//!
//! The trap is that `TTBR0_EL1`, `SCTLR_EL1`, `TCR_EL1`, `MAIR_EL1`, `VBAR_EL1` and `SP_EL1` are
//! **banked by security state**. Writing them while `SCR_EL3.NS = 0` writes the *secure* copies,
//! and the `eret` would then run on the *non-secure* copies — whatever they happened to hold.
//! So the order is: set `NS = 1` first, then write the EL1 registers, then `eret`.
//!
//! `SCR_EL3.FIQ` is read and **never modified**: booting.rst requires it to be the same value at
//! kernel entry as at boot, and on every CPU. Whether that boot-time value lets the A9's
//! FIQ-routed arch-timer interrupts (`s800-0-3.dtsi:295-302` uses `AIC_FIQ`) reach EL1 is
//! UNVERIFIED (U-3) — which is exactly what the `DESCRIBE` command reports `SCR_EL3` for.

use crate::asm::a9boot_el1_stub;
use a9boot_core::abi::Descriptor;
use core::arch::asm;

/// `SCTLR_EL1` with the MMU **off** and the D-cache off, plus the two RES1 bits (11 and 20) that
/// the architecture marks as reserved-1. booting.rst: "The MMU must be off."
///
/// This is the opposite of what an OS with its own VA space needs (m1n1's requirement, HANDOFF
/// §4) and exactly what a Linux kernel that maps itself from scratch expects.
pub const SCTLR_EL1_MMU_OFF: u64 = (1 << 11) | (1 << 20);

/// `CPACR_EL1.FPEN = 0b11`: do not trap FP/SIMD at EL0/EL1. Linux re-initialises this itself; the
/// value is here so the kernel never starts from an unknown bit pattern.
pub const CPACR_EL1_FPEN: u64 = 0b11 << 20;

/// `SPSR_EL3` for the `eret`: return to **EL1h** (M[3:0] = 0b0101, i.e. use `SP_EL1`) with
/// D, A, I and F all masked (bits 9..6), and M[4] = 0 (AArch64).
///
/// booting.rst: "All forms of interrupts must be masked in PSTATE.DAIF." `SP_EL1` is set below,
/// because `stext` executes `bl preserve_boot_args` before it installs its own stack.
pub const SPSR_EL1H_DAIF_MASKED: u64 = 0x3C5;

/// `CNTFRQ_EL0` fallback: the DT's fixed reference clock (`s800-0-3.dtsi:21-26`, 24 MHz).
/// booting.rst requires the frequency to be programmed; it is only written if it reads as 0,
/// because overwriting a frequency the ROM already set would be worse than useless.
pub const CNTFRQ_FALLBACK: u64 = 24_000_000;

/// A9 (Twister) cache line, used to step `dc cvac` across a range.
pub const CACHE_LINE: u64 = 64;

macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        // SAFETY: reading an architecturally-defined system register at EL3. No memory is
        // touched, the stack is not used, and no flags are affected.
        unsafe {
            asm!(concat!("mrs {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags));
        }
        v
    }};
}

pub fn current_el() -> u64 {
    read_sysreg!("currentel")
}
pub fn scr_el3() -> u64 {
    read_sysreg!("scr_el3")
}
pub fn sctlr_el3() -> u64 {
    read_sysreg!("sctlr_el3")
}
pub fn ttbr0_el3() -> u64 {
    read_sysreg!("ttbr0_el3")
}
pub fn tcr_el3() -> u64 {
    read_sysreg!("tcr_el3")
}
pub fn cptr_el3() -> u64 {
    read_sysreg!("cptr_el3")
}
pub fn sctlr_el1() -> u64 {
    read_sysreg!("sctlr_el1")
}
pub fn cntfrq_el0() -> u64 {
    read_sysreg!("cntfrq_el0")
}
pub fn midr_el1() -> u64 {
    read_sysreg!("midr_el1")
}
pub fn mpidr_el1() -> u64 {
    read_sysreg!("mpidr_el1")
}

/// Clean a physical range to the Point of Coherency, line by line.
///
/// booting.rst: "The address range corresponding to the loaded kernel image must be cleaned to
/// the PoC." Every blob staged through the ROM's `memcpy` went through the ROM's EL3 mapping,
/// which may be cacheable, so a `dc cvac` per line is what makes those writes visible to a CPU
/// that is about to run with its data cache off.
///
/// On a range the ROM mapped as Device-nGnRnE this is a no-op; on one it mapped cacheable it is
/// load-bearing. Doing it unconditionally costs a few milliseconds over a 16 MiB image and
/// removes the need to know which case we are in.
///
/// # Safety
/// `start`/`len` must describe memory mapped in the current (EL3) translation regime.
pub unsafe fn clean_to_poc(start: u64, len: u64) {
    if len == 0 {
        return;
    }
    let mut a = start & !(CACHE_LINE - 1);
    let end = start + len;
    while a < end {
        // No intrinsic exists for cache maintenance; `dc cvac` is "clean by VA to PoC".
        asm!("dc cvac, {0}", in(reg) a, options(nostack, preserves_flags));
        a += CACHE_LINE;
    }
    asm!("dsb sy", options(nostack, preserves_flags));
}

/// Invalidate the instruction cache, inner shareable.
///
/// booting.rst: the I-cache "must not hold any stale entries corresponding to the loaded kernel
/// image". The image was written by data accesses to addresses we are about to execute from, so
/// the I-cache is invalidated wholesale rather than pretended away.
///
/// # Safety
/// Instruction-cache maintenance has no Rust intrinsic. Safe to call at EL3.
pub unsafe fn invalidate_icache() {
    asm!("ic ialluis", options(nostack, preserves_flags));
    asm!("dsb sy", options(nostack, preserves_flags));
    asm!("isb", options(nostack, preserves_flags));
}

/// Write `CNTFRQ_EL0` if the ROM left it at zero. Returns the value that was in it on entry.
///
/// booting.rst: "CNTFRQ must be programmed with the timer frequency and CNTVOFF must be
/// programmed with a consistent value on all CPUs."
///
/// # Safety
/// EL3 is the only level that may write `CNTFRQ_EL0` when EL3 is implemented.
pub unsafe fn ensure_cntfrq() -> u64 {
    let v = cntfrq_el0();
    if v == 0 {
        asm!("msr cntfrq_el0, {0}", in(reg) CNTFRQ_FALLBACK, options(nostack, preserves_flags));
        CNTFRQ_FALLBACK
    } else {
        v
    }
}

/// The one-way transition: EL3 (secure, ROM MMU on) → Non-secure EL1 (MMU off), landing in
/// [`crate::asm::a9boot_el1_stub`] rather than directly in the kernel.
///
/// Going through our own stub buys one thing worth having: the stub **reads back** `SCTLR_EL1`,
/// `VBAR_EL1` and `TTBR0_EL1` and, if they are not what EL3 wrote, records
/// `record::EL1_STATE_UNEXPECTED` in the mailbox and parks instead of jumping into the kernel in
/// an unknown state. The banked-register assumption in this file is the design's riskiest
/// architectural claim, and this is what makes it measurable rather than trusted (U-4).
///
/// # Safety
/// Called once, with a validated descriptor, from the payload's `GO` command. Does not return.
pub unsafe fn enter_el1(d: &Descriptor) -> ! {
    // 1. Preserve SCR_EL3 and set only NS. booting.rst requires SCR_EL3.FIQ to keep its
    //    boot-time value; every other bit is the ROM's business, not ours.
    let scr = scr_el3();
    let scr_ns = (scr & !1u64) | 1u64;
    asm!("msr scr_el3, {0}", in(reg) scr_ns, options(nostack, preserves_flags));

    // 2. From here, EL1 system registers are the NON-SECURE bank.
    asm!("msr sctlr_el1, {0}", in(reg) SCTLR_EL1_MMU_OFF, options(nostack, preserves_flags));
    asm!("msr ttbr0_el1, xzr", options(nostack, preserves_flags));
    asm!("msr ttbr1_el1, xzr", options(nostack, preserves_flags));
    asm!("msr tcr_el1, xzr", options(nostack, preserves_flags));
    asm!("msr mair_el1, xzr", options(nostack, preserves_flags));
    asm!("msr vbar_el1, {0}", in(reg) d.vectors_addr, options(nostack, preserves_flags));
    asm!("msr cpacr_el1, {0}", in(reg) CPACR_EL1_FPEN, options(nostack, preserves_flags));
    asm!("msr sp_el1, {0}", in(reg) d.stack_top, options(nostack, preserves_flags));

    // 3. Return address and PSTATE for the eret.
    asm!("msr spsr_el3, {0}", in(reg) SPSR_EL1H_DAIF_MASKED, options(nostack, preserves_flags));
    asm!("msr elr_el3, {0}", in(reg) a9boot_el1_stub as *const () as u64, options(nostack, preserves_flags));

    // 4. eret, with the stub's arguments in fixed registers.
    //
    //    Explicit registers, not `in(reg)`: the compiler may allocate the same register to two
    //    `in(reg)` operands, and then the first `mov` would destroy the second's value. x4..x7
    //    are distinct, caller-saved, and not the kernel's argument registers.
    //
    //    Note there is deliberately no `msr daifset` here. The mask the kernel requires comes
    //    from SPSR_EL3 above; masking at EL3 as well would risk disabling the ROM's USB
    //    interrupts, and whether DAIF is banked per-EL is not something this design should
    //    depend on (U-10, and why the post-handoff mailbox is labelled best-effort).
    asm!(
        "mov x0, x4",
        "mov x1, x5",
        "mov x2, x6",
        "mov x3, x7",
        "dsb sy",
        "isb",
        "eret",
        in("x4") d.dtb_addr,
        in("x5") d.vectors_addr,
        in("x6") d.stack_top,
        in("x7") d.kernel_entry,
        options(noreturn)
    );
}

/// Write a telemetry record to the mailbox and clean it to the PoC.
///
/// # Safety
/// `MAILBOX_ADDR` must be inside the loader area, which is reserved and never handed to the
/// kernel (`layout::check` asserts it is at the top of DRAM, outside the memory the kernel gets
/// from `/memory` only in the sense that it is reserved — see DESIGN.md §3.2).
pub unsafe fn write_mailbox(m: &a9boot_core::abi::Mailbox) {
    let dst = a9boot_core::layout::MAILBOX_ADDR as *mut u8;
    let bytes = m.encode();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
    // The host reads this back through the ROM's EL3 mapping, which may be cacheable: clean it,
    // or the host may read a stale line rather than the record.
    clean_to_poc(a9boot_core::layout::MAILBOX_ADDR, bytes.len() as u64);
}

/// Fill in the exception-level picture, for the `DESCRIBE` reply and for the mailbox record.
pub fn describe_fields() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        current_el(),
        scr_el3(),
        sctlr_el3(),
        ttbr0_el3(),
        tcr_el3(),
        cptr_el3(),
        midr_el1(),
        mpidr_el1(),
        cntfrq_el0(),
        sctlr_el1(),
    )
}
