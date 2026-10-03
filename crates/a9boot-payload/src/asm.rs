//! Assembly that cannot be expressed in Rust, in one place, with the reason for each block.
//!
//! There are no `.S` files in this repository. These are `global_asm!` blocks inside Rust, which
//! keeps the payload a single-language artefact and keeps the reasons next to the code.
//!
//! Three blocks need assembly, and only three:
//!
//! 1. **`_start`** — the payload is entered by a `blr` from the ROM's DFU handler with the ROM's
//!    `SP` of unknown depth. The first thing that must happen is a switch to our own stack,
//!    before any Rust prologue writes to memory. Only assembly can run before the prologue.
//! 2. **The EL1 exception vector block** — `VBAR_EL1` requires a 2 KiB-aligned table of sixteen
//!    0x80-byte entries, copied verbatim to a fixed address. A contiguous, position-independent,
//!    alignment-exact block is exactly what a linker/assembler produces and what Rust cannot
//!    express. Its handler uses only `mov` immediates and PC-relative branches, so the copy is
//!    valid at any address — which is what makes the post-handoff fault mailbox possible.
//! 3. **The EL1 stub** — the first instructions executed after `eret`, at Non-secure EL1 with the
//!    MMU off. It must not touch the stack before setting it, and it must check that the EL1
//!    register writes made from EL3 actually landed (see DESIGN.md §4.3, UNVERIFIED.md U-4).

use core::arch::global_asm;

/// The entry-state anchor: 25 words written by `_start` before any Rust code runs.
///
/// This is a *definition* the linker places inside the payload image, so the host does not have to
/// know its address: `ANCHOR` returns the words through the reply area instead.
#[no_mangle]
pub static mut __anchor_regs: [u64; 25] = [0; 25];

// ---------------------------------------------------------------------------------------
// 1. Entry
// ---------------------------------------------------------------------------------------

global_asm!(
    r#"
    .section .text._start, "ax"
    .balign 16
    .global _start
    // Entered with x0 = command, x1 = descriptor PA, x2 = reply PA, from the ROM's EL3 handler.
    // x7 holds the first 8 bytes of our own image (the handler loads [base+0x48] into it) and is
    // therefore garbage as an argument: we never read it. Neither do we read x8, which is our
    // own entry address.
_start:
    // The entry-state anchor (LOADER-FILL.md §12 step 1). Saved BEFORE anything else, because
    // after the first Rust store the handler's registers are gone. `x0..x8` are the handler's
    // arguments (x0..x7 from the command header, x8 our entry address), so they are already known
    // to the host; what is NOT known is `x9..x30` (the ROM's own leftovers), the stack pointer the
    // handler was using, and where it will return to. Those are the anchor.
    adrp    x11, __anchor_regs
    add     x11, x11, :lo12:__anchor_regs
    stp     x9,  x10, [x11, #0]
    stp     x11, x12, [x11, #16]        // x11/x12 still hold the ROM's values here
    stp     x13, x14, [x11, #32]
    stp     x15, x16, [x11, #48]
    stp     x17, x18, [x11, #64]
    stp     x19, x20, [x11, #80]
    stp     x21, x22, [x11, #96]
    stp     x23, x24, [x11, #112]
    stp     x25, x26, [x11, #128]
    stp     x27, x28, [x11, #144]
    stp     x29, x30, [x11, #160]
    mov     x12, sp
    str     x12, [x11, #176]            // the handler's SP at the moment of the `blr`
    mrs     x12, spsr_el3
    str     x12, [x11, #184]
    mrs     x12, elr_el3
    str     x12, [x11, #192]            // where EL3 will resume: the ROM's own ELR
    adrp    x9, __stack_top
    add     x9, x9, :lo12:__stack_top
    mov     sp, x9                      // our stack, inside our own image, in the DFU buffer
    adrp    x10, __bss_start
    add     x10, x10, :lo12:__bss_start
    adrp    x11, __bss_end
    add     x11, x11, :lo12:__bss_end
1:  cmp     x10, x11
    b.hs    2f
    strb    wzr, [x10], #1              // .bss is NOT in the delivered image: zero it here
    b       1b
2:  b       a9boot_main                 // tail call: x0, x1, x2 are untouched
"#
);

// ---------------------------------------------------------------------------------------
// 2. The EL1 vector block
// ---------------------------------------------------------------------------------------

global_asm!(
    r#"
    .section .rodata.a9boot_vectors, "a"
    .balign 2048
    .global a9boot_vectors_start
    .global a9boot_vectors_end

    // Sixteen entries, 0x80 bytes each. Every entry branches to the single handler below, which
    // sits immediately after the table, so the branch offsets survive being copied.
    // The entry that matters here is offset 0x200 ("Current EL with SP_ELx", synchronous): with
    // SPSR_EL3.M[0] = 1 the kernel runs on SP_EL1, so a fault at EL1 lands there.
a9boot_vectors_start:
    .rept 16
    b       a9boot_vector_handler
    .balign 0x80
    .endr

a9boot_vector_handler:
    // EL1 faulted. Record everything that identifies it and park. Only absolute immediates and
    // PC-relative branches are used, so this code is valid wherever it is copied to.
    mrs     x0, esr_el1
    mrs     x1, far_el1
    mrs     x2, elr_el1
    mrs     x3, spsr_el1
    // `mov xN, #imm64` is not a real instruction and the integrated assembler does not expand it,
    // so the two constants are built with explicit movz/movk pairs. `a9boot-host` has a test that
    // pins these two values against layout::MAILBOX_ADDR and abi::MAILBOX_MAGIC, so a layout
    // change breaks the test rather than breaking the mailbox silently.
    movz    x9, #0x1000                 // layout::MAILBOX_ADDR = 0x8_7FE1_1000
    movk    x9, #0x7FE1, lsl #16
    movk    x9, #0x0008, lsl #32
    movz    x10, #0x4D42                // abi::MAILBOX_MAGIC = 0x4139424F4F544D42
    movk    x10, #0x4F54, lsl #16
    movk    x10, #0x424F, lsl #32
    movk    x10, #0x4139, lsl #48
    str     x10, [x9]
    mov     x10, #2                     // abi::record::EL1_FAULT
    str     x10, [x9, #8]
    str     x0, [x9, #0x18]             // Mailbox::esr_el1
    str     x1, [x9, #0x20]             // Mailbox::far_el1
    str     x2, [x9, #0x28]             // Mailbox::elr_el1
    str     x3, [x9, #0x30]             // Mailbox::spsr_el1
    dsb     sy
3:  wfi
    b       3b

a9boot_vectors_end:
"#
);

// ---------------------------------------------------------------------------------------
// 3. The EL1 stub
// ---------------------------------------------------------------------------------------

global_asm!(
    r#"
    .section .text.a9boot_el1_stub, "ax"
    .balign 4
    .global a9boot_el1_stub
    // Entered by `eret` from EL3, at Non-secure EL1, MMU off.
    //   x0 = device tree physical address   (kept for the kernel)
    //   x1 = VBAR_EL1 we asked for
    //   x2 = stack top we asked for
    //   x3 = kernel entry
    // No stack is touched before SP_EL1 is set, and no memory is read at all.
a9boot_el1_stub:
    msr     sp_el1, x2
    mrs     x9, sctlr_el1
    tbnz    x9, #0, a9boot_el1_bad     // SCTLR_EL1.M set: the EL3 write did not reach this bank
    mrs     x9, vbar_el1
    cmp     x9, x1
    b.ne    a9boot_el1_bad
    mrs     x9, ttbr0_el1
    cbnz    x9, a9boot_el1_bad
    mov     x16, x3                    // kernel entry
    mov     x1, xzr                    // booting.rst: x1 = x2 = x3 = 0 at kernel entry
    mov     x2, xzr
    mov     x3, xzr
    dsb     sy
    isb
    br      x16                        // x0 still holds the device tree address

a9boot_el1_bad:
    // The EL1 register state is not what EL3 wrote. Say so where the host can read it, and park:
    // jumping to the kernel in an unknown state would be indistinguishable from a kernel bug.
    movz    x9, #0x1000                 // layout::MAILBOX_ADDR
    movk    x9, #0x7FE1, lsl #16
    movk    x9, #0x0008, lsl #32
    movz    x10, #0x4D42                // abi::MAILBOX_MAGIC
    movk    x10, #0x4F54, lsl #16
    movk    x10, #0x424F, lsl #32
    movk    x10, #0x4139, lsl #48
    str     x10, [x9]
    mov     x10, #4                     // abi::record::EL1_STATE_UNEXPECTED
    str     x10, [x9, #8]
    mrs     x11, sctlr_el1
    str     x11, [x9, #0x18]            // Mailbox::esr_el1 slot: SCTLR_EL1 as actually read
    mrs     x11, vbar_el1
    str     x11, [x9, #0x20]            // Mailbox::far_el1 slot: VBAR_EL1 as actually read
    dsb     sy
4:  wfi
    b       4b
"#
);

extern "C" {
    pub static a9boot_vectors_start: u8;
    pub static a9boot_vectors_end: u8;
    /// The Non-secure EL1 entry point. `eret` targets this, not the kernel.
    pub fn a9boot_el1_stub();
}

/// The vector block's length in bytes. `VBAR_EL1` needs the 2 KiB table; the handler (which the
/// stub and the table both need) follows it.
pub fn vector_block_len() -> u64 {
    let start = core::ptr::addr_of!(a9boot_vectors_start) as u64;
    let end = core::ptr::addr_of!(a9boot_vectors_end) as u64;
    end - start
}

/// Copy the vector block to `dst` (which must be 2 KiB aligned: `layout::VECTORS_ADDR`).
///
/// A byte copy of code is only ever safe when the code is position independent — this block is
/// written that way on purpose, using `mov` immediates and PC-relative branches only, because
/// the copy destination is 1.7 GiB away from the source and any absolute reference would break.
pub unsafe fn install_vectors(dst: u64) -> u64 {
    let start = core::ptr::addr_of!(a9boot_vectors_start) as *const u8;
    let len = vector_block_len() as usize;
    let d = dst as *mut u8;
    core::ptr::copy_nonoverlapping(start, d, len);
    len as u64
}
