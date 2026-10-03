//! The A9 physical map, and every address a9boot places something at.
//!
//! **This module is the single source of truth for layout.** The payload's linker script is
//! generated from it (`a9boot-payload/build.rs`), the host's plan is computed from it, and
//! the design document quotes it. A value written twice is a value that will disagree.
//!
//! ## The one number that matters most
//!
//! `DRAM_BASE` is `0x8_0000_0000` — **34-bit, not `0x8000_0000`**. Two independent
//! confirmations, both INSPECTED:
//!
//! * `a9linux/dts/ref/dts/s800-0-3-common.dtsi:33` names the node `memory@800000000`, and the
//!   tree's `#address-cells = <2>`, so `reg = <0x8 0 0 0>` addresses `0x8_0000_0000`.
//! * `s800-0-3.dtsi:138`: `dma-ranges = <0x0 0x00000000 0x8 0x00000000 0x1 0x00000000>` — the
//!   USB complex's 32-bit DMA view of `0x0_00000000` is physical `0x8_00000000`.
//!
//! HANDOFF §8 exists because of mistakes of exactly this shape.

use crate::{align_up, Error, Result};

// ---------------------------------------------------------------------------------------
// DRAM
// ---------------------------------------------------------------------------------------

/// DRAM base. **INSPECTED** — see the module docs. Not `0x8000_0000`.
pub const DRAM_BASE: u64 = 0x8_0000_0000;

/// DRAM size. **INFERRED** — iPhone SE 1st gen has 2 GB.
/// Falsified by `PROBE_DRAM` in `UNVERIFIED.md` (U-2): a write/read round trip at
/// `+0`, `+1 GiB`, `+2 GiB - 8` and `+2 GiB + 0x1000`.
pub const DRAM_SIZE: u64 = 0x8000_0000;

/// booting.rst: an initrd "must reside entirely within a 1 GB aligned physical memory
/// window of up to 32 GB in size that fully covers the kernel Image as well."
pub const WINDOW_SIZE: u64 = 0x4000_0000;

/// 2 MiB. The unit that matters to the arm64 kernel: the Image is placed at
/// `text_offset` from a 2 MiB aligned base, and the DTB must not share a 2 MiB region
/// with something mapped with specific attributes.
pub const TWO_MIB: u64 = 0x0020_0000;

// ---------------------------------------------------------------------------------------
// The four blob regions, from the bottom of DRAM up
// ---------------------------------------------------------------------------------------

/// Device tree blob. At the very base of DRAM, in its own 2 MiB region.
/// booting.rst: "The device tree blob (dtb) must be placed on an 8-byte boundary and must not
/// exceed 2 megabytes in size. Since the dtb will be mapped cacheable using blocks of up to
/// 2 megabytes in size, it must not be placed within any 2M region which must be mapped with
/// any specific attributes."
pub const DTB_ADDR: u64 = DRAM_BASE;
/// The DTB's own 2 MiB region. Also the hard limit on the edited DTB's size.
pub const DTB_REGION_SIZE: u64 = TWO_MIB;

/// 2 MiB aligned base for the kernel Image. booting.rst: "The Image must be placed
/// text_offset bytes from a 2MB aligned base address anywhere in usable system RAM and called
/// there." `text_offset` comes from the Image header and is never assumed — see `image.rs`.
pub const IMAGE_2M_BASE: u64 = DRAM_BASE + TWO_MIB;

/// Alignment for the initrd. Not required by the protocol; 64 KiB keeps it page-aligned for
/// every arm64 page size this project could ever use.
pub const INITRD_ALIGN: u64 = 0x1_0000;

// ---------------------------------------------------------------------------------------
// Framebuffer (rung 2)
// ---------------------------------------------------------------------------------------

/// Panel is 640x1136 (**INSPECTED** — `a9linux/briefs/*`, and the panel size HANDOFF §4
/// names for this device).
pub const FB_WIDTH: u32 = 640;
pub const FB_HEIGHT: u32 = 1136;
/// 640 x 4 bytes. The format string below is 32-bit, so stride follows from width.
pub const FB_STRIDE: u32 = FB_WIDTH * 4;
/// **INFERRED.** The SE's panel is driven 32-bit; `a8r8g8b8` is the `simple-framebuffer`
/// binding's name for that byte order (`simple-framebuffer.yaml:100`).
/// Falsified by: a lit panel with wrong colours (rung 2). U-7.
pub const FB_FORMAT: &str = "a8r8g8b8";
/// The framebuffer must hold `stride * height` bytes.
pub const FB_MIN_SIZE: u64 = (FB_STRIDE as u64) * (FB_HEIGHT as u64);
/// 4 MiB: `FB_MIN_SIZE` (2,908,160) rounded up to a 2 MiB multiple.
pub const FB_SIZE: u64 = 0x40_0000;
/// Framebuffer base. Ours to choose, so it is chosen 4 MiB aligned, clear of the kernel's
/// window at the bottom and of the loader area at the top.
pub const FB_ADDR: u64 = 0x8_7800_0000;

// ---------------------------------------------------------------------------------------
// The loader area: 2 MiB at the top of DRAM, always reserved
// ---------------------------------------------------------------------------------------

pub const LOADER_AREA_BASE: u64 = 0x8_7FE0_0000;
pub const LOADER_AREA_SIZE: u64 = 0x0020_0000;

/// Where the payload's EL1 exception vector table is copied to. `VBAR_EL1` requires 2 KiB
/// alignment; the vector block is exactly 16 x 0x80 = 2 KiB, plus its handler.
pub const VECTORS_OFF: u64 = 0x0002_0000;
pub const VECTORS_SIZE: u64 = 0x1000;
pub const VECTORS_ADDR: u64 = LOADER_AREA_BASE + VECTORS_OFF;

/// Post-handoff telemetry: the only place a fault on the way into Linux can be recorded.
/// Read back by the host through the still-resident EL3 DFU handler (DESIGN.md §5.3).
pub const MAILBOX_OFF: u64 = 0x0001_1000;
pub const MAILBOX_SIZE: u64 = 0x1000;
pub const MAILBOX_ADDR: u64 = LOADER_AREA_BASE + MAILBOX_OFF;

/// Boot descriptor: the small struct the host writes and the payload validates.
pub const DESCRIPTOR_OFF: u64 = 0x0001_0000;
pub const DESCRIPTOR_SIZE: u64 = 0x1000;
pub const DESCRIPTOR_ADDR: u64 = LOADER_AREA_BASE + DESCRIPTOR_OFF;

/// The stack the payload hands to EL1. booting.rst does not mention a stack, but `stext`
/// does `bl preserve_boot_args` before it installs its own, so an unusable `SP_EL1` faults
/// immediately. See DESIGN.md §4.2.
pub const EL1_STACK_OFF: u64 = 0x0002_8000;
pub const EL1_STACK_SIZE: u64 = 0x4000;
pub const EL1_STACK_BOTTOM: u64 = LOADER_AREA_BASE + EL1_STACK_OFF;
pub const EL1_STACK_TOP: u64 = EL1_STACK_BOTTOM + EL1_STACK_SIZE;

/// `cpu-release-addr` for the spin-table secondaries (rung 2). booting.rst: "This property
/// identifies a naturally-aligned 64-bit zero-initalised memory location… which must be
/// contained in the reserved region."
pub const SPIN_MAILBOX_OFF: u64 = 0x0003_0000;
pub const SPIN_MAILBOX_ADDR: u64 = LOADER_AREA_BASE + SPIN_MAILBOX_OFF;

// ---------------------------------------------------------------------------------------
// The payload's own footprint, inside the DFU buffer
// ---------------------------------------------------------------------------------------

/// The payload's private stack, in `.bss` immediately after its image, inside the DFU buffer.
///
/// It must be the payload's *own* stack: on entry `SP` is the ROM's, of unknown size and
/// unknown remaining depth, and the handler calls us with `blr`. A 2 KiB stack is plenty for a
/// payload with no allocation and no recursion.
pub const PAYLOAD_STACK_SIZE: u64 = 0x800;

/// Hard budget for `image (text+rodata+data) + .bss + stack` — everything the command transfer
/// has to carry and the DFU buffer has to hold.
///
/// **MEASURED**: the built payload is 10,640 bytes of image (`.text` + `.rodata` + the 2 KiB
/// vector block) plus a 2 KiB stack = ~13,016 bytes of total footprint, read from
/// `a9boot-payload.map`. 16 KiB leaves ~25% headroom for growth without pretending the limit is
/// unbounded, and it is two orders of magnitude below any plausible DFU buffer (the same buffer
/// carries a ~200 KiB iBSS in stock DFU — INFERRED, `UNVERIFIED.md` U-2).
///
/// Enforced three ways: a linker `ASSERT` inside the payload build, a host-side footprint check,
/// and the *probed* buffer capacity, below which the host refuses to stage anything.
pub const PAYLOAD_MAX_FOOTPRINT: u64 = 0x4000;

// ---------------------------------------------------------------------------------------
// The channel, which lives in SRAM and therefore in *someone else's* address space
// ---------------------------------------------------------------------------------------

/// The ROM's DFU buffer. **MEASURED by the Lead** via `a9pwn plan` on this device (the config
/// row for CPID 0x8003 prints `insecure_memory_base = 0x180380000`), and independently
/// **INSPECTED** here: `a9pwn/src/config.rs` ← `gaster.c:637`. Two independent sources agree.
///
/// This is where every command's bytes land, and where the resident checkm8 handler reads the
/// command struct from. The payload itself executes from inside this buffer (see
/// `abi::PAYLOAD_OFF`), which is why the payload needs no relocation.
pub const DFU_BUFFER_ADDR: u64 = 0x1_8038_0000;

/// The ROM's `memcpy`, callable through the handler's `MEMC_MAGIC` command.
/// **INSPECTED** — `a9pwn/src/config.rs` ← `gaster.c:629`.
pub const ROM_MEMCPY_ADDR: u64 = 0x1_0001_1030;

/// The resident checkm8 handler, copied there by the exploit payload.
/// `= boot_tramp_end - 192 - 56` (**INSPECTED** — `a9pwn/src/config.rs` ← `gaster.c:1111`;
/// HANDOFF §8.2 records that this is *not* ipwndfu's `0x1800E0C00`).
pub const HANDLER_ADDR: u64 = 0x1_800E_0F08;

/// SRAM extent, as far as anything here depends on it. **INFERRED** from the addresses the
/// ROM itself uses (`boot_tramp_end = 0x1_800E_1000`, DFU buffer `0x1_8038_0000`).
pub const SRAM_BASE: u64 = 0x1_8000_0000;

/// The boot ROM itself: `patch_addr`/`memcpy_addr` live at fixed offsets into it.
pub const VROM_BASE: u64 = 0x1_0000_0000;

// ---------------------------------------------------------------------------------------
// Where the kernel is told about our regions
// ---------------------------------------------------------------------------------------

/// Labels for the `/reserved-memory` children a9boot creates. The node *name* is
/// `<label>@<address>`, built by the host (`bundle::reservation_node_name`) — the label here is
/// the bare word, deliberately, so the unit-address cannot be written twice.
///
/// `a9linux/dts/LOADER-FILL.md` §10 requires a **plain** (not `no-map`) child for the
/// framebuffer, and the DTS carries an empty `reserved-memory` node marked
/// `/* To be filled by loader */` — so children are the contract's mechanism, not the FDT
/// memory-reservation block.
pub const RESERVED_MEMORY_CHILDREN: &[(&str, u64, u64)] = &[
    // (label, address, size)
    ("loader", LOADER_AREA_BASE, LOADER_AREA_SIZE),
    ("framebuffer", FB_ADDR, FB_SIZE),
    ("dtb", DTB_ADDR, DTB_REGION_SIZE),
];

// ---------------------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------------------

/// `wdt: watchdog@2102b0000` — **INSPECTED** `s800-0-3.dtsi:286-292`.
/// Whether it is armed when control reaches us is UNVERIFIED (U-8); iBoot normally arms it
/// and in this boot chain iBoot never ran.
pub const WDT_ADDR: u64 = 0x2_102B_0000;

/// UART0, `serial0`. **INSPECTED** `s800-0-3.dtsi:79-90`.
/// The DT admits its clocks are "the bootloader-enabled clocks for now", i.e. iBoot normally
/// opens that gate and on this boot path nobody has — a real loader obligation, U-6.
///
/// **Demoted in rung 1**: `a9linux/dts/CONSOLE-SIGNALS.md` Q1 establishes (INFERRED, high
/// confidence, from the Lightning pinout) that this UART is not reachable through the
/// connector. The code stays, the *dependency* does not.
pub const UART_ADDR: u64 = 0x2_0A0C_0000;

// ---------------------------------------------------------------------------------------
// USB: the AUSB PHY tunables, and the one placeholder dt-engineer found that everyone missed
// ---------------------------------------------------------------------------------------

/// The AUSB PHY node's base, `phy@20c000030` under `bus@20c000000`.
/// **MEASURED** in the built DTB (`LOADER-FILL.md` §7).
pub const AUSB_PHY_BASE: u64 = 0x2_0C00_0030;

/// `AUSB_CFG0` / `AUSB_CFG1`, **INSPECTED** — `drivers/phy/apple/ausb.c:31-32` (`0x08`/`0x0c`);
/// `ausb.c:102-103` writes `cfg0_device`/`cfg1_device` straight into them.
///
/// These are the live register values, and in pwned DFU the SecureROM has already programmed
/// this PHY — that is how the exploit session is talking to the host. So the DT properties
/// `apple,cfg0-device`/`apple,cfg1-device` are **readbacks, not guesses**.
///
/// Read them from the host with a `MEMC` read: no payload code is involved, and no assumption
/// about the ROM's mapping of this address is needed beyond "the ROM can read its own PHY".
pub const AUSB_CFG0_ADDR: u64 = AUSB_PHY_BASE + 0x08; // 0x2_0C000038
pub const AUSB_CFG1_ADDR: u64 = AUSB_PHY_BASE + 0x0C; // 0x2_0C00003C

/// The USB device controller: `usbdev@20c100000`, `apple,s8000-dwc2`. **INSPECTED**
/// `s800-0-3.dtsi:153-164`. This is what the kernel's dwc2 driver will take over, and what
/// makes a CDC-ACM gadget console possible on the cable that is already plugged in.
pub const DWC2_ADDR: u64 = 0x2_0C10_0000;

// ---------------------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------------------

/// Check the layout against itself. Called by the host before staging anything and asserted
/// by test. If this fails, the design changed and something below it is now wrong.
pub fn check() -> Result<()> {
    if DRAM_BASE != 0x8_0000_0000 {
        return Err(Error::new("DRAM_BASE_CHANGED", DRAM_BASE));
    }
    if !DRAM_SIZE.is_power_of_two() || DRAM_SIZE < WINDOW_SIZE {
        return Err(Error::new("DRAM_SIZE_NOT_SANE", DRAM_SIZE));
    }
    // The framebuffer and the loader area must both fit, and must not overlap.
    if FB_ADDR < DRAM_BASE || FB_ADDR + FB_SIZE > LOADER_AREA_BASE {
        return Err(Error::new("FB_OVERLAPS_LOADER", FB_ADDR));
    }
    if LOADER_AREA_BASE + LOADER_AREA_SIZE != DRAM_BASE + DRAM_SIZE {
        return Err(Error::new("LOADER_AREA_NOT_AT_DRAM_TOP", LOADER_AREA_BASE));
    }
    // Everything inside the loader area must be inside it. Each failure has its own code.
    for (code, off, size) in [
        ("DESCRIPTOR_OUT_OF_AREA", DESCRIPTOR_OFF, DESCRIPTOR_SIZE),
        ("MAILBOX_OUT_OF_AREA", MAILBOX_OFF, MAILBOX_SIZE),
        ("VECTORS_OUT_OF_AREA", VECTORS_OFF, VECTORS_SIZE),
        ("STACK_OUT_OF_AREA", EL1_STACK_OFF, EL1_STACK_SIZE),
        ("SPIN_OUT_OF_AREA", SPIN_MAILBOX_OFF, 16),
    ] {
        let end = off + size;
        if end > LOADER_AREA_SIZE {
            return Err(Error::new(code, end));
        }
    }
    // VBAR_EL1 needs 2 KiB alignment. booting.rst does not say so; the architecture does.
    if VECTORS_ADDR % 0x800 != 0 {
        return Err(Error::new("VECTORS_NOT_2K_ALIGNED", VECTORS_ADDR));
    }
    // cpu-release-addr must be naturally aligned (8 bytes) and inside the reserved area.
    if SPIN_MAILBOX_ADDR % 8 != 0 {
        return Err(Error::new("SPIN_NOT_ALIGNED", SPIN_MAILBOX_ADDR));
    }
    // The payload must fit its budget with room for the stack, or it cannot be delivered inside
    // a command transfer at all.
    if PAYLOAD_STACK_SIZE >= PAYLOAD_MAX_FOOTPRINT {
        return Err(Error::new("PAYLOAD_BUDGET_IMPOSSIBLE", PAYLOAD_STACK_SIZE));
    }
    // The DFU buffer must be outside DRAM, or post-handoff DFU traffic could corrupt the
    // kernel's memory. That property is load-bearing for DESIGN.md §5.3.
    if DFU_BUFFER_ADDR >= DRAM_BASE && DFU_BUFFER_ADDR < DRAM_BASE + DRAM_SIZE {
        return Err(Error::new("DFU_BUFFER_INSIDE_DRAM", DFU_BUFFER_ADDR));
    }
    Ok(())
}

/// Address helper: a region's end, with overflow reported rather than wrapped.
pub fn region_end(addr: u64, size: u64) -> Result<u64> {
    addr.checked_add(size)
        .ok_or(Error::new("REGION_OVERFLOW", addr))
}

/// Reserve room for a blob at `cursor`, aligned, and return `(addr, next_cursor)`.
pub fn place(cursor: u64, size: u64, align: u64) -> Result<(u64, u64)> {
    let addr = align_up(cursor, align);
    let next = region_end(addr, size)?;
    Ok((addr, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align_down;

    /// The layout must be self-consistent. This is the test that fails if someone "fixes" an
    /// address by hand.
    #[test]
    fn layout_is_self_consistent() {
        check().expect("layout check");
    }

    /// The 34-bit DRAM base, spelled out, because this is the number this project gets wrong.
    #[test]
    fn dram_base_is_34_bit() {
        assert_eq!(DRAM_BASE, 0x8_0000_0000);
        assert_ne!(DRAM_BASE, 0x8000_0000);
        assert_eq!(DRAM_BASE / WINDOW_SIZE, 32, "DRAM base is 1 GiB aligned (32 x 1 GiB)");
    }

    /// The loader area ends exactly at the top of the DRAM we claim.
    #[test]
    fn loader_area_is_the_top_of_dram() {
        assert_eq!(LOADER_AREA_BASE + LOADER_AREA_SIZE, DRAM_BASE + DRAM_SIZE);
    }

    /// The framebuffer is bigger than the panel it holds, and clear of both neighbours.
    #[test]
    fn framebuffer_geometry() {
        assert_eq!(FB_MIN_SIZE, 2_908_160);
        assert!(FB_SIZE >= FB_MIN_SIZE);
        assert!(FB_ADDR + FB_SIZE <= LOADER_AREA_BASE);
        // ...and does not reach down into the window the kernel will use.
        assert!(FB_ADDR >= DRAM_BASE + WINDOW_SIZE);
    }

    /// The DFU buffer really is outside the memory the kernel is told about — the property
    /// that makes the post-handoff telemetry channel safe to use.
    #[test]
    fn dfu_buffer_is_outside_dram() {
        assert!(DFU_BUFFER_ADDR < DRAM_BASE);
        check().unwrap();
    }

    /// The payload executes at `DFU_BUFFER_ADDR + PAYLOAD_OFF`, past the reply area the handler
    /// writes into. See `abi`.
    #[test]
    fn payload_exec_address_is_inside_the_dfu_buffer() {
        let exec = crate::abi::payload_exec_addr();
        assert_eq!(exec, DFU_BUFFER_ADDR + crate::abi::PAYLOAD_OFF);
        assert!(exec >= DFU_BUFFER_ADDR + crate::abi::REPLY_OFF + crate::abi::REPLY_CAP);
        assert_eq!(exec % 16, 0, "the entry point should be 16-byte aligned");
    }

    #[test]
    fn align_helpers() {
        assert_eq!(align_up(0x1000, 0x20_0000), 0x20_0000);
        assert_eq!(align_up(0x20_0000, 0x20_0000), 0x20_0000);
        assert_eq!(align_up(0x20_0001, 0x20_0000), 0x40_0000);
        assert_eq!(align_down(0x20_0001, 0x20_0000), 0x20_0000);
    }
}
