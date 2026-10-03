//! Turning blob sizes into addresses, and enforcing the rules that make those addresses safe.
//!
//! This module is the *contract* between the host (which computes the plan and prints it) and
//! the payload (which validates the descriptor derived from it). The same `compute` runs in
//! both places whenever either side needs to check an invariant, so a disagreement is a
//! test failure rather than a boot failure.

use crate::layout::*;
use crate::{align_up, Error, Result};

/// The host's inputs. Everything else is derived and checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    /// `image_size` from the arm64 Image header — MEASURED, never assumed.
    pub image_size: u64,
    /// `text_offset` from the same header — MEASURED, never assumed.
    pub image_text_offset: u64,
    /// Size of the edited device tree blob.
    pub dtb_size: u64,
    /// Size of the initramfs. Zero means "no initrd".
    pub initrd_size: u64,
    /// DRAM size to advertise in `/memory`. Must equal `layout::DRAM_SIZE`: the mailbox, vector
    /// table and payload execution address are compile-time constants of a matching build.
    pub dram_size: u64,
    /// Whether a display module has actually lit the panel (rung 2). **Rung 1 passes `false`.**
    pub fb_enabled: bool,
    /// Whether the AUSB PHY tunables were read back, so the USB gadget console has a chance.
    pub usb_console: bool,
    /// Override the command line. `None` selects the contract default.
    pub bootargs: Option<BootArgs>,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            image_size: 0,
            image_text_offset: 0,
            dtb_size: 0,
            initrd_size: 0,
            dram_size: DRAM_SIZE,
            fb_enabled: false,
            usb_console: false,
            bootargs: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub name: &'static str,
    pub addr: u64,
    pub size: u64,
}

impl Region {
    pub fn end(&self) -> Result<u64> {
        crate::layout::region_end(self.addr, self.size)
    }
}

pub const MAX_REGIONS: usize = 6;

/// Command line. A fixed buffer, because this type is shared with `no_std`.
pub const BOOTARGS_CAP: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BootArgs {
    buf: [u8; BOOTARGS_CAP],
    len: usize,
}

impl BootArgs {
    pub const fn new() -> Self {
        Self { buf: [0u8; BOOTARGS_CAP], len: 0 }
    }

    /// Append a whitespace-separated argument. Refuses rather than truncating: a silently
    /// truncated command line is a boot that fails for a reason nobody can see.
    pub fn push(&mut self, arg: &str) -> Result<()> {
        let sep = if self.len == 0 { 0 } else { 1 };
        let need = self.len + sep + arg.len();
        if need > BOOTARGS_CAP {
            return Err(Error::new("BOOTARGS_OVERFLOW", need as u64));
        }
        if sep == 1 {
            self.buf[self.len] = b' ';
            self.len += 1;
        }
        self.buf[self.len..self.len + arg.len()].copy_from_slice(arg.as_bytes());
        self.len += arg.len();
        Ok(())
    }

    /// Build from a whole string, splitting on whitespace.
    pub fn from_str(s: &str) -> Result<Self> {
        let mut b = Self::new();
        for tok in s.split_whitespace() {
            b.push(tok)?;
        }
        Ok(b)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for BootArgs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for BootArgs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The command line, verbatim from `a9linux/dts/LOADER-FILL.md` §4.
///
/// This string is **dt-engineer's frozen contract**, not a9boot's preference, and two of its
/// tokens exist because of findings that would otherwise cost a device round trip:
///
/// * `earlycon`, argless: resolves through `/chosen/stdout-path` → `apple,s5l-uart` →
///   `apple_s5l_early_console_setup` (`samsung_tty.c:2851`). It prints before the memory
///   allocator and before any driver probes, which on a device with no display is the difference
///   between a log and a brick.
/// * `console=ttySAC0` with **no `,baud`**: `s3c24xx_serial_get_options()` reads the live
///   `UBRDIV` back and derives the baud from it, so the loader's baud round-trips unchanged.
///   Forcing `,115200` would instead trust the DT's `clkref`, and if A9's real UART input clock
///   is not 24 MHz that produces garbage.
/// * `keep_bootcon`: the early console is never unregistered, so the log survives a real-console
///   failure. This is also what makes an explicit `console=` safe rather than a silencer.
/// * `clk_ignore_unused` / `pd_ignore_unused`: exactly this situation — the DT says "use the
///   bootloader-enabled clocks for now" and no driver claims them.
///
/// `maxcpus=`/`nr_cpus=` are deliberately absent: with `cpu-release-addr = <0 0>` the kernel's
/// own `smp_spin_table.c:71-72` guard skips cpu1 cleanly (`UNVERIFIED.md` U-12).
pub const BOOTARGS_CONTRACT: &str = "earlycon console=ttySAC0 keep_bootcon ignore_loglevel \
                                     initcall_debug clk_ignore_unused pd_ignore_unused";

/// The rung-1 command line: the contract, plus the USB gadget console when the AUSB PHY
/// tunables were read back and written into the tree (`LOADER-FILL.md` §7).
///
/// Two `console=` tokens are fine: Linux registers both and `/dev/console` is the last one
/// named, while output goes to all registered consoles. Appending `ttyGS0` therefore *adds* a
/// channel rather than replacing the UART one.
pub const BOOTARGS_WITH_USB_CONSOLE: &str = "earlycon console=ttySAC0 console=ttyGS0 \
                                             keep_bootcon ignore_loglevel initcall_debug \
                                             clk_ignore_unused pd_ignore_unused";

/// The `a9boot` default. `= BOOTARGS_WITH_USB_CONSOLE` when the gadget is wired up, otherwise
/// the contract string; see `compute`.
pub fn default_bootargs() -> Result<BootArgs> {
    BootArgs::from_str(BOOTARGS_CONTRACT)
}

pub fn bootargs_with_usb_console() -> Result<BootArgs> {
    BootArgs::from_str(BOOTARGS_WITH_USB_CONSOLE)
}

/// The computed layout.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    pub regions: [Region; MAX_REGIONS],
    pub region_count: usize,
    /// Where `eret` lands: the first instruction of the Image.
    pub kernel_entry: u64,
    pub dtb_addr: u64,
    pub dtb_size: u64,
    pub image_addr: u64,
    pub image_size: u64,
    pub initrd_addr: u64,
    pub initrd_size: u64,
    pub dram_base: u64,
    pub dram_size: u64,
    pub bootargs: BootArgs,
    /// Regions to publish as `/reserved-memory` children (plain, never `no-map`).
    pub reservations: [Region; MAX_REGIONS],
    pub reservation_count: usize,
    pub fb_enabled: bool,
}

impl Plan {
    pub fn region(&self, name: &str) -> Option<Region> {
        self.regions[..self.region_count]
            .iter()
            .copied()
            .find(|r| r.name == name)
    }

    pub fn reservations(&self) -> &[Region] {
        &self.reservations[..self.reservation_count]
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions[..self.region_count]
    }
}

/// Compute the plan, or fail with a named reason.
///
/// The order of the checks is the order of the mistakes this project has actually made:
/// a wrong base, a straddled 1 GiB window, a DTB sharing a 2 MiB region with the kernel, a
/// blob that overlaps the loader's own area.
pub fn compute(inputs: &Inputs) -> Result<Plan> {
    if inputs.image_size == 0 {
        return Err(Error::new("PLAN_IMAGE_SIZE_ZERO", 0));
    }
    if inputs.dtb_size == 0 || inputs.dtb_size > DTB_REGION_SIZE {
        return Err(Error::new("PLAN_DTB_SIZE_BAD", inputs.dtb_size));
    }
    // The loader area, the mailbox, the vector table and the payload's fixed execution address
    // are *compile-time* constants of this layout, so the layout only exists for the DRAM size
    // it was built for. A device that reports something else needs a different payload build,
    // not a dynamic replan — and saying so by name beats quietly placing blobs off the end.
    if inputs.dram_size != DRAM_SIZE {
        return Err(Error::new("PLAN_DRAM_SIZE_UNSUPPORTED", inputs.dram_size));
    }
    let dram_end = DRAM_BASE
        .checked_add(inputs.dram_size)
        .ok_or(Error::new("PLAN_DRAM_OVERFLOW", DRAM_BASE))?;

    // 1. The kernel: 2 MiB aligned base plus the header's own text_offset.
    if IMAGE_2M_BASE % TWO_MIB != 0 {
        return Err(Error::new("PLAN_IMAGE_BASE_NOT_2M", IMAGE_2M_BASE));
    }
    let image_addr = IMAGE_2M_BASE
        .checked_add(inputs.image_text_offset)
        .ok_or(Error::new("PLAN_IMAGE_OVERFLOW", inputs.image_text_offset))?;
    let image_span = align_up(
        inputs
            .image_text_offset
            .checked_add(inputs.image_size)
            .ok_or(Error::new("PLAN_IMAGE_SPAN_OVERFLOW", inputs.image_size))?,
        TWO_MIB,
    );
    let image_end = IMAGE_2M_BASE + image_span;

    // 2. The initrd, in its own space after the kernel's 2 MiB-rounded span.
    let (initrd_addr, initrd_end) = if inputs.initrd_size > 0 {
        let addr = align_up(image_end, INITRD_ALIGN);
        let end = crate::layout::region_end(addr, inputs.initrd_size)?;
        (addr, end)
    } else {
        (0, image_end)
    };

    // 3. Nothing may reach into the framebuffer or the loader area at the top of DRAM. This is
    //    checked before the window rule because it is the more specific failure: "your blobs run
    //    into memory a9boot itself owns".
    let top_of_blobs = initrd_end;
    if top_of_blobs > FB_ADDR {
        return Err(Error::new("PLAN_BLOBS_REACH_FRAMEBUFFER", top_of_blobs));
    }

    // 4. The 1 GiB window rule. booting.rst: an initrd "must reside entirely within a 1 GB
    //    aligned physical memory window of up to 32 GB in size that fully covers the kernel
    //    Image as well." With 2 GiB of RAM there are exactly two windows, and straddling them
    //    is a silent failure, so it is a refusal here.
    let window_end = DRAM_BASE + WINDOW_SIZE;
    if image_addr < DRAM_BASE || image_end > dram_end {
        return Err(Error::new("PLAN_IMAGE_OUT_OF_DRAM", image_end));
    }
    if initrd_end > window_end {
        return Err(Error::new("PLAN_INITRD_STRADDLES_WINDOW", initrd_end));
    }

    // 5. Regions and reservations.
    let mut regions = [Region { name: "", addr: 0, size: 0 }; MAX_REGIONS];
    let mut n = 0;
    regions[n] = Region { name: "dtb", addr: DTB_ADDR, size: DTB_REGION_SIZE };
    n += 1;
    regions[n] = Region { name: "image", addr: image_addr, size: inputs.image_size };
    n += 1;
    if inputs.initrd_size > 0 {
        regions[n] = Region { name: "initrd", addr: initrd_addr, size: inputs.initrd_size };
        n += 1;
    }
    regions[n] = Region { name: "fb", addr: FB_ADDR, size: FB_SIZE };
    n += 1;
    regions[n] = Region { name: "loader", addr: LOADER_AREA_BASE, size: LOADER_AREA_SIZE };
    n += 1;

    // Reservations, as `/reserved-memory` children (LOADER-FILL.md §2, §10 — the DTS ships an
    // empty `reserved-memory` node marked "To be filled by loader", so that is the mechanism).
    // All plain, never `no-map`: the kernel must be able to read the DTB and initrd, and in
    // rung 2 it must be able to *write* the spin-table mailbox inside the loader area.
    let mut reservations = [Region { name: "", addr: 0, size: 0 }; MAX_REGIONS];
    let mut m = 0;
    for (name, addr, size) in RESERVED_MEMORY_CHILDREN {
        reservations[m] = Region { name, addr: *addr, size: *size };
        m += 1;
    }
    if inputs.initrd_size > 0 {
        reservations[m] = Region { name: "initramfs", addr: initrd_addr, size: inputs.initrd_size };
        m += 1;
    }
    // The Image itself is deliberately NOT reserved: the kernel reserves its own text
    // (`memblock_reserve(__pa_symbol(_text), _end - _text)`, arm64-mm-init.c:293).

    let bootargs = match inputs.bootargs {
        Some(b) => b,
        None if inputs.usb_console => bootargs_with_usb_console()?,
        None => default_bootargs()?,
    };

    let plan = Plan {
        regions,
        region_count: n,
        kernel_entry: image_addr,
        dtb_addr: DTB_ADDR,
        dtb_size: inputs.dtb_size,
        image_addr,
        image_size: inputs.image_size,
        initrd_addr,
        initrd_size: inputs.initrd_size,
        dram_base: DRAM_BASE,
        dram_size: inputs.dram_size,
        bootargs,
        reservations,
        reservation_count: m,
        fb_enabled: inputs.fb_enabled,
    };
    plan.check()?;
    Ok(plan)
}

impl Plan {
    /// Adopt the size of the **edited** device tree.
    ///
    /// The plan is computed before the tree is edited (the edit needs the plan's addresses), and
    /// the edited blob is bigger than its source — 27,664 bytes against 22,880 on the real board
    /// DTB, measured. What gets staged at `dtb_addr` is the *edited* blob, so the plan's idea of
    /// its size must be the edited one; otherwise every size-dependent check (the reservation
    /// arithmetic, and the hand-off assertion that no blob reaches into the kernel image) is
    /// computed against a number smaller than reality.
    ///
    /// No address depends on `dtb_size` — the DTB sits in its own fixed 2 MiB region — which is
    /// why this is a size update rather than a recomputation, and the method checks that.
    pub fn adopt_edited_dtb(&mut self, size: u64) -> Result<()> {
        if size == 0 || size > DTB_REGION_SIZE {
            return Err(Error::new("PLAN_EDITED_DTB_SIZE_BAD", size));
        }
        let before_regions = self.regions;
        let before_count = self.region_count;
        let before_reservations = self.reservations;
        let before_res_count = self.reservation_count;
        self.dtb_size = size;
        // The DTB's own region is fixed, so adopting a size must not move anything.
        if before_regions != self.regions
            || before_count != self.region_count
            || before_reservations != self.reservations
            || before_res_count != self.reservation_count
        {
            return Err(Error::new("PLAN_EDITED_DTB_MOVED_REGIONS", size));
        }
        self.check()
    }

    /// Re-check the finished plan. Cheap, and it runs on both sides of the wire.
    pub fn check(&self) -> Result<()> {
        crate::layout::check()?;
        crate::abi::check()?;
        if self.kernel_entry != self.image_addr {
            return Err(Error::new("PLAN_ENTRY_NOT_IMAGE_START", self.kernel_entry));
        }
        if self.dtb_addr % 8 != 0 {
            return Err(Error::new("PLAN_DTB_UNALIGNED", self.dtb_addr));
        }
        if self.dtb_size > DTB_REGION_SIZE {
            return Err(Error::new("PLAN_DTB_TOO_BIG", self.dtb_size));
        }
        for r in self.regions() {
            let end = r.end()?;
            if r.addr < self.dram_base || end > self.dram_base + self.dram_size {
                return Err(Error::new("PLAN_REGION_OUT_OF_DRAM", r.addr));
            }
        }
        // The two regions that must never overlap anything else.
        for r in self.regions() {
            let end = r.end()?;
            let loader_end = LOADER_AREA_BASE + LOADER_AREA_SIZE;
            if r.name != "loader" && r.addr < loader_end && end > LOADER_AREA_BASE {
                return Err(Error::new("PLAN_OVERLAPS_LOADER", r.addr));
            }
        }
        // No blob may sit inside the kernel image's own span: `__primary_switched` zeroes the
        // image's bss before `setup_arch` reads the tree or the initrd, so a blob placed there is
        // total silence with no output anywhere (qemu-validator's first stub map did exactly
        // that). Unreachable through `compute`, which places every blob outside the image's
        // span — it stays as a guard, because a layout change is how it would become reachable.
        let (kstart, kend) = (self.image_addr, self.image_addr + self.image_size);
        for r in self.regions() {
            if r.name == "image" || r.size == 0 {
                continue;
            }
            let end = r.end()?;
            if r.addr < kend && end > kstart {
                return Err(Error::new("PLAN_BLOB_INSIDE_KERNEL", r.addr));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(image_size: u64, text_offset: u64, dtb: u64, initrd: u64) -> Inputs {
        Inputs { image_size, image_text_offset: text_offset, dtb_size: dtb, initrd_size: initrd, ..Default::default() }
    }

    #[test]
    fn ordinary_plan() {
        let p = compute(&inputs(0x0180_0000, 0x80000, 0x5800, 0x300000)).unwrap();
        assert_eq!(p.kernel_entry, IMAGE_2M_BASE + 0x80000);
        assert_eq!(p.region("dtb").unwrap().addr, DTB_ADDR);
        assert_eq!(p.region("dtb").unwrap().size, TWO_MIB);
        // 0x80000 + 0x1800000 = 0x1880000, rounded up to a 2 MiB multiple = 0x1A00000.
        assert_eq!(p.initrd_addr, IMAGE_2M_BASE + 0x1A00_000);
        assert_eq!(p.initrd_addr, IMAGE_2M_BASE + align_up(0x80000 + 0x0180_0000, TWO_MIB));
        assert_eq!(p.reservations().len(), 4); // loader, framebuffer, dtb, initramfs
        assert_eq!(p.bootargs.as_str(), BOOTARGS_CONTRACT);
        assert!(!p.fb_enabled);
        // The exact same plan with a framebuffer-enabled build differs only in the flag: the
        // addresses do not move, so rung 1 and rung 2 cannot disagree about where things are.
        let mut with_fb = inputs(0x0180_0000, 0x80000, 0x5800, 0x300000);
        with_fb.fb_enabled = true;
        let q = compute(&with_fb).unwrap();
        assert_eq!(p.regions(), q.regions());
        assert_eq!(p.reservations(), q.reservations());
        assert!(q.fb_enabled);
    }

    /// The command line is dt-engineer's contract, and the USB variant *adds* a console rather
    /// than replacing the UART one.
    #[test]
    fn bootargs_follow_the_frozen_contract() {
        let p = compute(&inputs(0x0180_0000, 0x80000, 0x5800, 0x300000)).unwrap();
        for token in [
            "earlycon",
            "console=ttySAC0",
            "keep_bootcon",
            "ignore_loglevel",
            "initcall_debug",
            "clk_ignore_unused",
            "pd_ignore_unused",
        ] {
            assert!(p.bootargs.as_str().contains(token), "missing {token}");
        }
        // No forced baud: s3c24xx_serial_get_options() reads UBRDIV back and cancels the error.
        assert!(!p.bootargs.as_str().contains("ttySAC0,"));
        // maxcpus= is deliberately absent: the kernel's own guard skips cpu1.
        assert!(!p.bootargs.as_str().contains("maxcpus"));

        let mut i = inputs(0x0180_0000, 0x80000, 0x5800, 0x300000);
        i.usb_console = true;
        let q = compute(&i).unwrap();
        assert!(q.bootargs.as_str().contains("console=ttySAC0"));
        assert!(q.bootargs.as_str().contains("console=ttyGS0"));
        assert!(q.bootargs.len() <= BOOTARGS_CAP);
    }

    /// `text_offset` is read, not assumed: a kernel that wants to sit at the 2 MiB base exactly
    /// must be placed there.
    #[test]
    fn text_offset_zero_puts_the_image_at_the_base() {
        let p = compute(&inputs(0x0100_0000, 0, 0x5800, 0)).unwrap();
        assert_eq!(p.kernel_entry, IMAGE_2M_BASE);
        assert_eq!(p.image_addr, IMAGE_2M_BASE);
    }

    /// A DTB larger than 2 MiB is refused before it can share a 2 MiB region with the kernel.
    #[test]
    fn oversized_dtb_is_refused() {
        let e = compute(&inputs(0x1000_000, 0x80000, TWO_MIB + 1, 0)).unwrap_err();
        assert_eq!(e.code, "PLAN_DTB_SIZE_BAD");
    }

    /// An initrd that crosses the 1 GiB boundary is refused, not silently mis-placed. The size is
    /// chosen so that the *window* check is the one that fires: the end lands above
    /// `0x8_4000_0000` and below the framebuffer at `0x8_7800_0000`.
    #[test]
    fn initrd_straddling_the_window_is_refused() {
        let p = compute(&inputs(0x0000_0000 + 0x0010_0000, 0x80000, 0x5800, 0x5000_0000));
        // 0x10_0000 + 0x80000 = 0x18_0000 -> 2 MiB rounded span; initrd from ~0x8_0040_0000.
        assert_eq!(p.unwrap_err().code, "PLAN_INITRD_STRADDLES_WINDOW");
    }

    /// Blobs that reach into the framebuffer are refused by the more specific check first:
    /// "your blobs run into memory a9boot itself owns" beats "they cross a 1 GiB boundary".
    #[test]
    fn blobs_may_not_reach_the_framebuffer() {
        let e = compute(&inputs(0x1000_000, 0x80000, 0x5800, FB_ADDR - IMAGE_2M_BASE)).unwrap_err();
        assert_eq!(e.code, "PLAN_BLOBS_REACH_FRAMEBUFFER");
    }

    #[test]
    fn zero_sizes_are_named_failures() {
        assert_eq!(compute(&inputs(0, 0x80000, 0x5800, 0)).unwrap_err().code, "PLAN_IMAGE_SIZE_ZERO");
        assert_eq!(compute(&inputs(0x1000, 0x80000, 0, 0)).unwrap_err().code, "PLAN_DTB_SIZE_BAD");
    }

    /// A device with a different DRAM size needs a different payload build, because the
    /// mailbox, vector table and payload execution address are compile-time constants.
    #[test]
    fn a_different_dram_size_is_refused_rather_than_guessed() {
        let mut i = inputs(0x0180_0000, 0x80000, 0x5800, 0x300000);
        i.dram_size = 0x1_0000_0000;
        assert_eq!(compute(&i).unwrap_err().code, "PLAN_DRAM_SIZE_UNSUPPORTED");
        let mut i = inputs(0x0180_0000, 0x80000, 0x5800, 0x300000);
        i.dram_size = 0x4000_0000;
        assert_eq!(compute(&i).unwrap_err().code, "PLAN_DRAM_SIZE_UNSUPPORTED");
    }

    #[test]
    fn bootargs_refuse_to_truncate() {
        let mut b = BootArgs::new();
        b.push("earlycon").unwrap();
        assert_eq!(b.as_str(), "earlycon");
        for _ in 0..40 {
            let _ = b.push("0123456789");
        }
        assert!(b.push("0123456789").is_err());
        assert!(b.len() <= BOOTARGS_CAP);
    }

    #[test]
    fn plan_matches_the_layout_constants_it_claims_to_use() {
        let p = compute(&inputs(0x0180_0000, 0x80000, 0x5800, 0x300000)).unwrap();
        assert_eq!(p.dram_base, 0x8_0000_0000);
        assert_eq!(p.region("loader").unwrap().addr, LOADER_AREA_BASE);
        assert_eq!(p.region("fb").unwrap().addr, FB_ADDR);
        // initrd and image never overlap the loader area or each other
        assert!(p.image_addr + p.image_size <= p.initrd_addr);
    }
}
