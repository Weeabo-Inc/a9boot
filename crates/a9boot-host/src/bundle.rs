//! The staging sequence: what a9boot actually *does*, expressed as data.
//!
//! The sequence is built once, on the host, from the plan; then:
//!
//! * `plan --dry-run` prints every packet it would send (bytes, lengths, addresses) without any
//!   transport at all;
//! * `execute_steps` runs it against any `Transport` — the simulator in tests, the live transport
//!   when the Lead runs it.
//!
//! One code path, two back ends. That is the only way a dry run can mean anything.

use crate::channel::{self, Packet};
use crate::transport::{Exchange, Transport};
use a9boot_core::abi::{self, Command, Descriptor};
use a9boot_core::image::Header;
use a9boot_core::layout::*;
use a9boot_core::plan::{Plan, BOOTARGS_CAP};

/// Everything the host uploads.
pub struct BootBlobs {
    /// The on-device payload. Executed in place at `abi::payload_exec_addr()`.
    pub payload: Vec<u8>,
    /// The edited device tree (see `edit_dtb`).
    pub dtb: Vec<u8>,
    /// The uncompressed arm64 `Image`. Its header is parsed and validated, never assumed.
    pub image: Vec<u8>,
    /// The initramfs, passed through to the kernel. `None` for a kernel-only boot.
    pub initrd: Option<Vec<u8>>,
}

/// Knobs that differ between rung 1 and rung 2. Defaulted to rung 1, deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditOptions {
    /// Rung 2 only: the address the secondaries poll. `None` in rung 1, which leaves
    /// `cpu-release-addr = <0 0>` — `smp_spin_table.c:71-72` then skips cpu1 cleanly
    /// (`smp.c:810-818`), which is a rung-1-acceptable outcome and not a hang.
    pub spin_addr: Option<u64>,
    /// Rung 2 only, and only ever set by a display module that actually lit the panel.
    /// **Rung 1 leaves this false and the node `status = "disabled"`.**
    pub fb_enable: bool,
    /// The AUSB tunables, when the probe has read them back. `None` leaves USB dead, which is
    /// `LOADER-FILL.md` §7's "blocked today" state — honest, and worth stating explicitly.
    pub ausb: Option<AusbTunables>,
}

impl Default for EditOptions {
    fn default() -> Self {
        EditOptions { spin_addr: None, fb_enable: false, ausb: None }
    }
}

/// The AUSB PHY tunables, read back from live registers.
///
/// `a9linux/dts/LOADER-FILL.md` §7 and `CONSOLE-SIGNALS.md` Q3: the kernel's AUSB PHY probe
/// (`drivers/phy/apple/ausb.c:149-156`) returns `-ENODEV` unless `/soc/bus@20c000000/phy@20c000030`
/// carries `apple,cfg0-device`, `apple,cfg1-device`, `apple,cfg0-host` and `apple,cfg1-host`.
/// Without them the PHY never registers, dwc2 defers forever, and **USB is dead** — which is what
/// makes the USB gadget console, the only remaining human-readable channel, impossible.
///
/// The device pair is not a guess: `ausb.c:102-103` writes `cfg0_device`/`cfg1_device` straight
/// into `AUSB_CFG0`/`AUSB_CFG1` (offsets `0x08`/`0x0c` from the PHY base), and in pwned DFU the
/// SecureROM has already programmed this PHY — that is how the DFU session is talking to us. So
/// the values are read from `0x2_0C000038`/`0x2_0C00003C` through the *ROM's own* memcpy, with
/// no payload code involved at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AusbTunables {
    pub cfg0_device: u32,
    pub cfg1_device: u32,
}

impl AusbTunables {
    /// The host pair: **`(0, 0)`, deliberately, and it is a non-claim rather than a value.**
    ///
    /// Mirroring the device pair here would assert *"the host-mode tunables equal the device-mode
    /// tunables"* — and nobody has measured that. Host-mode tunables were never read: DFU is the
    /// device role, and the only consumer, `ausb_phy_usb2_set_mode()`, sits inside `#if 0`
    /// (`ausb.c:63-95`, `.set_mode` commented out at `:134`). Putting an unmeasured guess into the
    /// syntax of measured data is the failure this project keeps paying for. Zero is recognisably
    /// *unset*: if a future kernel re-enables `set_mode()`, host mode fails visibly and must be
    /// re-measured, instead of silently receiving device tunables. The presence check in
    /// `ausb.c:149-156` is satisfied by any `u32`, so presence is not a reason to put a number here.
    pub fn host_pair(&self) -> (u32, u32) {
        (0, 0)
    }

    /// A sanity check that costs nothing and catches the "the read did not happen" case: the
    /// SecureROM programmed this PHY, so a zero or all-ones pair means we read the wrong thing.
    pub fn looks_plausible(&self) -> bool {
        let zero = self.cfg0_device == 0 && self.cfg1_device == 0;
        let ones = self.cfg0_device == u32::MAX && self.cfg1_device == u32::MAX;
        !zero && !ones
    }
}

/// Everything the post-pwn experiment establishes, in one procedure (`UNVERIFIED.md` U-1, U-2,
/// U-13). This is the *same* experiment dt-engineer specified; it is implemented once, here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Probe {
    /// AUSB tunables, or `None` if the read did not happen.
    pub ausb: Option<AusbTunables>,
    /// Highest address whose write/read round trip succeeded.
    pub dram_last_ok: u64,
    /// First address that failed, if any. This is the measured DRAM extent, rounded down.
    pub dram_first_bad: Option<u64>,
    /// Whether the DRAM walk ran **at all**. Without this, `dram_last_ok == 0` is ambiguous
    /// between "the walk failed everywhere" and "the walk was not run", and the two need opposite
    /// responses. A run that skipped the walk must never be read as a measurement of nothing.
    pub dram_walk_ran: bool,
}

impl Probe {
    /// Whether any DRAM address was walked. `false` means the extent is **UNMEASURED**, which is
    /// not the same as zero.
    pub fn dram_measured(&self) -> bool {
        self.dram_walk_ran
    }

    /// The DRAM extent this probe supports declaring: the last address that round-tripped,
    /// rounded down to a 128 MiB boundary. Never larger than the nominal `layout::DRAM_SIZE`.
    ///
    /// **`0` means NOT MEASURED**, never "no DRAM": callers must check [`Probe::dram_measured`]
    /// first. Two different problems must not be spelled the same way.
    pub fn dram_extent(&self) -> u64 {
        if !self.dram_measured() || self.dram_last_ok < DRAM_BASE {
            return 0;
        }
        let ok = (self.dram_last_ok - DRAM_BASE) + 0x20;
        let rounded = crate::round_down(ok, 0x0800_0000);
        rounded.min(DRAM_SIZE)
    }

    pub fn report(&self) -> String {
        let mut s = String::new();
        match self.ausb {
            Some(a) => s.push_str(&format!(
                "AUSB cfg0-device={:#010x} cfg1-device={:#010x} ({})\n",
                a.cfg0_device,
                a.cfg1_device,
                if a.looks_plausible() { "non-zero, plausible" } else { "ZERO OR ALL-ONES: suspect" }
            )),
            None => s.push_str("AUSB tunables: NOT READ\n"),
        }
        if !self.dram_measured() {
            s.push_str(
                "DRAM: NOT MEASURED — the walk did not run in this session. This is not a result \
                 about DRAM; it is the absence of one.\n",
            );
            s.push_str(
                "DRAM extent this supports declaring: UNMEASURED (0 is not a measurement)\n",
            );
            return s;
        }
        s.push_str(&format!(
            "DRAM: last address that round-tripped {:#x}, first failure {}\n",
            self.dram_last_ok,
            match self.dram_first_bad {
                Some(a) => format!("{a:#x}"),
                None => "(none: the whole nominal range responded)".to_string(),
            }
        ));
        s.push_str(&format!(
            "DRAM extent this supports declaring: {:#x} ({} MiB), nominal {:#x}\n",
            self.dram_extent(),
            self.dram_extent() / (1024 * 1024),
            DRAM_SIZE
        ));
        s.push_str(
            "  CAVEAT, and it is load-bearing: the walk cannot see a cache. If the ROM's EL3 \
             context runs with the MMU and D-cache on and maps DRAM as Normal cacheable, a \
             write-then-read is served by the cache line and \"round-trips\" on memory that may \
             not exist. Distinct per-address patterns catch aliasing and mirroring, NOT this. \
             Nothing in this channel can perform cache maintenance or read SCTLR_EL3. So: a \
             FAILURE below is real evidence; a PASS is not sufficient evidence for an extent. \
             SCTLR_EL3/SCTLR_EL1 from the a9boot payload's DESCRIBE (U-3/U-4), or an \
             eviction-pressure experiment, is what settles it.\n",
        );
        s
    }
}

/// The addresses the DRAM walk visits: 128 MiB steps across the nominal range, plus the last 32
/// bytes of it. A 16 GiB-addressable part that only decodes 1 GiB shows up as the first failure
/// at the first address above the real extent.
pub fn dram_walk_addresses() -> Vec<u64> {
    let mut v = Vec::new();
    let mut a = DRAM_BASE;
    while a < DRAM_BASE + DRAM_SIZE {
        v.push(a);
        a += 0x0800_0000;
    }
    v.push(DRAM_BASE + DRAM_SIZE - 0x20);
    v
}

/// Which half of the post-pwn experiment to run. The two halves answer different questions and
/// carry different risk, so they must be selectable: the AUSB read changes nothing, while the DRAM
/// walk writes to DRAM and its *pass* cannot be trusted without a cache answer (see
/// `Probe::report`). Making the selector explicit is what lets the read go to hardware today
/// while the extent stays UNMEASURED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePart {
    /// Read `AUSB_CFG0/CFG1` (and `AUSB_CTL/SIG` in the same page). Read-only, touches only the
    /// ROM's own buffer.
    Ausb,
    /// The 128 MiB write/read-back walk that would measure the DRAM extent (U-1, U-5). Writes to
    /// DRAM, and a pass is **not** sufficient evidence until the cache question is answered.
    Dram,
}

/// The steps of the unified post-pwn experiment, filtered by part.
///
/// `probe_steps_filtered(None, None)` is the whole procedure and is what `probe_steps()` returns.
pub fn probe_steps_filtered(only: Option<ProbePart>, skip: Option<ProbePart>) -> Vec<Step> {
    let want = |p: ProbePart| only.map_or(true, |o| o == p) && skip != Some(p);
    let mut steps = Vec::new();
    if want(ProbePart::Ausb) {
        steps.push(Step::Comment(
            "AUSB PHY tunables: a readback of live registers the SecureROM has already \
             programmed, because that is how DFU is talking to us (LOADER-FILL.md §7)."
                .to_string(),
        ));
        steps.push(Step::Read { addr: AUSB_CFG0_ADDR, len: 8 });
    }
    if want(ProbePart::Dram) {
        steps.push(Step::Comment(format!(
            "DRAM walk: 128 MiB steps across the nominal {:#x} bytes. Over-declaring DRAM hands \
             the kernel dead pages and corrupts rather than panicking (LOADER-FILL.md §2), so \
             the extent is measured before it is declared. NOTE: a pass here is NOT sufficient \
             evidence for an extent while the ROM's cache state is unknown — see 
             `Probe::report`.",
            DRAM_SIZE
        )));
        for (i, addr) in dram_walk_addresses().iter().enumerate() {
            steps.push(Step::WriteVerify { dst: *addr, data: dram_pattern(i as u8) });
        }
    }
    steps
}

/// The steps of the unified post-pwn experiment. Nothing here needs a9boot to exist: it is all
/// the ROM's own `memcpy`, so it can run the moment the first `PWND:[checkm8]` appears.
pub fn probe_steps() -> Vec<Step> {
    probe_steps_filtered(None, None)
}

/// Run the probe, tolerating a failure at any single DRAM address so that the *extent* comes
/// back as a measurement instead of an abort.
pub fn run_probe(t: &mut dyn Transport) -> Result<Probe, String> {
    run_probe_with(t, probe_steps())
}

/// Run a *selected* set of probe steps. Same failure semantics as [`run_probe`]; the difference is
/// only which steps are in the list, so a session can read the AUSB registers without writing
/// anything to DRAM.
pub fn run_probe_with(t: &mut dyn Transport, steps: Vec<Step>) -> Result<Probe, String> {
    let mut probe = Probe::default();
    let mut steps = steps.into_iter();
    while let Some(step) = steps.next() {
        match &step {
            Step::Read { .. } => {
                let outcomes = execute_steps(t, core::slice::from_ref(&step), &[], &TransferBudget::default())?;
                if let Some(Outcome::Read { data, .. }) = outcomes.first() {
                    if data.len() >= 8 {
                        probe.ausb = Some(AusbTunables {
                            cfg0_device: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                            cfg1_device: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                        });
                    }
                }
            }
            Step::WriteVerify { dst, .. } => {
                probe.dram_walk_ran = true;
                match execute_steps(t, core::slice::from_ref(&step), &[], &TransferBudget::default()) {
                    Ok(outcomes) => {
                        if let Some(Outcome::Written { dst, .. }) = outcomes.first() {
                            probe.dram_last_ok = probe.dram_last_ok.max(*dst);
                        }
                    }
                    Err(e) => {
                        probe.dram_first_bad = Some(*dst);
                        // Everything past the first failure would fail identically.
                        while let Some(s) = steps.next() {
                            if matches!(s, Step::WriteVerify { .. }) {
                                continue;
                            }
                        }
                        eprintln!("DRAM walk stopped at {dst:#x}: {e}");
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(probe)
}

/// Node name for a `/reserved-memory` child: `<label>@<address in hex>`, which is what the DT
/// convention expects (the unit-address is the first cell of `reg`).
pub fn reservation_node_name(label: &str, addr: u64) -> String {
    format!("{label}@{addr:x}")
}

/// Apply the loader's device-tree obligations and return the new blob.
///
/// The authoritative list is `a9linux/dts/LOADER-FILL.md` §3 (mandatory) and §7/§10 (rung 1.5 /
/// rung 2). Where this function writes something that document does not list, it is because the
/// *loader* owns a region the kernel must not allocate — and every such write is named in the
/// returned summary rather than left implicit.
pub fn edit_dtb(src: &[u8], plan: &Plan, opts: &EditOptions) -> Result<Vec<u8>, String> {
    let mut f = crate::fdt::Fdt::parse(src)?;

    // 1. /memory: the built DTB ships `reg = <0x8 0 0 0>` — size 0. Without this the kernel has
    //    no RAM at all.
    let mem = f
        .root
        .child_prefix_mut("memory@")
        .ok_or("no memory@ node in the source DTB")?;
    mem.set_prop_cells(
        "reg",
        &[
            (plan.dram_base >> 32) as u32,
            (plan.dram_base & 0xffff_ffff) as u32,
            (plan.dram_size >> 32) as u32,
            (plan.dram_size & 0xffff_ffff) as u32,
        ],
    );

    // 2. /chosen: the command line (CONFIG_CMDLINE="" and no bootargs property exists) and the
    //    initrd range.
    //
    //    **Both properties are written unconditionally**, and here is why that is not pedantry.
    //    `linux,initrd-start`/`-end` are the loader's statement of *how many bytes it actually
    //    loaded*. A DTB template that carries a plausible-looking fixed pair is worse than no
    //    property at all: qemu-validator measured the reference template's implied size at
    //    2,670,592 bytes while rootfs-engineer's real Debian initramfs is 7,503,864 — hand the
    //    kernel the template values and it unpacks the first 2.67 MB of a 7.5 MB archive, which
    //    dies as a VFS/unpack error and reads like a rootfs bug. So:
    //
    //      * with an initramfs: the real start *and* the real byte count staged, from the blob
    //        this host actually transferred and verified chunk by chunk — never from a table;
    //      * without one: explicit `<0 0>`. The kernel treats `initrd_start == 0` as "no initrd"
    //        (arm64 checks `initrd_start` before reserving), so this is a defined value rather
    //        than an absent property, and a stale template value can never survive.
    //
    //    `check_handoff` re-parses the finished blob and asserts both, so a mismatch is a named
    //    refusal before handoff rather than a kernel that quietly unpacks the wrong number of
    //    bytes. Also note the `linux,` prefix: without it the kernel ignores the property
    //    entirely, and the boot panics with `VFS: Cannot open root device` — a rootfs-looking
    //    error from a property-name bug. The check looks for the un-prefixed names too.
    let chosen = f.root.child_mut("chosen").ok_or("no /chosen node in the source DTB")?;
    chosen.set_prop_str("bootargs", plan.bootargs.as_str());
    let (initrd_start, initrd_end) = if plan.initrd_size > 0 {
        (plan.initrd_addr, plan.initrd_addr + plan.initrd_size)
    } else {
        (0, 0)
    };
    chosen.set_prop_u64_cells("linux,initrd-start", initrd_start);
    chosen.set_prop_u64_cells("linux,initrd-end", initrd_end);

    // 3. framebuffer@0: mode information always; `status = "okay"` only if something lit it.
    if let Some(fb) = chosen.child_prefix_mut("framebuffer@") {
        fb.set_prop_cells(
            "reg",
            &[
                (FB_ADDR >> 32) as u32,
                (FB_ADDR & 0xffff_ffff) as u32,
                (FB_SIZE >> 32) as u32,
                (FB_SIZE & 0xffff_ffff) as u32,
            ],
        );
        fb.set_prop_cells("width", &[FB_WIDTH]);
        fb.set_prop_cells("height", &[FB_HEIGHT]);
        fb.set_prop_cells("stride", &[FB_STRIDE]);
        fb.set_prop_str("format", FB_FORMAT);
        if opts.fb_enable {
            fb.set_prop_str("status", "okay");
        } else {
            // The binding: pre-filled disabled nodes are the *advised* form; the firmware updates
            // mode information and enables them. We update the mode information and leave it
            // disabled, because nothing has lit this panel.
            fb.set_prop_str("status", "disabled");
        }
    }

    // 5. ausbphy0 tunables — the placeholder that gates the USB gadget console, and therefore
    //    the only remaining human-readable channel (`CONSOLE-SIGNALS.md` Q3).
    if let Some(a) = opts.ausb {
        let phy = f
            .root
            .find_by_compatible_mut("apple,ausb-phy")
            .ok_or("no apple,ausb-phy node in the source DTB: the PHY cannot be described, so USB \
                    will not come up on this tree")?;
        phy.set_prop_cells("apple,cfg0-device", &[a.cfg0_device]);
        phy.set_prop_cells("apple,cfg1-device", &[a.cfg1_device]);
        let (h0, h1) = a.host_pair();
        phy.set_prop_cells("apple,cfg0-host", &[h0]);
        phy.set_prop_cells("apple,cfg1-host", &[h1]);
    }

    // 6. cpu-release-addr — written **unconditionally**, for the same reason as the initrd pair:
    //    a stale non-zero value is a wild write into low memory plus a hung CPU1, while zero is a
    //    documented, safe outcome (`smp_spin_table.c:71-72` returns -ENODEV, `smp.c:810-818`
    //    skips the CPU, one core boots). Rung 1 therefore writes `<0 0>` *over* whatever the
    //    template said, and rung 2 writes the real SRAM mailbox address — not before, not
    //    speculatively.
    let spin = opts.spin_addr.unwrap_or(0);
    let cpus = f.root.child_mut("cpus").ok_or("no /cpus node in the source DTB")?;
    let mut cpus_written = 0;
    for cpu in cpus.children.iter_mut().filter(|c| c.name.starts_with("cpu@")) {
        cpu.set_prop_u64_cells("cpu-release-addr", spin);
        cpus_written += 1;
    }
    if cpus_written == 0 {
        return Err("no cpu@* nodes in the source DTB: cpu-release-addr cannot be written, and a \
                    template value must not survive"
            .to_string());
    }

    // 7. Reservations. `LOADER-FILL.md` §2/§10 and the DTS's own empty `reserved-memory` node:
    //    children, all **plain**, never `no-map` — the kernel must read the DTB and the initramfs,
    //    and in rung 2 it must be able to *write* the spin-table mailbox inside the loader area.
    //
    //    Created if the source tree has none: the standard `reserved-memory` shape is
    //    `#address-cells = <2>`, `#size-cells = <2>`, `ranges`, and a DTB variation that lacks
    //    the node should not turn into a refusal to boot.
    if f.root.child("reserved-memory").is_none() {
        let mut rm = crate::fdt::Node::new("reserved-memory");
        rm.set_prop_cells("#address-cells", &[2]);
        rm.set_prop_cells("#size-cells", &[2]);
        // An empty `ranges` property means a 1:1 mapping, which is what the DTS has.
        rm.props.push(crate::fdt::Property { name: "ranges".to_string(), value: Vec::new() });
        f.root.children.push(rm);
    }
    let rm = f.root.child_mut("reserved-memory").expect("just created");
    for r in plan.reservations() {
        let name = reservation_node_name(r.name, r.addr);
        let child = match rm.children.iter_mut().find(|c| c.name == name) {
            Some(c) => c,
            None => {
                rm.children.push(crate::fdt::Node::new(&name));
                rm.children.last_mut().unwrap()
            }
        };
        child.set_prop_cells(
            "reg",
            &[
                (r.addr >> 32) as u32,
                (r.addr & 0xffff_ffff) as u32,
                (r.size >> 32) as u32,
                (r.size & 0xffff_ffff) as u32,
            ],
        );
        // Explicitly *absent*: `no-map`. See above.
        child.props.retain(|p| p.name != "no-map");
    }

    let out = f.serialise();
    if out.len() > DTB_REGION_SIZE as usize {
        return Err(format!(
            "edited DTB is {} bytes, which exceeds its {} byte region at {:#x}",
            out.len(),
            DTB_REGION_SIZE,
            DTB_ADDR
        ));
    }
    // The command line and the AUSB tunables must agree, or the boot is half-configured in a way
    // that looks like a driver bug: a `console=ttyGS0` with no PHY tunables waits forever for a
    // gadget that cannot bind, and tunables with no `console=ttyGS0` mean nothing ever reads the
    // console we went to the trouble of enabling.
    let has_token = plan.bootargs.as_str().split_whitespace().any(|t| t == "console=ttyGS0");
    match (opts.ausb.is_some(), has_token) {
        (true, false) => {
            return Err("AUSB tunables supplied but the command line has no console=ttyGS0: the \
                        gadget console would be enabled and unread. Recompute the plan with \
                        usb_console = true."
                .to_string())
        }
        (false, true) => {
            return Err("the command line promises console=ttyGS0 but no AUSB tunables were \
                        supplied: the PHY will not probe and that console will never appear. Run \
                        the probe first, or drop the token."
                .to_string())
        }
        _ => {}
    }
    // Re-parse: a serialiser bug that produces a tree the kernel cannot read is the kind of
    // failure that only shows up as a hang, so it is caught here instead.
    let check = crate::fdt::Fdt::parse(&out)?;
    let mem = check.root.child_prefix("memory@").ok_or("edited DTB lost its memory node")?;
    if mem.prop_cells("reg").is_none() {
        return Err("edited DTB's memory node has an unreadable reg".to_string());
    }
    Ok(out)
}

/// The descriptor the payload validates. Field by field, from the plan — no value is typed twice.
pub fn build_descriptor(plan: &Plan, header: &Header, opts: &EditOptions) -> Result<Descriptor, String> {
    if header.entry_addr(IMAGE_2M_BASE).map_err(|e| e.code)? != plan.kernel_entry {
        return Err(format!(
            "plan says the entry is {:#x} but the Image header says {:#x}: the plan was built \
             from a different kernel",
            plan.kernel_entry,
            header.entry_addr(IMAGE_2M_BASE).map_err(|e| e.code)?
        ));
    }
    let mut flags = 0u64;
    if plan.initrd_size > 0 {
        flags |= abi::flags::INITRD_PRESENT;
    }
    if opts.fb_enable {
        flags |= abi::flags::FB_ENABLE;
    }
    Ok(Descriptor {
        magic: abi::DESCRIPTOR_MAGIC,
        version: abi::DESCRIPTOR_VERSION,
        flags,
        dram_base: plan.dram_base,
        dram_size: plan.dram_size,
        dtb_addr: plan.dtb_addr,
        dtb_size: plan.dtb_size,
        image_addr: plan.image_addr,
        image_size: plan.image_size,
        image_text_offset: header.text_offset,
        initrd_addr: plan.initrd_addr,
        initrd_size: plan.initrd_size,
        kernel_entry: plan.kernel_entry,
        mailbox_addr: MAILBOX_ADDR,
        vectors_addr: VECTORS_ADDR,
        vectors_size: VECTORS_SIZE,
        stack_top: EL1_STACK_TOP,
        spin_addr: opts.spin_addr.unwrap_or(0),
        fb_addr: FB_ADDR,
        fb_size: FB_SIZE,
        fb_width: FB_WIDTH as u64,
        fb_height: FB_HEIGHT as u64,
        fb_stride: FB_STRIDE as u64,
        wdt_addr: WDT_ADDR,
        uart_addr: UART_ADDR,
        reserved: [0; 8],
    })
}

// ---------------------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------------------

/// One unit of work, expressed so it can be printed without a device and executed with one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Operator-facing note. Sent nowhere.
    Comment(String),
    /// Write host bytes to a device address, then read them back and compare. A truncated or
    /// misplaced blob is otherwise indistinguishable from a kernel bug.
    WriteVerify { dst: u64, data: Vec<u8> },
    /// Invoke the payload.
    Exec(Command),
    /// Read device memory back (the mailbox, after handoff).
    Read { addr: u64, len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Comment,
    Written { dst: u64, len: usize },
    Exec { cmd: Command, retval: u64, status: &'static str, reply: Vec<u64> },
    Read { addr: u64, data: Vec<u8> },
}

/// What the finished device tree claims, checked against what the loader actually stages.
///
/// This is the loader's own hand-off contract, and it exists because two of its values are
/// dangerous as template constants:
///
/// * **the initrd range** — qemu-validator measured the reference template's implied size at
///   2,670,592 bytes while the real Debian initramfs is 7,503,864. A kernel handed the template
///   values unpacks the first 2.67 MB of a 7.5 MB archive and dies as a VFS error that reads like
///   a rootfs bug. The size must come from *the transfer this host performed*, so the check
///   derives it from the step sequence rather than from any table;
/// * **`cpu-release-addr`** — zero is a documented safe outcome (`smp_spin_table.c:71-72` →
///   `-ENODEV`, `smp.c:810-818` → the CPU is skipped, one core boots); a wrong non-zero value is
///   a wild write into low memory plus a hung CPU1.
///
/// Every failure below is a **named refusal**, because handing off with an unknown initrd size is
/// exactly the "best-effort guess" this project does not accept. Called from `build_steps`, so a
/// dry run and a live run refuse identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffContract {
    pub initrd_start: u64,
    pub initrd_end: u64,
    /// Bytes the step sequence actually stages at `initrd_start`.
    pub initrd_loaded: u64,
    pub cpu_release_addr: u64,
    pub dram_size: u64,
    /// The kernel image's own span, which no other blob may enter.
    pub kernel_span: (u64, u64),
}

impl HandoffContract {
    pub fn report(&self) -> String {
        format!(
            "initrd {:#x}..{:#x} ({} bytes loaded{})\n  cpu-release-addr {:#x} ({})\n  \
             memory size {:#x}\n  kernel image {:#x}..{:#x} (no other blob inside)",
            self.initrd_start,
            self.initrd_end,
            self.initrd_loaded,
            if self.initrd_loaded == 0 { ", no initramfs: written as 0/0" } else { "" },
            self.cpu_release_addr,
            if self.cpu_release_addr == 0 {
                "rung 1: the kernel skips cpu1 cleanly"
            } else {
                "rung 2: a real parked secondary"
            },
            self.dram_size,
            self.kernel_span.0,
            self.kernel_span.1,
        )
    }
}

/// Read the finished DTB back and prove it agrees with the transfer that was planned.
pub fn handoff_contract(
    dtb: &[u8],
    plan: &Plan,
    steps: &[Step],
    opts: &EditOptions,
) -> Result<HandoffContract, String> {
    let f = crate::fdt::Fdt::parse(dtb)?;
    let chosen = f
        .root
        .child("chosen")
        .ok_or("HANDOFF_NO_CHOSEN: the edited tree has no /chosen node")?;

    // The prefix tripwire. `initrd-start` without `linux,` is silently ignored by the kernel,
    // which then panics with `VFS: Cannot open root device` — a property-name bug wearing a
    // rootfs bug's clothes.
    for bad in ["initrd-start", "initrd-end"] {
        if chosen.prop(bad).is_some() {
            return Err(format!(
                "HANDOFF_INITRD_PROPERTY_MISNAMED: /chosen carries `{bad}` instead of \
                 `linux,{bad}`. The kernel ignores the un-prefixed name."
            ));
        }
    }
    let start = chosen
        .prop_u64("linux,initrd-start")
        .ok_or("HANDOFF_INITRD_PROPERTY_MISSING: /chosen has no readable linux,initrd-start")?;
    let end = chosen
        .prop_u64("linux,initrd-end")
        .ok_or("HANDOFF_INITRD_PROPERTY_MISSING: /chosen has no readable linux,initrd-end")?;

    // The byte count is derived from the *steps*: the write that targets the initrd's address is
    // the transfer this loader will perform, so its length is the honest answer.
    let staged = steps.iter().find_map(|s| match s {
        Step::WriteVerify { dst, data } if *dst == plan.initrd_addr => Some(data.len() as u64),
        _ => None,
    });
    let loaded = match (staged, plan.initrd_size) {
        (Some(n), _) => n,
        (None, 0) => 0,
        (None, want) => {
            return Err(format!(
                "HANDOFF_INITRD_SIZE_UNKNOWN: the plan reserves {want:#x} bytes at {:#x} for an \
                 initramfs, but no write step stages it — so the loader cannot state how many \
                 bytes it loaded. Refusing to hand off rather than guessing.",
                plan.initrd_addr
            ))
        }
    };
    if loaded != plan.initrd_size {
        return Err(format!(
            "HANDOFF_INITRD_PLAN_MISMATCH: the plan says {:#x} bytes, the steps stage {loaded:#x}. \
             The tree and the transfer disagree; one of them was built from a different input.",
            plan.initrd_size
        ));
    }
    if start != plan.initrd_addr {
        return Err(format!(
            "HANDOFF_INITRD_ADDR_MISMATCH: linux,initrd-start is {start:#x} but the initramfs is \
             staged at {:#x}.",
            plan.initrd_addr
        ));
    }
    if end != start + loaded {
        return Err(format!(
            "HANDOFF_INITRD_SIZE_MISMATCH: linux,initrd-end - start = {:#x} bytes, but {loaded:#x} \
             bytes were loaded. This is the template-constant failure: the kernel would unpack \
             the wrong number of bytes and die with a VFS error.",
            end.wrapping_sub(start)
        ));
    }

    // cpu-release-addr on every CPU.
    let want_spin = opts.spin_addr.unwrap_or(0);
    let cpus = f.root.child("cpus").ok_or("HANDOFF_NO_CPUS: the edited tree has no /cpus node")?;
    let mut seen = 0;
    for cpu in cpus.children.iter().filter(|c| c.name.starts_with("cpu@")) {
        let got = cpu.prop_u64("cpu-release-addr").ok_or_else(|| {
            format!("HANDOFF_CPU_RELEASE_MISSING: {} has no readable cpu-release-addr", cpu.name)
        })?;
        if got != want_spin {
            return Err(format!(
                "HANDOFF_CPU_RELEASE_MISMATCH: {} says {got:#x}, expected {want_spin:#x} \
                 ({}).",
                cpu.name,
                if want_spin == 0 {
                    "rung 1 must write zero: a wrong non-zero value is a wild write and a hung cpu1"
                } else {
                    "rung 2: the parked secondary's mailbox"
                }
            ));
        }
        seen += 1;
    }
    if seen == 0 {
        return Err("HANDOFF_NO_CPUS: no cpu@* nodes to check".to_string());
    }

    // The advertised memory size, from the same cells the kernel reads.
    let mem = f
        .root
        .child_prefix("memory@")
        .ok_or("HANDOFF_NO_MEMORY: the edited tree has no memory@ node")?;
    let cells = mem
        .prop_cells("reg")
        .ok_or("HANDOFF_MEMORY_UNREADABLE: memory/reg is not a whole number of cells")?;
    if cells.len() != 4 {
        return Err(format!(
            "HANDOFF_MEMORY_CELLS: memory/reg has {} cells, expected 4 (2 addr + 2 size)",
            cells.len()
        ));
    }
    let dram_size = ((cells[2] as u64) << 32) | cells[3] as u64;
    if dram_size != plan.dram_size {
        return Err(format!(
            "HANDOFF_MEMORY_SIZE_MISMATCH: the tree advertises {dram_size:#x}, the plan says {:#x}",
            plan.dram_size
        ));
    }

    // No blob may sit inside the kernel image's span. `__primary_switched` zeroes the image's bss
    // before `setup_arch` reads the tree or the initrd, so a blob there is total silence.
    let kernel_span = (plan.image_addr, plan.image_addr + plan.image_size);
    for (name, addr, size) in [
        ("dtb", plan.dtb_addr, plan.dtb_size),
        ("initramfs", start, loaded),
    ] {
        if size == 0 {
            continue;
        }
        let blob_end = addr + size;
        if addr < kernel_span.1 && blob_end > kernel_span.0 {
            return Err(format!(
                "HANDOFF_BLOB_INSIDE_KERNEL: the {name} at {addr:#x}..{blob_end:#x} overlaps the \
                 kernel image {:#x}..{:#x}.",
                kernel_span.0, kernel_span.1
            ));
        }
    }

    Ok(HandoffContract {
        initrd_start: start,
        initrd_end: end,
        initrd_loaded: loaded,
        cpu_release_addr: want_spin,
        dram_size,
        kernel_span,
    })
}

/// The largest single control transfer the transport will issue. One EP0-sized `DNLOAD` is what
/// the reference uses and what this project's transport has already proven on the wire; a command
/// larger than this is sent as several consecutive transfers, which the ROM accumulates into its
/// buffer (DESIGN.md §3.3).
pub const DNLOAD_CHUNK: usize = 0x800;

/// The DFU buffer's capacity, until the probe measures it. Conservative on purpose: the host
/// **refuses** to build a plan whose largest command does not fit, because a command that overruns
/// the buffer is a corruption, not a stall.
///
/// This replaces an assumption that the dry run caught: with no budget, `step_packets` emitted the
/// 2.6 MiB initramfs as a *single* 2.6 MiB transfer, which no transport can send and no buffer can
/// hold. The dry run exists to catch exactly that, and did.
/// **MEASURED, not assumed.** The hardware ladder bracketed the channel at
/// `[0x1000, 0x2000)` command bytes: 2048 and 4096 came back intact, 8192 did not
/// (`a9pwn-traces/linux/r18-capacity.json`). The default is therefore the *measured lower bound*
/// (`0x1000`): a budget derived from this value can never be optimistic, and anything that needs
/// more must say so with a measurement rather than inheriting a bigger number. The old 16 KiB
/// assumption is retired — it was 2–4× the truth, and `DESIGN.md:188` says an overrun is
/// corruption rather than a stall.
pub const ASSUMED_BUFFER_CAPACITY: usize = 0x1000;

/// The assumption this replaced, kept named so nothing re-derives from it by accident.
pub const RETIRED_ASSUMED_CAPACITY: usize = 0x4000;

/// What the plan may ask of the channel. Established by `probe` for a real device; the assumed
/// value is used for dry runs and is conservative in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferBudget {
    pub buffer_capacity: usize,
}

impl Default for TransferBudget {
    fn default() -> Self {
        TransferBudget { buffer_capacity: ASSUMED_BUFFER_CAPACITY }
    }
}

impl TransferBudget {
    pub fn from_probe(p: &Probe) -> Self {
        // The probe's walk writes at most 32 bytes per command, so it does not by itself establish
        // the capacity; `Probe` therefore carries only what it measured, and the capacity is
        // passed in from the capacity probe when one has been run.
        let _ = p;
        Self::default()
    }

    /// Data bytes a single command may carry, after the 72-byte header.
    pub fn data_per_command(&self) -> usize {
        self.buffer_capacity.saturating_sub(abi::HEADER_LEN as usize)
    }

    /// Bytes a single read-back may return. The reply cannot exceed the buffer, and the `UPLOAD`
    /// length is a `u16`, so both bounds apply.
    pub fn max_read(&self) -> usize {
        let by_buffer = self.buffer_capacity.saturating_sub(abi::REPLY_OFF as usize);
        let by_u16 = (u16::MAX as usize) - abi::REPLY_OFF as usize;
        let by_transfer = DNLOAD_CHUNK;
        by_buffer.min(by_u16).min(by_transfer)
    }

    /// How many control transfers a `dnload` of this size becomes.
    pub fn transfers(&self, dnload_len: usize) -> usize {
        dnload_len.div_ceil(DNLOAD_CHUNK)
    }

    /// Refuse a packet that cannot be delivered, naming the size and the limit.
    pub fn check(&self, p: &Packet) -> Result<(), String> {
        if p.dnload.len() > self.buffer_capacity {
            return Err(format!(
                "{}: DNLOAD of {} bytes exceeds the {} byte buffer capacity. Raise the capacity \
                 with a probe, or chunk the step smaller.",
                p.label,
                p.dnload.len(),
                self.buffer_capacity
            ));
        }
        Ok(())
    }
}

/// Expand a step into the packets it sends, chunked to what the channel can actually carry.
///
/// `payload` is needed by `Exec` steps and by nothing else, which is exactly why the payload can
/// be non-resident. Every write is followed by a read-back of the *same chunk*, so the dry run
/// prints the same packet sequence a live run sends — one code path, two back ends.
pub fn step_packets(step: &Step, payload: &[u8], budget: &TransferBudget) -> Vec<Packet> {
    let chunk = budget.data_per_command().min(DNLOAD_CHUNK);
    let read_chunk = budget.max_read().max(1);
    match step {
        Step::Comment(_) => Vec::new(),
        Step::WriteVerify { dst, data } => {
            let mut out = Vec::new();
            for (i, part) in data.chunks(chunk).enumerate() {
                let at = dst + (i * chunk) as u64;
                out.push(channel::mem_write(at, part));
                for (k, rpart) in part.chunks(read_chunk).enumerate() {
                    out.push(channel::mem_read(at + (k * read_chunk) as u64, rpart.len()));
                }
            }
            out
        }
        Step::Exec(cmd) => {
            // The payload plus the header and the reply gap travels as one command; the transport
            // turns it into `budget.transfers(len)` control transfers.
            vec![channel::exec_packet(payload, *cmd)]
        }
        Step::Read { addr, len } => {
            let mut out = Vec::new();
            let mut off = 0usize;
            while off < *len {
                let n = read_chunk.min(*len - off);
                out.push(channel::mem_read(addr + off as u64, n));
                off += n;
            }
            out
        }
    }
}

/// The full rung-1 sequence, from "device identified" to "the payload jumped".
///
/// The DRAM probe is **first**, and it is the highest-value five minutes in this project: it is
/// the single measurement the entire layout rests on (UNVERIFIED.md U-1).
pub fn build_steps(blobs: &BootBlobs, plan: &Plan, opts: &EditOptions) -> Result<Vec<Step>, String> {
    let header = Header::parse(&blobs.image).map_err(|e| format!("{} ({:#x})", e.code, e.detail))?;
    header.validate_for_a9().map_err(|e| format!("{} ({:#x})", e.code, e.detail))?;
    // Reserve vs transfer: `image_size` is the footprint to reserve (`.bss` included), the file is
    // what gets transferred. See `Header::check_extent` for why the old equality rule was wrong.
    let extent = header.check_extent(blobs.image.len() as u64).map_err(|e| {
        format!(
            "{} ({:#x}): the stored image cannot be larger than the footprint the kernel's own \
             linker asserted (`_kernel_size_le = _end - _text`)",
            e.code, e.detail
        )
    })?;
    if extent.reserve != plan.image_size {
        return Err(format!(
            "the Image header says the footprint is {:#x} but the plan reserves {:#x}: the \
             reservation must be the header's number, or a blob lands inside the kernel's .bss",
            extent.reserve, plan.image_size
        ));
    }
    let descriptor = build_descriptor(plan, &header, opts)?;
    descriptor.validate().map_err(|(code, detail)| {
        format!("descriptor refused by the host-side check: {} ({:#x})", abi::status::name(code), detail)
    })?;

    let mut steps = Vec::new();
    steps.push(Step::Comment(format!(
        "probe DRAM reachability at {:#x} (the ROM's EL3 translation) - the assumption the \
         whole layout rests on",
        DRAM_BASE
    )));
    for (i, addr) in [DRAM_BASE, DRAM_BASE + 0x4000_0000, DRAM_BASE + DRAM_SIZE - 0x1000].iter().enumerate() {
        steps.push(Step::WriteVerify { dst: *addr, data: dram_pattern(i as u8) });
    }
    steps.push(Step::Comment("write the boot descriptor".to_string()));
    steps.push(Step::WriteVerify { dst: DESCRIPTOR_ADDR, data: descriptor.encode().to_vec() });
    steps.push(Step::Comment("PING: prove the payload runs in place from the DFU buffer".to_string()));
    steps.push(Step::Exec(Command::Ping));
    steps.push(Step::Comment("DESCRIBE: the EL/MMU facts, measured rather than assumed".to_string()));
    steps.push(Step::Exec(Command::Describe));
    steps.push(Step::Comment("stage the device tree".to_string()));
    steps.push(Step::WriteVerify { dst: plan.dtb_addr, data: blobs.dtb.clone() });
    steps.push(Step::Comment("stage the kernel Image".to_string()));
    steps.push(Step::WriteVerify { dst: plan.image_addr, data: blobs.image.clone() });
    if let Some(initrd) = &blobs.initrd {
        steps.push(Step::Comment("stage the initramfs".to_string()));
        steps.push(Step::WriteVerify { dst: plan.initrd_addr, data: initrd.clone() });
    }
    steps.push(Step::Comment("PREPARE: the payload re-validates everything before the point of no return".to_string()));
    steps.push(Step::Exec(Command::Prepare));
    steps.push(Step::Comment(
        "GO: cache clean, EL1 setup, eret. The payload writes the handoff record to the mailbox \
         immediately before eret, so 'we jumped' and 'we died on entry' are distinguishable."
            .to_string(),
    ));
    steps.push(Step::Exec(Command::Go));

    // The hand-off contract is asserted here, inside the one function both a dry run and a live
    // run go through, so an unknown or mismatched initrd size is a named refusal either way.
    handoff_contract(&blobs.dtb, plan, &steps, opts)?;
    Ok(steps)
}

/// The largest single DNLOAD the transport will accept, as established by the capacity probe.
pub const DEFAULT_CHUNK: usize = 0x800 - abi::HEADER_LEN as usize;

/// Split the bulk blobs into chunks so `build_steps` never asks for a transfer bigger than the
/// transport's proven capacity.
pub fn chunk_steps(step: &Step, chunk: usize) -> Vec<Step> {
    match step {
        Step::WriteVerify { dst, data } if data.len() > chunk => {
            let mut out = Vec::new();
            for (i, part) in data.chunks(chunk).enumerate() {
                out.push(Step::WriteVerify { dst: dst + (i * chunk) as u64, data: part.to_vec() });
            }
            out
        }
        other => vec![other.clone()],
    }
}

/// Run steps against a transport. Every write is read back and compared, in chunks the channel can
/// actually carry; a mismatch stops the sequence with the offset named.
///
/// This is the *only* place that talks to a transport, and the chunking here is the same arithmetic
/// `step_packets` prints — so a dry run and a live run send the same bytes.
pub fn execute_steps(
    t: &mut dyn Transport,
    steps: &[Step],
    payload: &[u8],
    budget: &TransferBudget,
) -> Result<Vec<Outcome>, String> {
    let chunk = budget.data_per_command().min(DNLOAD_CHUNK);
    let read_chunk = budget.max_read().max(1);
    let mut out = Vec::new();
    for step in steps {
        match step {
            Step::Comment(_) => out.push(Outcome::Comment),
            Step::WriteVerify { dst, data } => {
                for (i, part) in data.chunks(chunk).enumerate() {
                    let at = dst + (i * chunk) as u64;
                    let w = channel::mem_write(at, part);
                    budget.check(&w)?;
                    run(t, &w)?;
                    let mut off = 0usize;
                    while off < part.len() {
                        let n = read_chunk.min(part.len() - off);
                        let p = channel::mem_read(at + off as u64, n);
                        budget.check(&p)?;
                        let raw = run(t, &p)?;
                        let r = channel::parse_response(&raw, p.upload_len)?;
                        if r.data.len() < n {
                            return Err(format!(
                                "read-back of {:#x} returned {} bytes, wanted {}",
                                at + off as u64,
                                r.data.len(),
                                n
                            ));
                        }
                        let want = &part[off..off + n];
                        if &r.data[..n] != want {
                            let first = r.data[..n]
                                .iter()
                                .zip(want.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or(0);
                            return Err(format!(
                                "read-back of {:#x} differs at +{:#x}: wrote {:#04x}, read {:#04x}. \
                                 The device did not store what was sent; nothing further is staged.",
                                at + off as u64,
                                first,
                                want[first],
                                r.data[first]
                            ));
                        }
                        off += n;
                    }
                }
                out.push(Outcome::Written { dst: *dst, len: data.len() });
            }
            Step::Exec(cmd) => {
                let p = channel::exec_packet(payload, *cmd);
                budget.check(&p)?;
                let raw = run(t, &p)?;
                let r = channel::parse_response(&raw, p.upload_len)?;
                let reply = r.reply().ok();
                if r.retval != abi::status::OK {
                    return Err(format!(
                        "{} returned {} ({}): {}",
                        cmd.name(),
                        r.retval,
                        abi::status::name(r.retval),
                        reply.map(|x| describe_reply(&x)).unwrap_or_else(|| "no structured reply".into())
                    ));
                }
                let words = reply.as_ref().map(words_of).unwrap_or_default();
                out.push(Outcome::Exec { cmd: *cmd, retval: r.retval, status: r.status_name(), reply: words });
            }
            Step::Read { addr, len } => {
                let mut data = Vec::with_capacity(*len);
                let mut off = 0usize;
                while off < *len {
                    let n = read_chunk.min(*len - off);
                    let p = channel::mem_read(addr + off as u64, n);
                    budget.check(&p)?;
                    let raw = run(t, &p)?;
                    let r = channel::parse_response(&raw, p.upload_len)?;
                    if r.data.len() < n {
                        return Err(format!(
                            "read of {:#x} returned {} bytes, wanted {}",
                            addr + off as u64,
                            r.data.len(),
                            n
                        ));
                    }
                    data.extend_from_slice(&r.data[..n]);
                    off += n;
                }
                out.push(Outcome::Read { addr: *addr, data });
            }
        }
    }
    Ok(out)
}

fn run(t: &mut dyn Transport, p: &Packet) -> Result<Vec<u8>, String> {
    let e = Exchange::from(p);
    t.exchange(&e).map_err(|err| format!("{}: {}", p.label, err))
}

fn words_of(r: &abi::Reply) -> Vec<u64> {
    vec![
        r.command, r.status, r.current_el, r.scr_el3, r.sctlr_el3, r.ttbr0_el3, r.tcr_el3,
        r.cptr_el3, r.midr_el1, r.mpidr_el1, r.cntfrq_el0, r.sctlr_el1, r.esr_el1, r.detail,
    ]
}

/// One line per reply field, with the field *names*, because a bare hex dump of the DESCRIBE
/// reply is not a diagnosis.
pub fn describe_reply(r: &abi::Reply) -> String {
    format!(
        "command={} current_el={:#x} scr_el3={:#x} sctlr_el3={:#x} ttbr0_el3={:#x} tcr_el3={:#x} \
         cptr_el3={:#x} midr={:#x} mpidr={:#x} cntfrq={:#x} sctlr_el1={:#x} esr_el1={:#x} detail={:#x}",
        r.command, r.current_el, r.scr_el3, r.sctlr_el3, r.ttbr0_el3, r.tcr_el3, r.cptr_el3,
        r.midr_el1, r.mpidr_el1, r.cntfrq_el0, r.sctlr_el1, r.esr_el1, r.detail
    )
}

/// The 32-byte pattern the DRAM probe writes. Distinct per address so an aliased or mirrored
/// region is visible as a wrong read rather than a lucky match.
pub fn dram_pattern(seed: u8) -> Vec<u8> {
    (0..32u8).map(|i| i.wrapping_mul(37).wrapping_add(seed)).collect()
}

/// Read the mailbox and decode it. The only post-handoff evidence that exists (DESIGN.md §5.3).
pub fn read_mailbox(t: &mut dyn Transport) -> Result<abi::Mailbox, String> {
    let p = channel::mem_read(MAILBOX_ADDR, abi::MAILBOX_SIZE);
    let raw = run(t, &p)?;
    let r = channel::parse_response(&raw, p.upload_len)?;
    abi::Mailbox::decode(&r.data).map_err(|e| format!("{} ({:#x})", e.code, e.detail))
}

/// Where the bootargs buffer's capacity is asserted, so a longer command line fails at plan time
/// rather than on the device.
pub const fn bootargs_capacity() -> usize {
    BOOTARGS_CAP
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::SimDevice;
    use a9boot_core::plan::Inputs;

    // -------------------------------------------------------------------------------
    // The probe selector, and the honesty of "not measured"
    // -------------------------------------------------------------------------------

    /// The rule the Lead's first real `plan` run falsified: `image_size` is the footprint to
    /// RESERVE (`.bss` included), the file is what is TRANSFERRED, and a gap is normal.
    #[test]
    fn a_kernel_with_bss_stages_while_reserving_the_whole_footprint() {
        let (mut blobs, mut plan, opts) = fixture();
        // Grow the header's footprint past the file, exactly as the real kernel does, and let the
        // plan reserve the larger footprint — the two must move together or a blob lands in .bss.
        let file_len = blobs.image.len() as u64;
        blobs.image[16..24].copy_from_slice(&(file_len + 0x9000).to_le_bytes());
        plan.image_size = file_len + 0x9000;
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        assert!(steps.iter().any(|s| matches!(s, Step::WriteVerify { data, .. } if data.len() as u64 == file_len)));
        // And the reservation must be the header's number: if the plan keeps the old one, a blob
        // would land inside the kernel's .bss, which is the failure the check exists to prevent.
        let (mut blobs2, plan2, opts2) = fixture();
        blobs2.image[16..24].copy_from_slice(&(file_len + 0x9000).to_le_bytes());
        let e = build_steps(&blobs2, &plan2, &opts2).unwrap_err();
        assert!(e.contains("the plan reserves"), "{e}");
    }

    #[test]
    fn a_file_larger_than_its_footprint_is_refused_by_name() {
        let (mut blobs, plan, opts) = fixture();
        let file_len = blobs.image.len() as u64;
        blobs.image[16..24].copy_from_slice(&(file_len - 8).to_le_bytes());
        let e = build_steps(&blobs, &plan, &opts).unwrap_err();
        assert!(e.contains("IMAGE_FILE_EXCEEDS_FOOTPRINT"), "{e}");
    }

    #[test]
    fn the_host_pair_is_zero_because_it_was_never_measured() {
        // The ruling, pinned. If someone later changes this to mirror the device pair, they must
        // also bring a measurement: the device pair is MEASURED (RUNG2-EVIDENCE §2), the host pair
        // is not, and the two must not be spelled the same way.
        let measured = AusbTunables { cfg0_device: 0x3737_23F3, cfg1_device: 0x0002_0E04 };
        assert_eq!(measured.host_pair(), (0, 0));
        assert_ne!(measured.host_pair().0, measured.cfg0_device);
        assert!(measured.looks_plausible(), "the device pair is still the measured one");
    }

    #[test]
    fn only_ausb_removes_every_dram_step() {
        // The property the Lead needs before sending: `--only ausb` must contain no write to
        // DRAM at all, so the AUSB registers can be read on hardware without a DRAM walk.
        let steps = probe_steps_filtered(Some(ProbePart::Ausb), None);
        assert!(steps.iter().all(|s| !matches!(s, Step::WriteVerify { .. })));
        assert_eq!(steps.iter().filter(|s| matches!(s, Step::Read { .. })).count(), 1);
        let full = probe_steps();
        assert!(full.iter().any(|s| matches!(s, Step::WriteVerify { .. })));
        // The full list is unchanged by the selector's existence.
        assert_eq!(full.len(), 2 + 1 + dram_walk_addresses().len(), "2 comments + 1 read + the walk");
    }

    #[test]
    fn only_dram_removes_the_ausb_read_and_skip_removes_one_half() {
        let d = probe_steps_filtered(Some(ProbePart::Dram), None);
        assert!(d.iter().all(|s| !matches!(s, Step::Read { .. })));
        assert!(d.iter().any(|s| matches!(s, Step::WriteVerify { .. })));
        let s = probe_steps_filtered(None, Some(ProbePart::Dram));
        assert!(s.iter().all(|s| !matches!(s, Step::WriteVerify { .. })));
        assert!(s.iter().any(|s| matches!(s, Step::Read { .. })));
    }

    #[test]
    fn an_empty_selection_is_empty_and_must_be_refused_by_the_caller() {
        // `--only ausb --skip ausb` selects nothing. The filter is honest about that; the CLI
        // refuses it before opening the device, because a run that measures nothing must not be
        // reported as PASS (that was a real defect: the probe's verdict started at Pass).
        assert!(probe_steps_filtered(Some(ProbePart::Ausb), Some(ProbePart::Ausb)).is_empty());
        assert!(probe_steps_filtered(Some(ProbePart::Dram), Some(ProbePart::Dram)).is_empty());
        // And a run with no steps never sets `dram_walk_ran`, so the extent stays UNMEASURED.
        let mut dev = SimDevice::new(0x4000);
        let p = run_probe_with(&mut dev, vec![]).unwrap();
        assert!(!p.dram_measured());
        assert_eq!(p.dram_extent(), 0);
    }

    #[test]
    fn a_probe_that_skipped_the_walk_reports_unmeasured_not_zero() {
        // The trap: `dram_last_ok` defaults to 0, so the old arithmetic underflowed (or, in
        // release, wrapped) and reported an extent from a walk that never ran.
        let mut dev = SimDevice::new(0x4000);
        let p = run_probe_with(&mut dev, probe_steps_filtered(Some(ProbePart::Ausb), None)).unwrap();
        assert!(!p.dram_measured());
        assert_eq!(p.dram_extent(), 0);
        let r = p.report();
        assert!(r.contains("NOT MEASURED"), "{r}");
        assert!(r.contains("0 is not a measurement"), "{r}");
        assert!(p.ausb.is_some(), "the AUSB half did run");
    }

    #[test]
    fn a_walk_that_ran_and_passed_still_carries_the_cache_caveat() {
        let mut dev = SimDevice::new(0x4000);
        let p = run_probe(&mut dev).unwrap();
        assert!(p.dram_measured());
        assert_eq!(p.dram_extent(), DRAM_SIZE, "the simulator models the whole nominal range");
        let r = p.report();
        assert!(r.contains("the walk cannot see a cache"), "{r}");
        assert!(r.contains("a FAILURE below is real evidence"), "{r}");
    }

    fn fake_image(size: usize, text_offset: u64) -> Vec<u8> {
        let mut v = vec![0u8; size];
        v[8..16].copy_from_slice(&text_offset.to_le_bytes());
        v[16..24].copy_from_slice(&(size as u64).to_le_bytes());
        v[24..32].copy_from_slice(&(2u64 << 1).to_le_bytes());
        v[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
        v
    }

    /// A small `Image`: the layout maths does not care about the size, and a 16 MiB fixture
    /// crawling through the simulator one 1976-byte chunk at a time turned a unit test into a
    /// 72-second job. The plan's size arithmetic is exercised by `a9boot-core`'s own tests.
    fn fixture() -> (BootBlobs, Plan, EditOptions) {
        fixture_with_initrd(0x4000, &[])
    }

    /// The fixture now goes through the *same* order the real tool does: raw tree → plan → edit →
    /// adopt the edited size → blobs. Building steps from an unedited tree is exactly what the
    /// hand-off assertion caught in the first version of these tests, and it is a caller error
    /// worth failing loudly on.
    ///
    /// `stale_initrd` seeds the source tree with a plausible-looking fixed pair, which is the
    /// template hazard the Lead's decision is about.
    fn fixture_with_initrd(initrd_len: usize, stale_initrd: &[(u64, u64)]) -> (BootBlobs, Plan, EditOptions) {
        let image = fake_image(0x8000, 0x80000);
        let raw_dtb = minimal_dtb_with_stale_initrd(stale_initrd);
        let initrd = if initrd_len > 0 { Some(vec![7u8; initrd_len]) } else { None };
        let opts = EditOptions::default();
        let mut plan = a9boot_core::plan::compute(&Inputs {
            image_size: 0x8000,
            image_text_offset: 0x80000,
            dtb_size: raw_dtb.len() as u64,
            initrd_size: initrd_len as u64,
            ..Default::default()
        })
        .unwrap();
        let dtb = edit_dtb(&raw_dtb, &plan, &opts).unwrap();
        plan.adopt_edited_dtb(dtb.len() as u64).unwrap();
        let blob = BootBlobs { payload: vec![0u8; 256], dtb, image, initrd };
        (blob, plan, opts)
    }

    /// The same plan, with or without the USB gadget console in the command line.
    fn plan_with_usb(blobs: &BootBlobs, usb: bool) -> Plan {
        a9boot_core::plan::compute(&Inputs {
            image_size: blobs.image.len() as u64,
            image_text_offset: 0x80000,
            dtb_size: blobs.dtb.len() as u64,
            initrd_size: blobs.initrd.as_ref().map(|i| i.len() as u64).unwrap_or(0),
            usb_console: usb,
            ..Default::default()
        })
        .unwrap()
    }

    fn minimal_dtb() -> Vec<u8> {
        minimal_dtb_with_stale_initrd(&[])
    }

    /// A DTB carrying exactly the placeholders the real board DTB has.
    fn minimal_dtb_with_stale_initrd(stale: &[(u64, u64)]) -> Vec<u8> {
        use crate::fdt::{Fdt, Node};
        let mut root = Node::new("");
        let mut chosen = Node::new("chosen");
        chosen.set_prop_str("stdout-path", "serial0");
        // Seed the template hazard when asked: a plausible-looking fixed initrd pair, of the kind
        // the reference `n69-loader-target.dtb` carries (`<0x08 0x10000000>` .. `<0x08 0x1028c000>`
        // = 2,670,592 bytes while the real Debian initramfs is 7,503,864).
        for (start, end) in stale {
            chosen.set_prop_u64_cells("linux,initrd-start", *start);
            chosen.set_prop_u64_cells("linux,initrd-end", *end);
        }
        let mut fb = Node::new("framebuffer@0");
        fb.set_prop_str("compatible", "apple,simple-framebuffer");
        fb.set_prop_cells("reg", &[0, 0, 0, 0]);
        fb.set_prop_str("status", "disabled");
        chosen.children.push(fb);
        root.children.push(chosen);
        let mut mem = Node::new("memory@800000000");
        mem.set_prop_cells("reg", &[0x8, 0, 0, 0]);
        root.children.push(mem);
        let mut cpus = Node::new("cpus");
        let mut c0 = Node::new("cpu@0");
        c0.set_prop_cells("cpu-release-addr", &[0, 0]);
        let mut c1 = Node::new("cpu@1");
        c1.set_prop_cells("cpu-release-addr", &[0, 0]);
        cpus.children.push(c0);
        cpus.children.push(c1);
        root.children.push(cpus);
        // The AUSB PHY, nested two levels deep as it is on the real board
        // (`/soc/bus@20c000000/phy@20c000030`), so the compatible-based search is exercised.
        let mut soc = Node::new("soc");
        let mut bus = Node::new("bus@20c000000");
        let mut phy = Node::new("phy@20c000030");
        phy.set_prop_strlist("compatible", &["apple,s8000-ausb-phy", "apple,ausb-phy"]);
        phy.set_prop_cells("reg", &[0x2, 0x0c00_0030, 0, 0x20]);
        bus.children.push(phy);
        soc.children.push(bus);
        root.children.push(soc);
        Fdt { root, memrsv: vec![], boot_cpuid_phys: 0, padding: 0x400 }.serialise()
    }

    /// Every reservation this loader owns must be a `/reserved-memory` child, plain (never
    /// `no-map`), because the kernel has to be able to read the DTB and — in rung 2 — write the
    /// spin-table mailbox inside the loader area (`LOADER-FILL.md` §2, §10).
    #[test]
    fn reservations_are_plain_reserved_memory_children() {
        let (blobs, plan, opts) = fixture();
        let out = edit_dtb(&blobs.dtb, &plan, &opts).unwrap();
        let f = crate::fdt::Fdt::parse(&out).unwrap();
        let rm = f.root.child("reserved-memory").expect("reserved-memory node");
        assert_eq!(rm.prop_cells("#address-cells").unwrap(), vec![2]);
        assert_eq!(rm.prop_cells("#size-cells").unwrap(), vec![2]);
        for r in plan.reservations() {
            let name = reservation_node_name(r.name, r.addr);
            let child = rm.child(&name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(
                child.prop_cells("reg").unwrap(),
                vec![
                    (r.addr >> 32) as u32,
                    (r.addr & 0xffff_ffff) as u32,
                    (r.size >> 32) as u32,
                    (r.size & 0xffff_ffff) as u32
                ],
                "{name} reg"
            );
            assert!(
                child.prop("no-map").is_none(),
                "{name} must not be no-map: the kernel needs to reach it"
            );
        }
        // The loader area is the one the spin-table mailbox lives in, so check it by name.
        assert!(rm.child("loader@87fe00000").is_some());
        assert!(rm.child("framebuffer@878000000").is_some());
    }

    /// The AUSB tunables are a *readback*, and they are what unblocks the USB gadget console.
    #[test]
    fn ausb_tunables_are_written_as_single_cells() {
        let (blobs, _plan, _) = fixture();
        let ausb = AusbTunables { cfg0_device: 0x0000_1234, cfg1_device: 0x0000_5678 };
        // The plan must have been computed *with* the gadget console in mind, which is what
        // makes the bootargs and the PHY properties agree.
        let plan = plan_with_usb(&blobs, true);
        let opts = EditOptions { ausb: Some(ausb), ..Default::default() };
        let out = edit_dtb(&blobs.dtb, &plan, &opts).unwrap();
        let f = crate::fdt::Fdt::parse(&out).unwrap();
        let phy = f.root.find_by_compatible("apple,ausb-phy").expect("PHY node found by compatible");
        assert_eq!(phy.prop_cells("apple,cfg0-device").unwrap(), vec![0x1234]);
        assert_eq!(phy.prop_cells("apple,cfg1-device").unwrap(), vec![0x5678]);
        // The host pair is unused in peripheral mode but must be present (ausb.c:149-156).
        assert!(phy.prop("apple,cfg0-host").is_some());
        assert!(phy.prop("apple,cfg1-host").is_some());
        let chosen = f.root.child("chosen").unwrap();
        assert!(chosen.prop_str("bootargs").unwrap().contains("console=ttyGS0"));

        // Without tunables, USB stays dead and the bootargs must NOT promise a gadget console.
        let plan_none = plan_with_usb(&blobs, false);
        let out2 = edit_dtb(&blobs.dtb, &plan_none, &EditOptions::default()).unwrap();
        let f2 = crate::fdt::Fdt::parse(&out2).unwrap();
        assert!(!f2.root.child("chosen").unwrap().prop_str("bootargs").unwrap().contains("ttyGS0"));
        let phy2 = f2.root.find_by_compatible("apple,ausb-phy").unwrap();
        assert!(phy2.prop("apple,cfg0-device").is_none());
    }

    /// A half-configured console is refused rather than shipped: either token without its
    /// counterpart produces a boot that looks like a driver bug.
    #[test]
    fn a_half_configured_usb_console_is_refused() {
        let (blobs, plan_no_usb, _) = fixture();
        let ausb = AusbTunables { cfg0_device: 1, cfg1_device: 2 };
        // Tunables, but a command line without the token.
        let e = edit_dtb(&blobs.dtb, &plan_no_usb, &EditOptions { ausb: Some(ausb), ..Default::default() })
            .unwrap_err();
        assert!(e.contains("console=ttyGS0"), "{e}");

        // The token, but no tunables.
        let plan_usb = plan_with_usb(&blobs, true);
        let e = edit_dtb(&blobs.dtb, &plan_usb, &EditOptions::default()).unwrap_err();
        assert!(e.contains("no AUSB tunables"), "{e}");
    }

    #[test]
    fn ausb_plausibility_check() {
        assert!(!AusbTunables::default().looks_plausible(), "all zero is not plausible");
        assert!(!AusbTunables { cfg0_device: u32::MAX, cfg1_device: u32::MAX }.looks_plausible());
        assert!(AusbTunables { cfg0_device: 1, cfg1_device: 2 }.looks_plausible());
    }

    #[test]
    fn the_edit_fills_every_placeholder_the_board_ships_with() {
        let (blobs, plan, opts) = fixture();
        let out = edit_dtb(&blobs.dtb, &plan, &opts).unwrap();
        let f = crate::fdt::Fdt::parse(&out).unwrap();
        assert_eq!(
            f.root.child_prefix("memory@").unwrap().prop_cells("reg").unwrap(),
            vec![0x8, 0, 0, 0x8000_0000],
            "the kernel must be told it has 2 GiB"
        );
        let chosen = f.root.child("chosen").unwrap();
        assert_eq!(chosen.prop_str("bootargs").unwrap(), a9boot_core::plan::BOOTARGS_CONTRACT);
        assert_eq!(chosen.prop_u64("linux,initrd-start").unwrap(), plan.initrd_addr);
        assert_eq!(
            chosen.prop_u64("linux,initrd-end").unwrap(),
            plan.initrd_addr + plan.initrd_size
        );
        let fb = chosen.child_prefix("framebuffer@").unwrap();
        assert_eq!(fb.prop_cells("reg").unwrap(), vec![0x8, 0x7800_0000, 0, 0x40_0000]);
        assert_eq!(fb.prop_cells("width").unwrap(), vec![640]);
        assert_eq!(fb.prop_cells("height").unwrap(), vec![1136]);
        assert_eq!(fb.prop_cells("stride").unwrap(), vec![2560]);
        assert_eq!(fb.prop_str("format").unwrap(), "a8r8g8b8");
        assert_eq!(fb.prop_str("status").unwrap(), "disabled", "rung 1 does not claim a panel");
        // Every region we own is reserved, as a plain reserved-memory child.
        let rm = f.root.child("reserved-memory").expect("reserved-memory node");
        assert!(rm.child("loader@87fe00000").is_some());
        assert!(rm.child("framebuffer@878000000").is_some());
        assert!(rm.children.iter().any(|c| c.name.starts_with("initramfs@")));
    }

    #[test]
    fn rung_1_leaves_the_second_cpu_alone() {
        let (blobs, plan, opts) = fixture();
        let out = edit_dtb(&blobs.dtb, &plan, &opts).unwrap();
        let f = crate::fdt::Fdt::parse(&out).unwrap();
        let cpus = f.root.child("cpus").unwrap();
        assert_eq!(cpus.child("cpu@0").unwrap().prop_u64("cpu-release-addr").unwrap(), 0);
        assert_eq!(cpus.child("cpu@1").unwrap().prop_u64("cpu-release-addr").unwrap(), 0);
    }

    #[test]
    fn rung_2_can_fill_the_spin_mailbox_and_enable_the_fb() {
        let (blobs, plan, _) = fixture();
        let opts = EditOptions { spin_addr: Some(SPIN_MAILBOX_ADDR), fb_enable: true, ausb: None };
        let out = edit_dtb(&blobs.dtb, &plan, &opts).unwrap();
        let f = crate::fdt::Fdt::parse(&out).unwrap();
        assert_eq!(
            f.root.child("cpus").unwrap().child("cpu@1").unwrap().prop_u64("cpu-release-addr").unwrap(),
            SPIN_MAILBOX_ADDR
        );
        assert_eq!(
            f.root.child("chosen").unwrap().child_prefix("framebuffer@").unwrap().prop_str("status").unwrap(),
            "okay"
        );
    }

    /// The descriptor the payload validates must pass the *same* validation the payload runs.
    #[test]
    fn the_descriptor_passes_the_payloads_own_validation() {
        let (blobs, plan, opts) = fixture();
        let header = Header::parse(&blobs.image).unwrap();
        let d = build_descriptor(&plan, &header, &opts).unwrap();
        d.validate().expect("the payload's validator must accept what the host builds");
        assert_eq!(d.kernel_entry, d.image_addr);
        assert_eq!(d.flags & abi::flags::FB_ENABLE, 0, "rung 1 never sets FB_ENABLE");
        assert_ne!(d.flags & abi::flags::INITRD_PRESENT, 0);
        assert_eq!(abi::Descriptor::decode(&d.encode()).unwrap(), d);
    }

    #[test]
    fn a_descriptor_for_the_wrong_kernel_is_refused() {
        let (blobs, plan, opts) = fixture();
        let mut header = Header::parse(&blobs.image).unwrap();
        header.text_offset = 0; // plan was built with 0x80000
        let e = build_descriptor(&plan, &header, &opts).unwrap_err();
        assert!(e.contains("different kernel"), "{e}");
    }

    /// The whole rung-1 sequence, end to end, against the channel simulator. This is what makes
    /// the dry run meaningful: the same steps, byte for byte, that a live run would send.
    #[test]
    fn the_full_sequence_runs_against_the_simulator_and_verifies_every_write() {
        let (blobs, plan, opts) = fixture();
        let mut dev = SimDevice::new(0x4000);
        // Stand in for the payload: accept every command, reply with a DESCRIBE-shaped record.
        dev.on_exec(|cmd, _desc| {
            let r = abi::Reply { command: cmd, status: abi::status::OK, current_el: 0xc, ..Default::default() };
            (abi::status::OK, r.encode().to_vec())
        });
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        let outcomes = execute_steps(&mut dev, &steps, &blobs.payload, &TransferBudget::default()).unwrap();

        // Every blob landed at the address the plan promised.
        assert_eq!(dev.peek(plan.dtb_addr, blobs.dtb.len()), blobs.dtb);
        assert_eq!(dev.peek(plan.image_addr, blobs.image.len()), blobs.image);
        assert_eq!(dev.peek(plan.initrd_addr, 0x4000), vec![7u8; 0x4000]);
        // And the descriptor the payload will read back decodes to what the host built.
        let raw = dev.peek(DESCRIPTOR_ADDR, abi::DESCRIPTOR_SIZE);
        let d = abi::Descriptor::decode(&raw).unwrap();
        d.validate().unwrap();
        assert_eq!(d.image_size, blobs.image.len() as u64);
        // The sequence ended with GO, and every Exec reported its status by name.
        let execs: Vec<_> = outcomes
            .iter()
            .filter_map(|o| match o {
                Outcome::Exec { cmd, status, .. } => Some((*cmd, *status)),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            vec![
                (Command::Ping, "OK"),
                (Command::Describe, "OK"),
                (Command::Prepare, "OK"),
                (Command::Go, "OK")
            ]
        );
    }

    /// A write that the device fails to store must stop the sequence, with the offset named —
    /// never continue into a boot with a silently truncated kernel.
    #[test]
    fn a_bad_read_back_stops_everything_immediately() {
        let (blobs, plan, opts) = fixture();
        struct Liar(SimDevice);
        impl Transport for Liar {
            fn serial(&mut self) -> Result<String, String> {
                self.0.serial()
            }
            fn exchange(&mut self, e: &Exchange) -> Result<Vec<u8>, String> {
                let mut v = self.0.exchange(e)?;
                // Corrupt every read-back response.
                if e.label.starts_with("memc read") && v.len() > 16 {
                    v[16] ^= 0xff;
                }
                Ok(v)
            }
            fn describe(&self) -> String {
                "liar".into()
            }
        }
        let mut dev = Liar(SimDevice::new(0x4000));
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        let e = execute_steps(&mut dev, &steps, &blobs.payload, &TransferBudget::default()).unwrap_err();
        assert!(e.contains("differs at"), "{e}");
        assert!(e.contains("nothing further is staged"), "{e}");
    }

    /// The DRAM probe is first in the sequence, and it fails loudly on a device whose ROM
    /// translation does not reach DRAM. That is UNVERIFIED.md U-1, and it is the whole reason
    /// the probe exists.
    #[test]
    fn the_dram_probe_is_first_and_fails_loudly_when_dram_is_unreachable() {
        let (blobs, plan, opts) = fixture();
        let mut dev = SimDevice::new(0x4000).with_dram_unreachable();
        dev.on_exec(|cmd, _| (abi::status::OK, abi::Reply { command: cmd, ..Default::default() }.encode().to_vec()));
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        match &steps[0] {
            Step::Comment(c) => assert!(c.contains("probe DRAM reachability"), "{c}"),
            other => panic!("the first step must be the DRAM probe, got {other:?}"),
        }
        let e = execute_steps(&mut dev, &steps, &blobs.payload, &TransferBudget::default()).unwrap_err();
        assert!(e.contains("not reachable"), "{e}");
        assert!(e.contains("PLAN B"), "{e}");
    }

    /// Chunking splits a big blob without moving it, and the last chunk carries the remainder.
    #[test]
    fn chunking_is_contiguous() {
        let step = Step::WriteVerify { dst: 0x1000, data: (0..100u8).collect() };
        let parts = chunk_steps(&step, 32);
        assert_eq!(parts.len(), 4);
        let mut reassembled = Vec::new();
        let mut expect_dst = 0x1000;
        for p in &parts {
            match p {
                Step::WriteVerify { dst, data } => {
                    assert_eq!(*dst, expect_dst);
                    expect_dst += data.len() as u64;
                    reassembled.extend_from_slice(data);
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(reassembled, (0..100u8).collect::<Vec<u8>>());
    }

    /// The image-size disagreement is caught on the host, not on the device.
    #[test]
    fn a_truncated_image_file_is_refused_by_name() {
        // The old rule was `image_size == file_len`, which the Lead's first real `plan` run
        // falsified: it rejected the shipped kernel (image_size 0x1370000, file 0x12d7200, the
        // difference being .bss). What is refused now is the *structural* impossibility — a stored
        // image larger than the footprint the kernel's linker asserted — and, for the tail
        // truncation the header cannot see, a declared artefact size or hash.
        let (mut blobs, plan, opts) = fixture();
        blobs.image.truncate(0x1000);
        // A truncated tail is *not* detectable from the header, and the code must not pretend
        // otherwise: this is accepted, with the plan reserving the header's footprint.
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        assert!(steps.iter().any(|s| matches!(s, Step::WriteVerify { .. })));

        // Grow the file past its footprint: now it is structurally impossible, and refused.
        let (mut blobs, plan, opts) = fixture();
        let file_len = blobs.image.len() as u64;
        blobs.image[16..24].copy_from_slice(&(file_len - 8).to_le_bytes());
        let e = build_steps(&blobs, &plan, &opts).unwrap_err();
        assert!(e.contains("IMAGE_FILE_EXCEEDS_FOOTPRINT"), "{e}");
    }

    #[test]
    fn dry_run_packets_never_need_a_device() {
        let (blobs, plan, opts) = fixture();
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        let mut n = 0;
        for s in &steps {
            n += step_packets(s, &blobs.payload, &TransferBudget::default()).len();
        }
        assert!(n >= 8, "expected a full sequence, got {n} packets");
        // A comment sends nothing at all.
        assert!(step_packets(&Step::Comment("x".into()), &[], &TransferBudget::default()).is_empty());
    }

    #[test]
    fn dram_patterns_are_distinct_per_seed() {
        assert_ne!(dram_pattern(0), dram_pattern(1));
        assert_ne!(dram_pattern(1), dram_pattern(2));
        assert_eq!(dram_pattern(0).len(), 32);
    }

    /// **The template hazard, as a test.** The reference target DTB carries
    /// `linux,initrd-start = <0x08 0x10000000>` / `-end = <0x08 0x1028c000>` — 2,670,592 bytes —
    /// while rootfs-engineer's real Debian initramfs is 7,503,864. If a9boot ever preserved a
    /// template value, the kernel would unpack the first 2.67 MB of a 7.5 MB archive and die with
    /// a VFS error that reads like a rootfs bug. So: seed the stale pair, edit, and assert the
    /// finished tree carries the loaded bytes and nothing else.
    #[test]
    fn a_stale_template_initrd_pair_is_overwritten_with_the_loaded_size() {
        const REAL: usize = 7_503_864;
        let (blobs, plan, opts) = fixture_with_initrd(REAL, &[(0x8_1000_0000, 0x8_1028_c000)]);
        let c = handoff_contract(&blobs.dtb, &plan, &blobs_steps(&blobs, &plan, &opts), &opts)
            .expect("the hand-off must check out");
        assert_eq!(c.initrd_loaded, REAL as u64);
        assert_eq!(c.initrd_start, plan.initrd_addr);
        assert_eq!(c.initrd_end - c.initrd_start, REAL as u64);
        assert_ne!(c.initrd_end - c.initrd_start, 2_670_592, "the template's size survived");
        assert_ne!(c.initrd_start, 0x8_1000_0000, "the template's address survived");

        // And the raw property really holds the new pair, not a merge of old and new.
        let f = crate::fdt::Fdt::parse(&blobs.dtb).unwrap();
        let chosen = f.root.child("chosen").unwrap();
        assert_eq!(chosen.prop_u64("linux,initrd-start").unwrap(), plan.initrd_addr);
        assert_eq!(chosen.prop_u64("linux,initrd-end").unwrap(), plan.initrd_addr + REAL as u64);
    }

    /// With no initramfs the pair is written as explicit zeros — a defined value, not an absent
    /// property and not whatever the template said. The kernel treats `initrd_start == 0` as
    /// "no initrd" (`arm64_memblock_init` checks it before reserving).
    #[test]
    fn no_initramfs_writes_explicit_zeros_not_a_stale_value() {
        let (blobs, plan, opts) = fixture_with_initrd(0, &[(0x8_1000_0000, 0x8_1028_c000)]);
        let steps = blobs_steps(&blobs, &plan, &opts);
        let c = handoff_contract(&blobs.dtb, &plan, &steps, &opts).unwrap();
        assert_eq!((c.initrd_start, c.initrd_end, c.initrd_loaded), (0, 0, 0));
        let f = crate::fdt::Fdt::parse(&blobs.dtb).unwrap();
        let chosen = f.root.child("chosen").unwrap();
        assert_eq!(chosen.prop_u64("linux,initrd-start").unwrap(), 0);
        assert_eq!(chosen.prop_u64("linux,initrd-end").unwrap(), 0);
    }

    /// An initramfs the plan expects but the steps never stage is a **named refusal**: the loader
    /// cannot state how many bytes it loaded, and guessing is what this project does not do.
    #[test]
    fn an_unknown_initrd_size_refuses_by_name() {
        let (blobs, plan, opts) = fixture();
        // Steps without the initrd write: drop it deliberately.
        let steps: Vec<Step> = blobs_steps(&blobs, &plan, &opts)
            .into_iter()
            .filter(|s| !matches!(s, Step::WriteVerify { dst, .. } if *dst == plan.initrd_addr))
            .collect();
        let e = handoff_contract(&blobs.dtb, &plan, &steps, &opts).unwrap_err();
        assert!(e.contains("HANDOFF_INITRD_SIZE_UNKNOWN"), "{e}");
        assert!(e.contains("Refusing to hand off"), "{e}");
    }

    /// The `linux,` prefix. Without it the kernel ignores the property and the boot panics with
    /// `VFS: Cannot open root device` — a property-name bug wearing a rootfs bug's clothes.
    #[test]
    fn an_unprefixed_initrd_property_is_refused_by_name() {
        let (blobs, plan, opts) = fixture();
        let steps = blobs_steps(&blobs, &plan, &opts);
        let mut f = crate::fdt::Fdt::parse(&blobs.dtb).unwrap();
        let chosen = f.root.child_mut("chosen").unwrap();
        chosen.props.retain(|p| p.name != "linux,initrd-start" && p.name != "linux,initrd-end");
        chosen.set_prop_u64_cells("initrd-start", plan.initrd_addr);
        chosen.set_prop_u64_cells("initrd-end", plan.initrd_addr + plan.initrd_size);
        let bad = f.serialise();
        let e = handoff_contract(&bad, &plan, &steps, &opts).unwrap_err();
        assert!(e.contains("HANDOFF_INITRD_PROPERTY_MISNAMED"), "{e}");
        assert!(e.contains("linux,"), "{e}");
    }

    /// A non-zero `cpu-release-addr` in rung 1 is a wild write into low memory plus a hung CPU1.
    /// The loader writes zero over whatever it found, and the check proves it.
    #[test]
    fn rung_1_writes_zero_over_a_stale_cpu_release_addr() {
        let (mut blobs, plan, opts) = fixture();
        // A template that (wrongly) claimed a mailbox.
        let mut f = crate::fdt::Fdt::parse(&blobs.dtb).unwrap();
        for cpu in f.root.child_mut("cpus").unwrap().children.iter_mut() {
            cpu.set_prop_u64_cells("cpu-release-addr", 0x8_7000_0000);
        }
        // edit_dtb is what the real pipeline runs, so the stale value must not survive it.
        blobs.dtb = edit_dtb(&f.serialise(), &plan, &opts).unwrap();
        let steps = blobs_steps(&blobs, &plan, &opts);
        let c = handoff_contract(&blobs.dtb, &plan, &steps, &opts).unwrap();
        assert_eq!(c.cpu_release_addr, 0, "rung 1 must write zero");

        // Rung 2 may fill it with a real mailbox, and then the check expects that value.
        let opts2 = EditOptions { spin_addr: Some(SPIN_MAILBOX_ADDR), ..Default::default() };
        let dtb2 = edit_dtb(&blobs.dtb, &plan, &opts2).unwrap();
        let mut plan2 = plan;
        plan2.adopt_edited_dtb(dtb2.len() as u64).unwrap();
        let blobs2 = BootBlobs {
            payload: blobs.payload.clone(),
            dtb: dtb2,
            image: blobs.image.clone(),
            initrd: blobs.initrd.clone(),
        };
        let steps2 = build_steps(&blobs2, &plan2, &opts2).unwrap();
        let c2 = handoff_contract(&blobs2.dtb, &plan2, &steps2, &opts2).unwrap();
        assert_eq!(c2.cpu_release_addr, SPIN_MAILBOX_ADDR);
    }

    /// A helper so the tests above read as one thought each.
    fn blobs_steps(blobs: &BootBlobs, plan: &Plan, opts: &EditOptions) -> Vec<Step> {
        build_steps(blobs, plan, opts).expect("the hand-off must build")
    }

    /// **The check the first dry run failed.** Before the transfer budget existed, the plan emitted
    /// the 2.6 MiB initramfs as a *single* packet: a control transfer no transport can send and no
    /// buffer can hold. Every packet the plan can produce must fit what the channel can carry.
    #[test]
    fn no_packet_exceeds_the_channel_budget() {
        let (blobs, plan, opts) = fixture();
        let budget = TransferBudget::default();
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        let mut commands = 0;
        for s in &steps {
            for p in step_packets(s, &blobs.payload, &budget) {
                budget.check(&p).expect("every packet must fit the budget");
                assert!(
                    p.upload_len as usize <= budget.buffer_capacity,
                    "{}: UPLOAD of {} bytes exceeds the buffer",
                    p.label,
                    p.upload_len
                );
                commands += 1;
            }
        }
        assert!(commands > 8, "expected a full sequence, got {commands} commands");
        assert_eq!(budget.data_per_command(), ASSUMED_BUFFER_CAPACITY - abi::HEADER_LEN as usize);
        assert_eq!(budget.max_read(), DNLOAD_CHUNK);
    }

    /// A blob far larger than the buffer — the real initramfs is 2.6 MiB — is split into
    /// transfer-sized commands that stay contiguous, each followed by its own read-back.
    #[test]
    fn a_large_blob_is_chunked_into_transfer_sized_commands() {
        let budget = TransferBudget::default();
        let big = vec![0xABu8; 2 * 1024 * 1024];
        let step = Step::WriteVerify { dst: 0x8_0100_0000, data: big.clone() };
        let packets = step_packets(&step, &[], &budget);

        let chunk = budget.data_per_command().min(DNLOAD_CHUNK);
        let expected_writes = big.len().div_ceil(chunk);
        let writes: Vec<_> = packets.iter().filter(|p| p.label.starts_with("memc 0x")).collect();
        assert_eq!(writes.len(), expected_writes, "one command per chunk");
        for p in &packets {
            budget.check(p).unwrap();
            assert!(p.dnload.len() <= budget.buffer_capacity);
        }
        // The chunks are contiguous and together cover the blob exactly once.
        let mut expected_at = 0x8_0100_0000u64;
        let mut total = 0usize;
        for p in &writes {
            assert_eq!(
                u64::from_le_bytes(p.dnload[0x10..0x18].try_into().unwrap()),
                expected_at,
                "chunks must be contiguous"
            );
            let len = u64::from_le_bytes(p.dnload[0x20..0x28].try_into().unwrap()) as usize;
            expected_at += len as u64;
            total += len;
        }
        assert_eq!(total, big.len());
        assert_eq!(expected_at, 0x8_0100_0000 + big.len() as u64);
    }

    /// A budget too small to carry the payload must be a **named refusal**, not a truncated send:
    /// a command that overruns the DFU buffer is corruption, not a stall.
    #[test]
    fn a_budget_below_the_payload_is_refused_by_name() {
        let (blobs, plan, opts) = fixture();
        let tight = TransferBudget { buffer_capacity: 512 };
        let steps = build_steps(&blobs, &plan, &opts).unwrap();
        let exec = steps.iter().find(|s| matches!(s, Step::Exec(_))).unwrap();
        let p = step_packets(exec, &blobs.payload, &tight).pop().unwrap();
        let e = tight.check(&p).unwrap_err();
        assert!(e.contains("exceeds the"), "{e}");
        assert!(e.contains("buffer capacity"), "{e}");
    }

    /// The vector handler and the EL1 stub in `a9boot-payload` read the mailbox address and the
    /// mailbox magic as **literal movz/movk constants** — they run at EL1 with no page tables and
    /// no relocations, so they cannot look either up. Those literals are therefore duplicated in
    /// assembly, which is exactly the situation this project has been burned by. This test is the
    /// tripwire: change the layout or the magic and it fails here, next to the constants, instead
    /// of failing silently on the device.
    #[test]
    fn assembly_literals_match_the_constants_they_duplicate() {
        assert_eq!(MAILBOX_ADDR, 0x8_7FE1_1000, "update the movz/movk pair in a9boot-payload/src/asm.rs");
        assert_eq!(
            abi::MAILBOX_MAGIC, 0x4139_424F_4F54_4D42,
            "update the movz/movk pair in a9boot-payload/src/asm.rs"
        );
        // The mailbox magic, as the four movk immediates build it (little-endian halves).
        assert_eq!(abi::MAILBOX_MAGIC & 0xffff, 0x4D42);
        assert_eq!((abi::MAILBOX_MAGIC >> 16) & 0xffff, 0x4F54);
        assert_eq!((abi::MAILBOX_MAGIC >> 32) & 0xffff, 0x424F);
        assert_eq!((abi::MAILBOX_MAGIC >> 48) & 0xffff, 0x4139);
        // And the mailbox address halves.
        assert_eq!(MAILBOX_ADDR & 0xffff, 0x1000);
        assert_eq!((MAILBOX_ADDR >> 16) & 0xffff, 0x7FE1);
        assert_eq!((MAILBOX_ADDR >> 32) & 0xffff, 0x0008);
    }

    /// The offsets the vector handler stores to must match `abi::Mailbox`'s field order, because
    /// the handler computes them by hand.
    #[test]
    fn mailbox_offsets_used_by_assembly_are_the_structs_offsets() {
        // magic@0, kind@8, detail@16, esr_el1@24, far_el1@32, elr_el1@40, spsr_el1@48
        let m = abi::Mailbox {
            magic: abi::MAILBOX_MAGIC,
            kind: abi::record::EL1_FAULT,
            detail: 0,
            esr_el1: 0x11,
            far_el1: 0x22,
            elr_el1: 0x33,
            spsr_el1: 0x44,
            ..Default::default()
        };
        let b = m.encode();
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), abi::MAILBOX_MAGIC);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 2, "kind at +0x08");
        assert_eq!(u64::from_le_bytes(b[0x18..0x20].try_into().unwrap()), 0x11, "esr_el1 at +0x18");
        assert_eq!(u64::from_le_bytes(b[0x20..0x28].try_into().unwrap()), 0x22, "far_el1 at +0x20");
        assert_eq!(u64::from_le_bytes(b[0x28..0x30].try_into().unwrap()), 0x33, "elr_el1 at +0x28");
        assert_eq!(u64::from_le_bytes(b[0x30..0x38].try_into().unwrap()), 0x44, "spsr_el1 at +0x30");
    }
}
