//! Walk the ROM's live EL3 translation tables and answer one question **before** anything touches
//! the address: *is it mapped?*
//!
//! ## Why this exists, in one paragraph
//!
//! Reading an unmapped address through the channel cost us a device: `0x20E80110` (PMGR) got no
//! reply, wedged EP0, and the recovery reset took the phone off the bus. The ROM's EL3 translation
//! covers the AUSB window and not PMGR, and — the finding that reframes rung 2 — **our payload
//! inherits that translation**, so executing our own code does not buy us our own address space.
//! The robust fix is not a better recovery; it is to *not fault in the first place*. The tables
//! that decide this are in SRAM, they are the ROM's own, and reading them is a plain `MEMC` read.
//!
//! ## The discipline this makes possible
//!
//! 1. read the handler's first bytes (`exec::HANDLER_FIRST_32_HEX`) — the canary: the CPU is
//!    executing them, so that page is mapped, and a match proves SRAM reads work;
//! 2. read the translation tables from `TTBR0_EL3`'s base and walk them for the target;
//! 3. only then touch the target — and only if the walk says `Mapped`.
//!
//! ## What a table entry means (ARM ARM VMSAv8-64, "VMSAv8-64 translation table descriptor")
//!
//! The descriptor's low two bits decide what it is, for a 4 KiB granule:
//!
//! * `0b01` → a **block** (leaf) at level 0/1/2 — 512 GiB at L0, 1 GiB at L1, 2 MiB at L2;
//! * `0b11` → a **table** (pointer to the next level) at level 0/1/2, and a **page** (leaf) at
//!   level 3;
//! * `0b00`/`0b10` → invalid / reserved, i.e. **not mapped** — which for our purpose is the
//!   answer, not an error.
//!
//! `AF` (bit 10) clear means the entry is present but not yet accessible: touching it faults, so
//! the walk reports `NotAccessible` rather than `Mapped`. Attributes (`AttrIndx`, `AP`, `SH`) are
//! reported but only *interpreted* where they are unambiguous — `MAIR_EL3` itself cannot be read
//! through this channel, and inventing a cacheability answer from `AttrIndx` alone is exactly the
//! confident-wrong value this project keeps paying for.
//!
//! ## Granule and T0SZ: NOT YET MEASURED — the walk is only as right as what it is told
//!
//! How many levels there are, how many index bits each level uses, and the block/page sizes all
//! depend on the translation granule (`TCR_EL3.TG0`) and the input address size (`T0SZ`). The
//! kernel is built `Image-16k`, so TG0 is *likely* 16 KiB, but `tcr_el3` sat just past the 64-byte
//! DESCRIBE reply cut and was **not captured**. The [`Granule`] type carries the ARM ARM's
//! per-granule facts (table/page output-base width, entries per level, per-level index shift, and
//! block base/size), and the walk takes the granule explicitly. The default is 4 KiB as a
//! *placeholder*, not a measurement: until `tcr_el3.TG0` is read, the walk's level structure is
//! only correct for the granule it is told, and T0SZ is assumed to be the common 48-bit case.

use a9boot_core::layout;

/// Translation granule (page size), from `TCR_EL3.TG0`. **NOT YET MEASURED** on this unit.
///
/// All three values below are the ARM ARM VMSAv8-64 translation-table facts (Linux
/// `arch/arm64/include/asm/pgtable-hwdef.h` is the same table, derived from the ARM ARM):
///
/// | granule | page shift | index bits/level | entries/level | levels (48-bit) | first level |
/// |---------|-----------:|-----------------:|--------------:|----------------:|------------:|
/// | 4K      | 12         | 9                | 512           | 4               | 0           |
/// | 16K     | 14         | 11               | 2048          | 4               | 0           |
/// | 64K     | 16         | 13               | 8192          | 3               | 1           |
///
/// * Table/page descriptor output address field: `bits[47:12]` (4K), `bits[47:14]` (16K),
///   `bits[47:16]` (64K).
/// * Block output-base width (and block size) per level: 4K → L1 `bits[47:30]` (1 GiB), L2
///   `bits[47:21]` (2 MiB); 16K → L1 `bits[47:36]` (64 GiB), L2 `bits[47:25]` (32 MiB); 64K →
///   L1 `bits[47:42]` (4 TiB), L2 `bits[47:29]` (512 MiB). A block at level N covers the index
///   bits at level N and below, so its base mask is `bits[47 : level_shift(N)]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    Granule4k,
    Granule16k,
    Granule64k,
}

impl Granule {
    pub fn from_arg(s: &str) -> Option<Granule> {
        match s {
            "4k" => Some(Granule::Granule4k),
            "16k" => Some(Granule::Granule16k),
            "64k" => Some(Granule::Granule64k),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Granule::Granule4k => "4K",
            Granule::Granule16k => "16K",
            Granule::Granule64k => "64K",
        }
    }

    /// Log2 of the page size, and the alignment of every table/page output address field.
    pub fn page_shift(self) -> u8 {
        match self {
            Granule::Granule4k => 12,
            Granule::Granule16k => 14,
            Granule::Granule64k => 16,
        }
    }

    /// Index bits per level (log2 of entries per level): 9 / 11 / 13.
    pub fn index_bits(self) -> u8 {
        match self {
            Granule::Granule4k => 9,
            Granule::Granule16k => 11,
            Granule::Granule64k => 13,
        }
    }

    /// Entries in a translation table at this granule: 512 / 2048 / 8192.
    pub fn entries_per_level(self) -> usize {
        1usize << self.index_bits()
    }

    /// Number of translation levels for a 48-bit input address (`T0SZ = 16`).
    ///
    /// `T0SZ` is also **not yet measured**; the walk assumes 48-bit input. A different T0SZ changes
    /// the starting level and number of levels and must be revisited when `TCR_EL3` is read.
    pub fn levels(self) -> u8 {
        match self {
            Granule::Granule4k | Granule::Granule16k => 4,
            Granule::Granule64k => 3,
        }
    }

    /// First (top) level of the walk: level 0 for 4K/16K, level 1 for 64K.
    pub fn first_level(self) -> u8 {
        match self {
            Granule::Granule4k | Granule::Granule16k => 0,
            Granule::Granule64k => 1,
        }
    }

    /// First level for a given `T0SZ` (input address size = 64 - T0SZ).
    ///
    /// MEASURED on this unit: `TCR_EL3.T0SZ = 27` → 37-bit input → with 16K granule the walk
    /// starts at LEVEL 1, not 0 — which is why the L0 table appeared to have a single dead
    /// entry: the root `ttbr0_el3` IS the L1 table under a 37-bit input.
    /// `first = last_level - floor((total_index_bits - 1) / index_bits)` where
    /// `total_index_bits = (64 - T0SZ) - page_shift`. Pinned by
    /// `t0sz_start_level_matches_the_measured_unit`.
    pub fn first_level_for_t0sz(self, t0sz: u8) -> u8 {
        let input_bits = 64i32 - t0sz as i32;
        let total_index = input_bits - self.page_shift() as i32;
        if total_index <= 0 {
            return self.first_level();
        }
        let skip = ((total_index - 1) / self.index_bits() as i32) as u8;
        self.last_level().saturating_sub(skip)
    }

    /// Last (leaf) level, where `0b11` is a Page. Always 3 for a 48-bit input at any granule.
    pub fn last_level(self) -> u8 {
        self.first_level() + self.levels() - 1
    }

    /// The bit position where level `level`'s index begins (its least-significant bit).
    ///
    /// `level_shift(L) = page_shift + (last_level - L) * index_bits` (Linux
    /// `level_n_shift = (page_shift - 3) * n + 3` in `pgtable-hwdef.h`). For 4K that is
    /// L0=39, L1=30, L2=21, L3=12; for 16K L0=47, L1=36, L2=25, L3=14; for 64K L1=42, L2=29,
    /// L3=16.
    pub fn level_shift(self, level: u8) -> u8 {
        self.page_shift() + (self.last_level() - level) * self.index_bits()
    }

    /// Mask that keeps the output address field of a table/page descriptor (`bits[47:page_shift]`).
    pub fn table_mask(self) -> u64 {
        !((1u64 << self.page_shift()) - 1) & 0x0000_FFFF_FFFF_FFFF
    }

    /// Shift of a block's output base at `level` — the same as the level's index shift, because a
    /// block at level N covers the index bits at N and everything below.
    pub fn block_shift(self, level: u8) -> u8 {
        self.level_shift(level)
    }

    /// Mask that keeps a block descriptor's output base at `level`.
    pub fn block_mask(self, level: u8) -> u64 {
        !((1u64 << self.block_shift(level)) - 1) & 0x0000_FFFF_FFFF_FFFF
    }

    /// The size in bytes of a block at `level` (a leaf block at that level maps this much).
    pub fn block_size(self, level: u8) -> u64 {
        1u64 << self.block_shift(level)
    }
}

/// Descriptor kinds, decoded from the low bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorKind {
    /// `0b11` at level 3: a page (4 KiB / 16 KiB / 64 KiB depending on granule).
    Page,
    /// `0b01` at level 0/1/2: a block leaf (size depends on the level *and* the granule).
    Block,
    /// `0b11` at level 0/1/2: points at the next level's table.
    Table,
    /// `0b00`/`0b10`, or `0b01` at level 3: invalid/reserved, so the address is not mapped.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    pub raw: u64,
    pub kind: DescriptorKind,
    pub level: u8,
    /// Bits [4:2]: index into `MAIR_EL3`. Reported, not interpreted.
    pub attr_index: u8,
    /// Bit 10: the access flag. Clear means "present but touching it faults".
    pub access_flag: bool,
    /// Bits [7:6]: AP[2:1].
    pub ap: u8,
    /// Bits [9:8]: shareability.
    pub sh: u8,
    /// Bits [47:12]/[47:14]/[47:16] (table/page) or the block's base, per the granule.
    pub output_base: u64,
}

impl Descriptor {
    pub fn decode(raw: u64, level: u8, granule: Granule) -> Descriptor {
        // ARM ARM VMSAv8-64, "VMSAv8-64 translation table descriptor", bits[1:0]:
        //   0b00 invalid, 0b10 reserved, 0b01 = BLOCK at L0/L1/L2, 0b11 = TABLE at L0/L1/L2,
        //   0b11 = PAGE at L3. The previous code had 0b01/0b11 swapped at L1/L2 — a false
        //   UNMAPPED, not a false MAPPED, but wrong is wrong: it enshrined the inverted model in
        //   its tests.
        let kind = match (raw & 0b11, level) {
            (0b11, 3) => DescriptorKind::Page,
            (0b11, _) => DescriptorKind::Table,
            (0b01, _) if level < 3 => DescriptorKind::Block,
            _ => DescriptorKind::Invalid,
        };
        // The output address field depends on the *kind* and the *granule*, not just the level: a
        // table/page points at a granule-aligned base (`bits[47:page_shift]`), and a block's base
        // is `bits[47:level_shift(level)]`. Using one mask for all of them silently produced base 0
        // and reported mapped memory as UNMAPPED.
        let output_base = match kind {
            DescriptorKind::Table | DescriptorKind::Page => raw & granule.table_mask(),
            DescriptorKind::Block => raw & granule.block_mask(level),
            DescriptorKind::Invalid => raw,
        };
        Descriptor {
            raw,
            kind,
            level,
            attr_index: ((raw >> 2) & 0b111) as u8,
            access_flag: raw & (1 << 10) != 0,
            ap: ((raw >> 6) & 0b11) as u8,
            sh: ((raw >> 8) & 0b11) as u8,
            output_base,
        }
    }
}

/// The answer the caller actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapping {
    /// Walked to a page or block with `AF` set: touching this address does not fault.
    Mapped { level: u8, kind: DescriptorKind, attr_index: u8 },
    /// A descriptor exists but `AF` is clear: present, and it still faults.
    NotAccessible { level: u8 },
    /// No valid descriptor on the path: **do not touch it.**
    Unmapped { level: u8, raw: u64 },
    /// The tables could not be read (a transport/read failure), which is not an answer.
    Unknown { reason: String },
}

impl Mapping {
    pub fn name(&self) -> &'static str {
        match self {
            Mapping::Mapped { .. } => "MAPPED",
            Mapping::NotAccessible { .. } => "NOT_ACCESSIBLE",
            Mapping::Unmapped { .. } => "UNMAPPED",
            Mapping::Unknown { .. } => "UNKNOWN",
        }
    }

    /// May the caller touch the address? Only `Mapped` says yes. Everything else — including
    /// `NotAccessible` and `Unknown` — must read as a refusal, or a wrong fix flips a refusal into
    /// a false MAPPED and green-lights the read that hangs the device.
    pub fn may_touch(&self) -> bool {
        matches!(self, Mapping::Mapped { .. })
    }

    pub fn summary(&self) -> String {
        match self {
            Mapping::Mapped { level, kind, attr_index } => format!(
                "MAPPED at level {level} ({kind:?}), AttrIndx {attr_index}. The walk only says the \
                 translation exists; it does not say the memory behind it exists, and MAIR_EL3 is \
                 not readable through this channel so no cacheability claim is made."
            ),
            Mapping::NotAccessible { level } => format!(
                "NOT_ACCESSIBLE at level {level}: the descriptor exists but AF is clear, so the \
                 access still faults. Treat as unmapped."
            ),
            Mapping::Unmapped { level, raw } => format!(
                "UNMAPPED: the walk stopped at level {level} on an invalid descriptor \
                 ({raw:#018x}). DO NOT TOUCH THIS ADDRESS: this is the read that cost a device \
                 (RUNG2-EVIDENCE.md §3)."
            ),
            Mapping::Unknown { reason } => format!(
                "UNKNOWN: the tables could not be read ({reason}). Not an answer — do not touch the \
                 address on the strength of it."
            ),
        }
    }
}

/// A table, as read from the device: base address, level, and the entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub base: u64,
    pub level: u8,
    pub entries: Vec<u64>,
}

/// How many entries the walk may need to fetch, so the host can plan its reads. This is the full
/// table size at the granule (512/2048/8192 entries), not just the one index in use.
pub fn entries_needed(level: u8, granule: Granule) -> usize {
    let _ = level;
    granule.entries_per_level()
}

/// The byte offset of the entry for `addr` inside a table, and the base it maps.
fn entry_index(addr: u64, level: u8, granule: Granule) -> usize {
    let shift = granule.level_shift(level);
    ((addr >> shift) & ((granule.entries_per_level() - 1) as u64)) as usize
}

/// Walk tables the caller fetched, for `target`, using the given granule's level structure.
///
/// `fetch(level, base)` returns that level's entries. The walk is pure: giving it synthetic tables
/// is how the decoder is tested without a device, and how the "unmapped is a result" property is
/// proved.
pub fn walk_with<F>(target: u64, root: u64, granule: Granule, start_level: u8, mut fetch: F) -> Mapping
where
    F: FnMut(u8, u64) -> Result<Vec<u64>, String>,
{
    let mut base = root;
    let mut level = start_level;
    loop {
        let entries = match fetch(level, base) {
            Ok(e) => e,
            Err(reason) => return Mapping::Unknown { reason },
        };
        let idx = entry_index(target, level, granule);
        let Some(&raw) = entries.get(idx) else {
            return Mapping::Unknown {
                reason: format!("level {level} table at {base:#x} has no entry {idx}"),
            };
        };
        let d = Descriptor::decode(raw, level, granule);
        match d.kind {
            DescriptorKind::Invalid => {
                return Mapping::Unmapped { level, raw };
            }
            DescriptorKind::Table => {
                base = d.output_base;
                level += 1;
                if level > granule.last_level() {
                    return Mapping::Unknown { reason: "walk went below the leaf level".to_string() };
                }
            }
            DescriptorKind::Page | DescriptorKind::Block => {
                if !d.access_flag {
                    return Mapping::NotAccessible { level };
                }
                return Mapping::Mapped {
                    level,
                    kind: d.kind,
                    attr_index: d.attr_index,
                };
            }
        }
    }
}

/// May the walk follow a table pointer to `addr`?
///
/// **This is the guard that keeps the walk from faulting.** A table read is a `MEMC` read of an
/// address taken from the table itself; if that pointer is garbage, following it reads an unmapped
/// address and we lose the device to the instrument that exists to stop us doing exactly that. So
/// the walk only follows pointers into memory already known to be mapped: the SRAM window the ROM
/// itself uses. DRAM is *not* followed by default, because DRAM reachability is the open question
/// (U-1) — a table there is a reason to stop and measure, not to read.
pub fn may_follow(addr: u64, allow_dram: bool) -> Result<(), String> {
    let sram = layout::SRAM_BASE..(layout::SRAM_BASE + 0x0040_0000);
    if sram.contains(&addr) {
        return Ok(());
    }
    if allow_dram && (layout::DRAM_BASE..layout::DRAM_BASE + layout::DRAM_SIZE).contains(&addr) {
        return Ok(());
    }
    Err(format!(
        "TABLE_POINTER_OUTSIDE_KNOWN_MEMORY: the walk was about to read a table at {addr:#x},          which is neither in SRAM ({:#x}..{:#x}) nor DRAM. Following it would read an address \
         whose mapping is unknown — the fault this whole phase exists to avoid. Refusing, and \
         reporting the pointer instead.",
        layout::SRAM_BASE,
        layout::SRAM_BASE + 0x0040_0000
    ))
}

/// The table a `MEMC` read would need, as a request the caller can print: base + entries*8 bytes.
pub fn table_read(base: u64, granule: Granule) -> (u64, usize) {
    (base, granule.entries_per_level() * 8)
}

/// The `TTBR0_EL3` base `gaster`'s config names for CPID `0x8003` (`gaster.c:627-631`).
///
/// **INSPECTED, and MEASURED WRONG as a root on this unit**: the measured `ttbr0_el3` is
/// `0x1800875C0` (RUNG2-EVIDENCE.md §6.0), whose L0 `entry[0]` is a TABLE pointing at
/// `0x1800C8000` — so `0x1800C8000` is the **L1 table**, not the root. It is kept as a
/// *candidate*, never as truth: [`find_root`] searches SRAM for the base that actually walks a
/// known-mapped address to `MAPPED`, and a run whose positive control does not pass is refused
/// rather than believed.
pub const ROM_TTBR0_TABLES_CANDIDATE: u64 = 0x1_800C_8000;

/// Kept as an alias so existing call sites read the same; prefer the candidate name.
pub const ROM_TTBR0_TABLES: u64 = ROM_TTBR0_TABLES_CANDIDATE;

/// Addresses that are **known mapped by measurement**, so a walk that cannot map one of them is
/// not answering its own question.
///
/// `0x1_800E_0F08` is the resident handler: the CPU is executing those bytes during the run, and
/// its contents were read back as the 248-byte reference build (MEASURED, `r18-pagewalk`).
/// `0x1_8038_0110` is the payload staging address inside the DFU buffer: the channel writes and
/// reads through that buffer on every command (MEASURED).
pub fn positive_controls() -> [(u64, &'static str); 2] {
    [
        (layout::HANDLER_ADDR, "the resident handler (executing during the run; canary matched)"),
        (layout::DFU_BUFFER_ADDR + 0x110, "the payload staging address inside the DFU buffer"),
    ]
}

/// Find the live table base by search, read-only, and **prove it** by walking a known-mapped
/// address to `MAPPED`.
///
/// `fetch8(addr)` reads eight bytes; the search reads entry 0 of every 4 KiB-aligned candidate in
/// SRAM, then walks each candidate for `prove` and keeps the first that answers `MAPPED`. The
/// candidate list is returned so the operator can see what was tried, and `None` means "no base in
/// SRAM maps a known-mapped address", which is itself a result: the tables are not where the
/// channel can see them, and no extent may be declared.
pub fn find_root<E, G>(
    mut fetch8: E,
    mut fetch512: G,
    prove: u64,
    granule: Granule,
    start_level: u8,
) -> (Option<u64>, Vec<u64>, Vec<String>)
where
    E: FnMut(u64) -> Result<[u8; 8], String>,
    G: FnMut(u8, u64) -> Result<Vec<u64>, String>,
{
    let mut candidates: Vec<u64> = Vec::new();
    let mut notes = Vec::new();
    let end = layout::SRAM_BASE + 0x0040_0000;
    let mut base = layout::SRAM_BASE;
    while base < end {
        match fetch8(base) {
            Ok(b) => {
                let raw = u64::from_le_bytes(b);
                // A level-0 table's entry 0 must be a table descriptor (0b11) pointing into SRAM;
                // anything else cannot be the root for an address in SRAM. The table address field
                // width is the granule's (`table_mask`).
                if raw & 0b11 == 0b11
                    && (layout::SRAM_BASE..end).contains(&(raw & granule.table_mask()))
                {
                    candidates.push(base);
                }
            }
            Err(e) => {
                notes.push(format!("candidate sweep stopped at {base:#x}: {e}"));
                break;
            }
        }
        base += 4096;
    }
    notes.push(format!(
        "swept {} candidates in SRAM ({:#x}..{end:#x}); {} have a level-0 table descriptor at \
         entry 0",
        (end - layout::SRAM_BASE) / 4096,
        layout::SRAM_BASE,
        candidates.len()
    ));
    // Prove each candidate by walking a KNOWN-MAPPED address. A base that cannot map the handler
    // or the DFU buffer is not the live root, whatever it looks like.
    for cand in &candidates {
        match walk_from(*cand, prove, granule, start_level, &mut fetch512) {
            Ok(Mapping::Mapped { .. }) => {
                notes.push(format!(
                    "root candidate {cand:#x} PROVED: {prove:#x} walks to MAPPED from it"
                ));
                return (Some(*cand), candidates, notes);
            }
            _ => {}
        }
    }
    notes.push(format!(
        "NO ROOT FOUND: {} candidate(s) were tried and none maps {prove:#x}. The live tables are \
         not in the SRAM the channel can see, so no mapping may be declared from this run.",
        candidates.len()
    ));
    (None, candidates, notes)
}

/// Walk for `target` starting at a **given** base, using a fetch callback. A thin wrapper over
/// [`walk_with`] so the search and the CLI share one implementation.
pub fn walk_from<F>(base: u64, target: u64, granule: Granule, start_level: u8, fetch: F) -> Result<Mapping, String>
where
    F: FnMut(u8, u64) -> Result<Vec<u64>, String>,
{
    Ok(walk_with(target, base, granule, start_level, fetch))
}

/// The canary: the cheapest address that is certainly mapped, because the CPU is executing it.
/// Read this first; only if it matches `exec::HANDLER_FIRST_32_HEX` is it worth reading tables.
pub use crate::exec::HANDLER_ADDR as CANARY_ADDR;

/// Where the ROM's own translation stops being predictable. Kept as a named constant so the
/// runbook and the code agree on the window that is *known* good.
pub fn known_mapped_windows() -> &'static [(u64, u64, &'static str)] {
    &[
        (0x2_0C00_0000, 0x2_0C00_1000, "AUSB PHY (MEASURED readable, RUNG2-EVIDENCE §2)"),
        (layout::HANDLER_ADDR, layout::HANDLER_ADDR + 0xF8, "the resident handler (executing now)"),
        (layout::DFU_BUFFER_ADDR, layout::DFU_BUFFER_ADDR + 0x4000, "the DFU buffer (the ROM writes it)"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic table set that maps DRAM `0x8_0000_0000` to a leaf block, built in the bit
    /// positions the given granule dictates. The block is placed at a level whose block size
    /// aligns with `0x8_0000_0000`: L1 (1 GiB) for 4K, L2 (32 MiB) for 16K. (64K needs a 4 TiB-
    /// aligned target and is covered by the decode tests instead.) PMGR `0x20E80110` shares the
    /// L0 entry with DRAM but its L1 entry is left zero — the negative control.
    fn synthetic(granule: Granule) -> impl FnMut(u8, u64) -> Result<Vec<u64>, String> {
        move |level: u8, base: u64| {
            let mut e = vec![0u64; granule.entries_per_level()];
            let target = 0x8_0000_0000u64;
            let first = granule.first_level();
            if level == first && base == 0x1000 {
                // L0 (4K/16K) table: DRAM's L0 entry points at the L1 table. The pointer is
                // 0x4000 — 16K-aligned — so it survives BOTH the 4K mask (bits[47:12]) and the
                // 16K mask (bits[47:14]); a 4K-only base like 0x2000 would be zeroed by the 16K
                // mask and the walk would report UNMAPPED for a mapped address.
                e[entry_index(target, level, granule)] = 0x4000 | 0b11;
            } else if level == first + 1 && base == 0x4000 {
                if granule == Granule::Granule4k {
                    // 4K: 1 GiB block, AF set (0b01 = block).
                    e[entry_index(target, level, granule)] = 0x8_0000_0000 | (1 << 10) | 0b01;
                } else {
                    // 16K: the L1 block would be 64 GiB, so descend one more level to a table.
                    e[entry_index(target, level, granule)] = 0x8000 | 0b11;
                }
            } else if level == first + 2 && base == 0x8000 {
                // 16K: 32 MiB block, AF set.
                e[entry_index(target, level, granule)] = 0x8_0000_0000 | (1 << 10) | 0b01;
            }
            Ok(e)
        }
    }

    #[test]
    fn a_mapped_block_is_reported_mapped_4k() {
        let m = walk_with(0x8_0000_0000, 0x1000, Granule::Granule4k, Granule::Granule4k.first_level(), synthetic(Granule::Granule4k));
        assert_eq!(m.name(), "MAPPED");
        assert!(m.may_touch());
        assert!(matches!(m, Mapping::Mapped { level: 1, kind: DescriptorKind::Block, .. }));
        assert!(m.summary().contains("MAIR_EL3"), "no cacheability claim is made");
    }

    #[test]
    fn a_mapped_block_is_reported_mapped_16k() {
        let m = walk_with(0x8_0000_0000, 0x1000, Granule::Granule16k, Granule::Granule16k.first_level(), synthetic(Granule::Granule16k));
        assert_eq!(m.name(), "MAPPED");
        assert!(m.may_touch());
        assert!(matches!(m, Mapping::Mapped { level: 2, kind: DescriptorKind::Block, .. }));
    }

    #[test]
    fn negative_control_the_pmgr_window_is_reported_unmapped_and_forbids_the_touch() {
        // This is the address that cost a device (RUNG2-EVIDENCE.md §3): 0x20E80110, PMGR. The
        // walk must say UNMAPPED, and `may_touch` must be false — the runbook's rule is only
        // useful if the code enforces it.
        let m = walk_with(0x20E80110, 0x1000, Granule::Granule4k, Granule::Granule4k.first_level(), synthetic(Granule::Granule4k));
        assert_eq!(m.name(), "UNMAPPED");
        assert!(!m.may_touch());
        let s = m.summary();
        assert!(s.contains("DO NOT TOUCH"), "{s}");
        assert!(s.contains("cost a device"), "{s}");
    }

    #[test]
    fn negative_control_af_clear_is_not_mapped_either() {
        // A present descriptor with AF clear still faults; reporting it as "mapped" would be the
        // same failure wearing a different hat.
        let m = walk_with(
            0x8_0000_0000,
            0x1000,
            Granule::Granule4k,
            Granule::Granule4k.first_level(),
            |level, base| {
                let mut e = vec![0u64; 512];
                if level == 0 && base == 0x1000 {
                    e[entry_index(0x8_0000_0000, 0, Granule::Granule4k)] = 0x2000 | 0b11;
                } else if level == 1 && base == 0x2000 {
                    e[entry_index(0x8_0000_0000, 1, Granule::Granule4k)] = 0x8_0000_0000 | 0b01; // block, AF CLEAR
                }
                Ok(e)
            },
        );
        assert_eq!(m.name(), "NOT_ACCESSIBLE");
        assert!(!m.may_touch());
    }

    #[test]
    fn a_read_failure_is_unknown_not_unmapped() {
        // "I could not read the tables" and "the address is not mapped" are different answers and
        // must never be spelled the same way.
        let m = walk_with(0x8_0000_0000, 0x1000, Granule::Granule4k, Granule::Granule4k.first_level(), |_, _| Err("no reply".to_string()));
        assert_eq!(m.name(), "UNKNOWN");
        assert!(!m.may_touch());
        assert!(m.summary().contains("Not an answer"));
    }

    #[test]
    fn may_touch_is_true_only_for_mapped() {
        assert!(Mapping::Mapped { level: 1, kind: DescriptorKind::Block, attr_index: 0 }.may_touch());
        assert!(!Mapping::NotAccessible { level: 1 }.may_touch());
        assert!(!Mapping::Unmapped { level: 1, raw: 0 }.may_touch());
        assert!(!Mapping::Unknown { reason: "x".into() }.may_touch());
    }

    /// The encoding truth, pinned level by level. If the 0b01/0b11 arms are swapped back, these
    /// fail. (The old `descriptor_decoding_is_per_level` asserted `0b11 at L1 == Block` — it was
    /// asserting the bug.)
    #[test]
    fn descriptor_type_bits_match_the_arm_arm() {
        let g = Granule::Granule4k;
        for level in [0u8, 1, 2] {
            assert_eq!(Descriptor::decode(0b01, level, g).kind, DescriptorKind::Block, "0b01 block at L{level}");
            assert_eq!(Descriptor::decode(0b11, level, g).kind, DescriptorKind::Table, "0b11 table at L{level}");
        }
        assert_eq!(Descriptor::decode(0b11, 3, g).kind, DescriptorKind::Page, "0b11 page at L3");
        assert_eq!(Descriptor::decode(0b01, 3, g).kind, DescriptorKind::Invalid, "0b01 at L3 is reserved");
        assert_eq!(Descriptor::decode(0b00, 1, g).kind, DescriptorKind::Invalid);
        assert_eq!(Descriptor::decode(0b10, 1, g).kind, DescriptorKind::Invalid);
    }

    /// CROSS-CHECK against the MEASURED hardware descriptor (not synthetic). r45-table.json read
    /// the ROM's L0 table at `ttbr0_el3 = 0x1800875C0`: `entry[0] = 0x00800001800C8003`, all
    /// other entries zero. Decoded per the ARM ARM, bits[1:0]=0b11 → TABLE, bits[47:12]=
    /// 0x1800C8000 → the L1 table (the "gaster constant" misused as a root). Re-inverting the
    /// encoding turns this into a Block and the test FAILS — which the old `0x8_0000_0000`-style
    /// fixtures provably could not catch, because that value's single bit (2^35) made the block
    /// and table masks agree.
    #[test]
    fn measured_hardware_entry_is_a_table_pointing_at_the_l1_table() {
        let d = Descriptor::decode(0x0080_0001_800C_8003, 0, Granule::Granule4k);
        assert_eq!(d.kind, DescriptorKind::Table);
        assert_eq!(d.output_base, 0x1800C8000);
    }

    /// A block descriptor is `0b01`, not `0b11`, and its base is the block-size mask of its level.
    #[test]
    fn a_block_descriptor_is_0b01_and_yields_its_block_base() {
        let d = Descriptor::decode(0x180000000 | (1 << 10) | 0b01, 1, Granule::Granule4k);
        assert_eq!(d.kind, DescriptorKind::Block);
        assert!(d.access_flag);
        assert_eq!(d.output_base, 0x180000000);
    }

    /// GRANULE-distinguishing cross-check. The measured entry's bits[13:12] are zero, so 4K
    /// (`bits[47:12]`) and 16K (`bits[47:14]`) extract the SAME table address — the same ambiguity
    /// that hid the block/table swap, now on the granule axis. A table descriptor with bits[13:12]
    /// non-zero decodes DIFFERENTLY under the two granules, pinning the 16K field width (ARM ARM:
    /// table address = OA[47:14] for 16K, OA[47:12] for 4K).
    #[test]
    fn a_descriptor_with_nonzero_bits_13_12_pins_the_granule() {
        let raw = 0x1800C0000 | (0b11 << 12) | 0b11; // table base bits[47:14]=0x1800C0000, bits[13:12]=0b11
        let d4 = Descriptor::decode(raw, 1, Granule::Granule4k);
        let d16 = Descriptor::decode(raw, 1, Granule::Granule16k);
        assert_eq!(d4.kind, DescriptorKind::Table);
        assert_eq!(d16.kind, DescriptorKind::Table);
        assert_eq!(d4.output_base, 0x1800C3000, "4K keeps bits[13:12]");
        assert_eq!(d16.output_base, 0x1800C0000, "16K clears bits[13:0]");
        assert_ne!(d4.output_base, d16.output_base);
    }

    /// The per-granule facts must stay consistent: entry count, index shift, and table/output-base
    /// width all derive from the same page_shift/index_bits, and must not drift apart.
    #[test]
    fn granule_facts_are_self_consistent() {
        let cases: [(Granule, u8, u8, usize, u8); 3] = [
            (Granule::Granule4k, 12, 9, 512, 4),
            (Granule::Granule16k, 14, 11, 2048, 4),
            (Granule::Granule64k, 16, 13, 8192, 3),
        ];
        for (g, page_shift, index_bits, entries, levels) in cases {
            assert_eq!(g.page_shift(), page_shift);
            assert_eq!(g.index_bits(), index_bits);
            assert_eq!(g.entries_per_level(), entries);
            assert_eq!(g.levels(), levels);
            assert_eq!(g.table_mask(), !((1u64 << page_shift) - 1) & 0x0000_FFFF_FFFF_FFFF);
            assert_eq!(g.last_level(), g.first_level() + g.levels() - 1);
        }
        // Per-level shifts, ARM ARM / Linux pgtable-hwdef.h.
        assert_eq!((Granule::Granule4k).level_shift(0), 39);
        assert_eq!((Granule::Granule4k).level_shift(1), 30);
        assert_eq!((Granule::Granule4k).level_shift(2), 21);
        assert_eq!((Granule::Granule4k).level_shift(3), 12);
        assert_eq!((Granule::Granule16k).level_shift(0), 47);
        assert_eq!((Granule::Granule16k).level_shift(1), 36);
        assert_eq!((Granule::Granule16k).level_shift(2), 25);
        assert_eq!((Granule::Granule16k).level_shift(3), 14);
        assert_eq!((Granule::Granule64k).level_shift(1), 42);
        assert_eq!((Granule::Granule64k).level_shift(2), 29);
        assert_eq!((Granule::Granule64k).level_shift(3), 16);
        // Block sizes (leaf blocks): 4K L1=1GiB/L2=2MiB; 16K L1=64GiB/L2=32MiB; 64K L1=4TiB/L2=512MiB.
        assert_eq!((Granule::Granule4k).block_size(1), 0x4000_0000);
        assert_eq!((Granule::Granule4k).block_size(2), 0x20_0000);
        assert_eq!((Granule::Granule16k).block_size(1), 0x10_0000_0000);
        assert_eq!((Granule::Granule16k).block_size(2), 0x200_0000);
        assert_eq!((Granule::Granule64k).block_size(1), 0x400_0000_0000);
        assert_eq!((Granule::Granule64k).block_size(2), 0x2000_0000);
        // entry_index must agree with a hand-computed index.
        assert_eq!(entry_index(0x8_0000_0000, 1, Granule::Granule4k), 32);
        assert_eq!(entry_index(0x8_0000_0000, 2, Granule::Granule16k), 1024);
    }

    #[test]
    fn the_known_mapped_windows_are_where_the_measurements_say() {
        let w = known_mapped_windows();
        assert!(w.iter().any(|(b, _, _)| *b == layout::HANDLER_ADDR));
        assert!(w.iter().any(|(b, _, _)| *b == 0x2_0C00_0000));
        // Every window's note carries its label, so a reader can tell measured from inferred.
        assert!(w.iter().any(|(_, _, n)| n.contains("MEASURED")));
        assert!(w.iter().any(|(_, _, n)| n.contains("executing now")));
        assert_eq!(ROM_TTBR0_TABLES, 0x1_800C_8000);
    }

    /// MEASURED on this unit (r57, DESCRIBE reply): `TCR_EL3 = 0x8081A51B` → `T0SZ = 27`
    /// (37-bit input) and `TG0 = 0b10` (16K). A 37-bit input with 16K granule starts the walk
    /// at LEVEL 1 — the root `ttbr0_el3 = 0x1800875C0` IS the L1 table. This pins the
    /// `first_level_for_t0sz` derivation against that measurement and the 48-bit defaults.
    #[test]
    fn t0sz_start_level_matches_the_measured_unit() {
        // MEASURED: TCR_EL3.T0SZ = 27, TG0 = 16K → 37-bit input → start at level 1.
        assert_eq!(Granule::Granule16k.first_level_for_t0sz(27), 1);
        // Defaults: 48-bit input starts at level 0 for 4K/16K, level 1 for 64K.
        assert_eq!(Granule::Granule4k.first_level_for_t0sz(16), 0);
        assert_eq!(Granule::Granule16k.first_level_for_t0sz(16), 0);
        assert_eq!(Granule::Granule64k.first_level_for_t0sz(16), 1);
        // Degenerate: an input no wider than the page offset falls back to the granule default.
        assert_eq!(Granule::Granule16k.first_level_for_t0sz(64 - 14), Granule::Granule16k.first_level());
    }
}
