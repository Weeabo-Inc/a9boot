//! The device-tree editor.
//!
//! The DTS for this board marks `memory`, `framebuffer0` and `cpu-release-addr` as
//! `/* To be filled by loader */`, and the built DTB has `memory` `reg = <0x8 0 0 0>` — that is,
//! **size 0**: the kernel gets no RAM at all. On top of that there is no `/chosen/bootargs`
//! (`CONFIG_CMDLINE=""`, so the command line must be injected) and no `linux,initrd-start/end`
//! (so the initramfs would never be unpacked).
//!
//! Editing happens **here, on the host**, and for a specific reason: the values are all known at
//! plan time (the host decides every address), so the on-device payload needs no FDT code at all,
//! and the exact bytes the kernel will be handed can be printed and reviewed *before* hardware is
//! touched. Parse → owned tree → serialise also means there is no slack arithmetic and no
//! in-place resize, which is where an FDT editor usually goes wrong quietly.
//!
//! ## Cell endianness
//!
//! Every DT cell is **big-endian**, regardless of the CPU's endianness:
//!
//! * `reg` / `cpu-release-addr` / `linux,initrd-*` are 32-bit cells, big-endian, and a 64-bit
//!   address is two of them (HI then LO). `of_property_read_u64` reads 8 bytes as
//!   `of_read_number(val, 2)` = `be32[0] << 32 | be32[1]`; the initrd code takes the
//!   `sizeof(__be64)` path and does the same.
//! * Memory-reservation entries are 64-bit big-endian pairs.
//!
//! Getting this wrong produces a DTB that parses, contains the "right" numbers when read as
//! little-endian, and tells the kernel the memory is at `0x0800_0000_0000_0000`. The tests below
//! pin the exact bytes for that reason.

use std::collections::BTreeMap;

pub const FDT_MAGIC: u32 = 0xd00d_feed;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Node {
    pub name: String,
    pub props: Vec<Property>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(name: &str) -> Self {
        Node { name: name.to_string(), props: Vec::new(), children: Vec::new() }
    }

    /// Find the property with `name`.
    pub fn prop(&self, name: &str) -> Option<&Property> {
        self.props.iter().find(|p| p.name == name)
    }

    /// Replace or add a property, preserving position when it already exists (so a diff of two
    /// edits is readable) and appending otherwise.
    pub fn set_prop(&mut self, name: &str, value: Vec<u8>) {
        match self.props.iter_mut().find(|p| p.name == name) {
            Some(p) => p.value = value,
            None => self.props.push(Property { name: name.to_string(), value }),
        }
    }

    pub fn set_prop_str(&mut self, name: &str, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.set_prop(name, v);
    }

    /// A `compatible`-style string list: NUL-separated, NUL-terminated. The kernel matches any
    /// entry, and the driver for the AUSB PHY matches the *second* one (`apple,ausb-phy`), which
    /// is why a single-string property is not equivalent.
    pub fn set_prop_strlist(&mut self, name: &str, items: &[&str]) {
        let mut v = Vec::new();
        for s in items {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        self.set_prop(name, v);
    }

    pub fn prop_str(&self, name: &str) -> Option<String> {
        let p = self.prop(name)?;
        let end = p.value.iter().position(|b| *b == 0).unwrap_or(p.value.len());
        String::from_utf8(p.value[..end].to_vec()).ok()
    }

    pub fn set_prop_cells(&mut self, name: &str, cells: &[u32]) {
        let mut v = Vec::with_capacity(cells.len() * 4);
        for c in cells {
            v.extend_from_slice(&c.to_be_bytes());
        }
        self.set_prop(name, v);
    }

    /// Read a big-endian cell array as u32s. Returns `None` if the length is not a multiple of 4.
    pub fn prop_cells(&self, name: &str) -> Option<Vec<u32>> {
        let p = self.prop(name)?;
        if p.value.len() % 4 != 0 {
            return None;
        }
        Some(
            p.value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
        )
    }

    /// Read a 64-bit value stored as two big-endian cells (the DT's `u64` convention).
    pub fn prop_u64(&self, name: &str) -> Option<u64> {
        let cells = self.prop_cells(name)?;
        if cells.len() != 2 {
            return None;
        }
        Some(((cells[0] as u64) << 32) | cells[1] as u64)
    }

    pub fn set_prop_u64_cells(&mut self, name: &str, v: u64) {
        self.set_prop_cells(name, &[(v >> 32) as u32, (v & 0xffff_ffff) as u32]);
    }

    /// Child by name (`"chosen"`, `"memory@800000000"`, …).
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut Node> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// First child whose name starts with `prefix` — how `memory@<addr>` and
    /// `framebuffer@<addr>` are found without hardcoding the unit address.
    pub fn child_prefix(&self, prefix: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name.starts_with(prefix))
    }

    pub fn child_prefix_mut(&mut self, prefix: &str) -> Option<&mut Node> {
        self.children.iter_mut().find(|c| c.name.starts_with(prefix))
    }

    /// Find a node by its `compatible` string, anywhere in the tree (read-only form).
    pub fn find_by_compatible(&self, compatible: &str) -> Option<&Node> {
        if self
            .prop("compatible")
            .map(|p| p.value.split(|b| *b == 0).any(|s| s == compatible.as_bytes()))
            .unwrap_or(false)
        {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find_by_compatible(compatible))
    }

    /// Find a node by its `compatible` string, anywhere in the tree.
    ///
    /// Used instead of a hardcoded path because the DTB's node names are not part of any
    /// contract: `phy@20c000030` under `bus@20c000000` is where it is *today*, and a driver
    /// match is what the kernel itself uses.
    pub fn find_by_compatible_mut(&mut self, compatible: &str) -> Option<&mut Node> {
        if self
            .prop("compatible")
            .map(|p| {
                p.value
                    .split(|b| *b == 0)
                    .any(|s| s == compatible.as_bytes())
            })
            .unwrap_or(false)
        {
            return Some(self);
        }
        for c in self.children.iter_mut() {
            if let Some(n) = c.find_by_compatible_mut(compatible) {
                return Some(n);
            }
        }
        None
    }

    /// Count of nodes in this subtree, for change summaries and tests.
    pub fn node_count(&self) -> usize {
        1 + self.children.iter().map(|c| c.node_count()).sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fdt {
    pub root: Node,
    /// Memory-reservation entries, in order: (address, size).
    pub memrsv: Vec<(u64, u64)>,
    pub boot_cpuid_phys: u32,
    /// Padding appended after the structure block on serialise, so the result has room to be
    /// edited again (by `dtc -p`, or by a later a9boot stage) without a realloc dance.
    pub padding: usize,
}

impl Fdt {
    /// Parse a flattened device tree.
    pub fn parse(bytes: &[u8]) -> Result<Fdt, String> {
        if bytes.len() < 40 {
            return Err(format!("FDT too short: {} bytes", bytes.len()));
        }
        let u32_at = |o: usize| u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_be_bytes([
                bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3],
                bytes[o + 4], bytes[o + 5], bytes[o + 6], bytes[o + 7],
            ])
        };
        let magic = u32_at(0);
        if magic != FDT_MAGIC {
            return Err(format!("bad FDT magic: {magic:#010x}, expected {FDT_MAGIC:#010x}"));
        }
        let totalsize = u32_at(4) as usize;
        if totalsize > bytes.len() {
            return Err(format!("FDT totalsize {totalsize} exceeds the {} bytes given", bytes.len()));
        }
        let off_struct = u32_at(8) as usize;
        let off_strings = u32_at(12) as usize;
        let off_memrsv = u32_at(16) as usize;
        let size_strings = u32_at(32) as usize;
        let size_struct = u32_at(36) as usize;
        let boot_cpuid_phys = u32_at(28);
        if off_struct + size_struct > totalsize || off_strings + size_strings > totalsize {
            return Err("FDT block offsets run past totalsize".to_string());
        }
        let strings = &bytes[off_strings..off_strings + size_strings];

        // Memory reservation block: big-endian (address, size) pairs terminated by (0, 0).
        let mut memrsv = Vec::new();
        let mut p = off_memrsv;
        while p + 16 <= totalsize {
            let addr = u64_at(p);
            let size = u64_at(p + 8);
            if addr == 0 && size == 0 {
                break;
            }
            memrsv.push((addr, size));
            p += 16;
        }

        // Structure block.
        let s = &bytes[off_struct..off_struct + size_struct];
        let mut cursor = 0usize;
        let mut stack: Vec<Node> = Vec::new();
        let mut root: Option<Node> = None;
        loop {
            if cursor + 4 > s.len() {
                return Err("FDT structure block ended without FDT_END".to_string());
            }
            let token = u32::from_be_bytes([s[cursor], s[cursor + 1], s[cursor + 2], s[cursor + 3]]);
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let end = s[cursor..].iter().position(|b| *b == 0).ok_or("unterminated node name")?;
                    let name = String::from_utf8_lossy(&s[cursor..cursor + end]).to_string();
                    cursor += end + 1;
                    cursor = (cursor + 3) & !3; // 4-byte align
                    stack.push(Node::new(&name));
                }
                FDT_END_NODE => {
                    let node = stack.pop().ok_or("FDT_END_NODE with no open node")?;
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => {
                            if root.is_some() {
                                return Err("more than one root node".to_string());
                            }
                            root = Some(node);
                        }
                    }
                }
                FDT_PROP => {
                    if cursor + 8 > s.len() {
                        return Err("truncated FDT_PROP".to_string());
                    }
                    let len = u32::from_be_bytes([s[cursor], s[cursor + 1], s[cursor + 2], s[cursor + 3]]) as usize;
                    let nameoff = u32::from_be_bytes([s[cursor + 4], s[cursor + 5], s[cursor + 6], s[cursor + 7]]) as usize;
                    cursor += 8;
                    if cursor + len > s.len() {
                        return Err("FDT_PROP value runs past the structure block".to_string());
                    }
                    let value = s[cursor..cursor + len].to_vec();
                    cursor += len;
                    cursor = (cursor + 3) & !3;
                    let name = read_string(strings, nameoff)
                        .ok_or_else(|| format!("property name offset {nameoff} is outside the strings block"))?;
                    let node = stack.last_mut().ok_or("FDT_PROP outside any node")?;
                    node.props.push(Property { name, value });
                }
                FDT_NOP => {}
                FDT_END => break,
                other => return Err(format!("unknown FDT token {other:#x} at {cursor:#x}")),
            }
        }
        let root = root.ok_or("FDT has no root node")?;
        Ok(Fdt { root, memrsv, boot_cpuid_phys, padding: 0x1000 })
    }

    /// Serialise back to a flattened blob, `padding` bytes longer than the structures require.
    pub fn serialise(&self) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut names: BTreeMap<String, u32> = BTreeMap::new();
        let mut struct_block = Vec::new();
        self.emit_node(&self.root, true, &mut struct_block, &mut strings, &mut names);
        struct_block.extend_from_slice(&FDT_END.to_be_bytes());

        let mut memrsv = Vec::new();
        for (a, s) in &self.memrsv {
            memrsv.extend_from_slice(&a.to_be_bytes());
            memrsv.extend_from_slice(&s.to_be_bytes());
        }
        memrsv.extend_from_slice(&[0u8; 16]); // terminator

        let off_memrsv = 40usize;
        let off_struct = align8(off_memrsv + memrsv.len());
        let off_strings = align4(off_struct + struct_block.len());
        let totalsize = align8(off_strings + strings.len()) + self.padding;

        let mut out = vec![0u8; totalsize];
        out[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        out[4..8].copy_from_slice(&(totalsize as u32).to_be_bytes());
        out[8..12].copy_from_slice(&(off_struct as u32).to_be_bytes());
        out[12..16].copy_from_slice(&(off_strings as u32).to_be_bytes());
        out[16..20].copy_from_slice(&(off_memrsv as u32).to_be_bytes());
        out[20..24].copy_from_slice(&17u32.to_be_bytes()); // version
        out[24..28].copy_from_slice(&16u32.to_be_bytes()); // last_comp_version
        out[28..32].copy_from_slice(&self.boot_cpuid_phys.to_be_bytes());
        out[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        out[36..40].copy_from_slice(&(struct_block.len() as u32).to_be_bytes());
        out[off_memrsv..off_memrsv + memrsv.len()].copy_from_slice(&memrsv);
        out[off_struct..off_struct + struct_block.len()].copy_from_slice(&struct_block);
        out[off_strings..off_strings + strings.len()].copy_from_slice(&strings);
        out
    }

    fn emit_node(
        &self,
        node: &Node,
        is_root: bool,
        out: &mut Vec<u8>,
        strings: &mut Vec<u8>,
        names: &mut BTreeMap<String, u32>,
    ) {
        out.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        // The root node's name is the empty string in the flattened form.
        let name = if is_root { "" } else { node.name.as_str() };
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        for p in &node.props {
            let nameoff = match names.get(&p.name) {
                Some(o) => *o,
                None => {
                    let o = strings.len() as u32;
                    strings.extend_from_slice(p.name.as_bytes());
                    strings.push(0);
                    names.insert(p.name.clone(), o);
                    o
                }
            };
            out.extend_from_slice(&FDT_PROP.to_be_bytes());
            out.extend_from_slice(&(p.value.len() as u32).to_be_bytes());
            out.extend_from_slice(&nameoff.to_be_bytes());
            out.extend_from_slice(&p.value);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        for c in &node.children {
            self.emit_node(c, false, out, strings, names);
        }
        out.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    }

    /// Add a memory-reservation entry unless an identical one already exists.
    pub fn add_memrsv(&mut self, addr: u64, size: u64) {
        if size == 0 || self.memrsv.contains(&(addr, size)) {
            return;
        }
        self.memrsv.push((addr, size));
    }
}

fn read_string(strings: &[u8], off: usize) -> Option<String> {
    if off >= strings.len() {
        return None;
    }
    let end = strings[off..].iter().position(|b| *b == 0)?;
    Some(String::from_utf8_lossy(&strings[off..off + end]).to_string())
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}
fn align8(v: usize) -> usize {
    (v + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal tree exercising root naming, nested nodes, property order and alignment.
    fn sample() -> Fdt {
        let mut root = Node::new("");
        root.set_prop_cells("#address-cells", &[2]);
        root.set_prop_cells("#size-cells", &[2]);
        let mut chosen = Node::new("chosen");
        chosen.set_prop_str("stdout-path", "serial0");
        root.children.push(chosen);
        let mut mem = Node::new("memory@800000000");
        mem.set_prop_str("device_type", "memory");
        mem.set_prop_cells("reg", &[0x8, 0, 0, 0]);
        root.children.push(mem);
        Fdt { root, memrsv: vec![(0x8_7FE0_0000, 0x20_0000)], boot_cpuid_phys: 0, padding: 0x100 }
    }

    #[test]
    fn round_trips_through_serialise_and_parse() {
        let f = sample();
        let bytes = f.serialise();
        assert_eq!(&bytes[0..4], &FDT_MAGIC.to_be_bytes());
        let g = Fdt::parse(&bytes).unwrap();
        assert_eq!(g.root, f.root);
        assert_eq!(g.memrsv, f.memrsv);
        // totalsize covers everything, and the padding is real.
        let totalsize = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(totalsize, bytes.len());
        assert!(totalsize >= f.padding + 40);
    }

    /// The whole point: `memory@800000000` `reg` must end up as four **big-endian** cells, or
    /// the kernel reads an address it cannot use.
    #[test]
    fn cell_endianness_is_big_endian_on_the_wire() {
        let mut f = sample();
        let mem = f.root.child_prefix_mut("memory@").unwrap();
        mem.set_prop_cells("reg", &[0x8, 0x0000_0000, 0x0, 0x8000_0000]);
        let bytes = f.serialise();
        let g = Fdt::parse(&bytes).unwrap();
        let mem = g.root.child_prefix("memory@").unwrap();
        assert_eq!(mem.prop("reg").unwrap().value, vec![
            0x00, 0x00, 0x00, 0x08, // HI of 0x8_0000_0000
            0x00, 0x00, 0x00, 0x00, // LO
            0x00, 0x00, 0x00, 0x00,
            0x80, 0x00, 0x00, 0x00, // 2 GiB
        ]);
        assert_eq!(mem.prop_cells("reg").unwrap(), vec![0x8, 0, 0, 0x8000_0000]);
    }

    /// A 64-bit property is two big-endian cells, which is what `of_property_read_u64` reads.
    #[test]
    fn u64_properties_are_two_cells() {
        let mut n = Node::new("cpu@0");
        n.set_prop_u64_cells("cpu-release-addr", 0x8_7FE3_0000);
        assert_eq!(n.prop_u64("cpu-release-addr").unwrap(), 0x8_7FE3_0000);
        assert_eq!(n.prop("cpu-release-addr").unwrap().value.len(), 8);
        assert_eq!(
            n.prop("cpu-release-addr").unwrap().value,
            vec![0x00, 0x00, 0x00, 0x08, 0x7F, 0xE3, 0x00, 0x00]
        );
    }

    #[test]
    fn strings_are_nul_terminated() {
        let mut n = Node::new("x");
        n.set_prop_str("status", "okay");
        assert_eq!(n.prop("status").unwrap().value, b"okay\0".to_vec());
        assert_eq!(n.prop_str("status").unwrap(), "okay");
    }

    #[test]
    fn property_order_is_preserved_and_updates_do_not_move_it() {
        let mut n = Node::new("x");
        n.set_prop_cells("a", &[1]);
        n.set_prop_cells("b", &[2]);
        n.set_prop_cells("c", &[3]);
        n.set_prop_cells("b", &[9]);
        assert_eq!(n.props.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(n.prop_cells("b").unwrap(), vec![9]);
    }

    #[test]
    fn memrsv_entries_are_deduplicated_and_big_endian() {
        let mut f = sample();
        f.add_memrsv(0x8_7800_0000, 0x40_0000);
        f.add_memrsv(0x8_7800_0000, 0x40_0000);
        assert_eq!(f.memrsv.len(), 2);
        let bytes = f.serialise();
        let g = Fdt::parse(&bytes).unwrap();
        assert_eq!(g.memrsv[1], (0x8_7800_0000, 0x40_0000));
        // Big-endian on the wire: 0x8_7800_0000 as eight bytes.
        let off_memrsv = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
        assert_eq!(
            &bytes[off_memrsv + 16..off_memrsv + 24],
            &[0x00, 0x00, 0x00, 0x08, 0x78, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn parse_failures_are_named() {
        assert!(Fdt::parse(&[0u8; 8]).unwrap_err().contains("too short"));
        assert!(Fdt::parse(&vec![0u8; 64]).unwrap_err().contains("bad FDT magic"));
        let mut bytes = sample().serialise();
        bytes[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        assert!(Fdt::parse(&bytes).unwrap_err().contains("exceeds"));
    }

    /// The real DTB, if `dt-engineer`'s build is present: parse it, edit it the way the loader
    /// must, serialise, re-parse, and assert every value survived. Skipped when absent so the
    /// test suite is hermetic.
    #[test]
    fn fills_the_real_board_dtb_when_present() {
        let path = std::path::Path::new("../a9linux/dts/ref/dts/s8003-n69.dtb");
        let path = if path.exists() { path } else { std::path::Path::new("../../a9linux/dts/ref/dts/s8003-n69.dtb") };
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let bytes = std::fs::read(path).unwrap();
        let mut f = Fdt::parse(&bytes).expect("the board DTB must parse");

        // 1. memory: size 0 in the built artefact (MEASURED by kernel-engineer).
        let mem = f.root.child_prefix_mut("memory@").expect("memory node");
        assert_eq!(mem.prop_cells("reg").unwrap(), vec![0x8, 0, 0, 0]);
        mem.set_prop_cells("reg", &[0x8, 0x0000_0000, 0x0, 0x8000_0000]);

        // 2. /chosen: bootargs (the node has none) and the initrd range.
        let chosen = f.root.child_mut("chosen").expect("chosen node");
        chosen.set_prop_str("bootargs", "earlycon loglevel=8 maxcpus=1");
        chosen.set_prop_u64_cells("linux,initrd-start", 0x8_01C0_0000);
        chosen.set_prop_u64_cells("linux,initrd-end", 0x8_04C0_0000);

        // 3. framebuffer@0: geometry, and status stays disabled in rung 1.
        let fb = f.root.child_mut("chosen").unwrap().child_prefix_mut("framebuffer@").expect("fb node");
        assert_eq!(fb.prop_str("status").unwrap(), "disabled");
        fb.set_prop_cells("reg", &[0x8, 0x7800_0000, 0x0, 0x40_0000]);
        fb.set_prop_cells("width", &[640]);
        fb.set_prop_cells("height", &[1136]);
        fb.set_prop_cells("stride", &[2560]);
        fb.set_prop_str("format", "a8r8g8b8");

        // 4. cpu-release-addr is left at 0 in rung 1: smp_spin_table.c:71-72 turns that into a
        //    printed error rather than a hang.
        let cpus = f.root.child("cpus").expect("cpus node");
        assert_eq!(cpus.child("cpu@0").unwrap().prop_u64("cpu-release-addr").unwrap(), 0);

        // 5. Reservations.
        f.add_memrsv(0x8_0000_0000, 0x0020_0000); // DTB region
        f.add_memrsv(0x8_7800_0000, 0x0040_0000); // framebuffer
        f.add_memrsv(0x8_7FE0_0000, 0x0020_0000); // loader area

        let out = f.serialise();
        let g = Fdt::parse(&out).expect("the edited DTB must re-parse");
        assert_eq!(g.root.child_prefix("memory@").unwrap().prop_cells("reg").unwrap(), vec![0x8, 0, 0, 0x8000_0000]);
        let chosen = g.root.child("chosen").unwrap();
        assert_eq!(chosen.prop_str("bootargs").unwrap(), "earlycon loglevel=8 maxcpus=1");
        assert_eq!(chosen.prop_u64("linux,initrd-start").unwrap(), 0x8_01C0_0000);
        assert_eq!(chosen.prop_u64("linux,initrd-end").unwrap(), 0x8_04C0_0000);
        let fb = chosen.child_prefix("framebuffer@").unwrap();
        assert_eq!(fb.prop_cells("reg").unwrap(), vec![0x8, 0x7800_0000, 0, 0x40_0000]);
        assert_eq!(fb.prop_cells("stride").unwrap(), vec![2560]);
        assert_eq!(fb.prop_str("format").unwrap(), "a8r8g8b8");
        // The binding: "It is advised that devicetree files contain pre-filled, disabled
        // framebuffer nodes, so that the firmware only needs to update the mode information and
        // enable them." Rung 1 updates the mode information and does NOT enable.
        assert_eq!(fb.prop_str("status").unwrap(), "disabled");
        assert!(g.memrsv.contains(&(0x8_7800_0000, 0x0040_0000)));
        assert!(out.len() < 0x20_0000, "the edited DTB must fit its 2 MiB region");
    }
}
