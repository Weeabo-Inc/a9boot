//! Just enough ELF64 to turn the payload's linked ELF into the flat bytes the channel carries.
//!
//! The payload is delivered inside a `DFU_DNLOAD` and executed **in place** at
//! `abi::payload_exec_addr()`, so what goes on the wire is not the ELF file but the *loadable
//! image*: every `PT_LOAD` segment's file bytes, placed at `p_vaddr - base`, with the gaps
//! zero-filled.
//!
//! Rolling this by hand rather than pulling in `objcopy` or a crate is deliberate: it is ~80
//! lines, it is pure, it is testable against the real built artefact, and it lets the host
//! **verify the link contract** — that the ELF's entry point is exactly where the host is about
//! to jump, and that the footprint fits the budget the linker was given. Those are two of the
//! checks that catch a wrong address before it becomes a silent corruption on the device.

use a9boot_core::abi;
use a9boot_core::layout::PAYLOAD_MAX_FOOTPRINT;
use std::collections::BTreeMap;

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
const EM_AARCH64: u16 = 183;

/// The flat image, with the contract checks already applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatImage {
    /// Where the image must be written: `abi::payload_exec_addr()`.
    pub base: u64,
    /// The loadable bytes, contiguous from `base`.
    pub bytes: Vec<u8>,
    /// The ELF's entry point, which must equal `base`.
    pub entry: u64,
    /// **Size in bytes** of the image plus `.bss` (the payload's stack): the region the channel
    /// occupies from `base`. Must fit both `PAYLOAD_MAX_FOOTPRINT` and the probed buffer
    /// capacity. It is a size, not an end address — the two were confused once already.
    pub footprint: u64,
}

impl FlatImage {
    /// Checks that must pass before the payload is allowed anywhere near the device.
    pub fn check(&self) -> Result<(), String> {
        if self.entry != self.base {
            return Err(format!(
                "the payload's ELF entry point is {:#x} but the command channel will execute it \
                 at {:#x}: the linker script and a9boot_core::abi disagree, and every absolute \
                 address in the payload would be wrong.",
                self.entry,
                self.base
            ));
        }
        if self.footprint > PAYLOAD_MAX_FOOTPRINT {
            return Err(format!(
                "the payload's footprint is {} bytes, over its {} byte budget",
                self.footprint, PAYLOAD_MAX_FOOTPRINT
            ));
        }
        if self.bytes.len() as u64 > self.footprint {
            return Err(format!(
                "the delivered image ({} bytes) is larger than the reported footprint ({} bytes)",
                self.bytes.len(),
                self.footprint
            ));
        }
        Ok(())
    }

    /// Bytes that are `.bss`: delivered as nothing, zeroed by `_start` on the device.
    pub fn bss_len(&self) -> u64 {
        self.footprint - self.bytes.len() as u64
    }

    pub fn summary(&self) -> String {
        format!(
            "base {:#x}, {} bytes delivered + {} bytes .bss = {} bytes footprint (budget {}), entry {:#x}",
            self.base,
            self.bytes.len(),
            self.bss_len(),
            self.footprint,
            PAYLOAD_MAX_FOOTPRINT,
            self.entry
        )
    }
}

/// Flatten an ELF64 little-endian AArch64 executable.
pub fn flatten(elf: &[u8]) -> Result<FlatImage, String> {
    if elf.len() < 64 || elf[0..4] != ELF_MAGIC {
        return Err("not an ELF file".to_string());
    }
    if elf[4] != 2 {
        return Err(format!("ELF class {} is not 64-bit", elf[4]));
    }
    if elf[5] != 1 {
        return Err("ELF is not little-endian".to_string());
    }
    let u16_at = |o: usize| u16::from_le_bytes([elf[o], elf[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([elf[o], elf[o + 1], elf[o + 2], elf[o + 3]]);
    let u64_at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&elf[o..o + 8]);
        u64::from_le_bytes(b)
    };
    if u16_at(18) != EM_AARCH64 {
        return Err(format!("ELF machine {} is not AArch64 ({EM_AARCH64})", u16_at(18)));
    }
    let entry = u64_at(24);
    let phoff = u64_at(32) as usize;
    let phentsize = u16_at(54) as usize;
    let phnum = u16_at(56) as usize;
    if phnum == 0 || phentsize < 56 {
        return Err(format!("no program headers (phnum {phnum}, phentsize {phentsize})"));
    }
    if phoff + phnum * phentsize > elf.len() {
        return Err("program header table runs past the end of the file".to_string());
    }

    // A sparse map first, so overlapping segments are detected rather than silently ordered.
    let mut placed: BTreeMap<u64, u8> = BTreeMap::new();
    let mut base: Option<u64> = None;
    let mut end = 0u64;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let p_type = u32_at(p);
        if p_type != PT_LOAD {
            continue;
        }
        let p_offset = u64_at(p + 8) as usize;
        let p_vaddr = u64_at(p + 16);
        let p_filesz = u64_at(p + 32) as usize;
        let p_memsz = u64_at(p + 40);
        if p_filesz as u64 > p_memsz {
            return Err(format!("segment {i}: filesz {p_filesz} > memsz {p_memsz}"));
        }
        if p_offset + p_filesz > elf.len() {
            return Err(format!("segment {i}: file range runs past the end of the ELF"));
        }
        let b = *base.get_or_insert(p_vaddr);
        if p_vaddr < b {
            base = Some(p_vaddr);
        }
        end = end.max(p_vaddr + p_memsz);
        for (k, byte) in elf[p_offset..p_offset + p_filesz].iter().enumerate() {
            let a = p_vaddr + k as u64;
            if placed.insert(a, *byte).is_some() {
                return Err(format!("segment {i}: overlapping load at {a:#x}"));
            }
        }
    }
    let base = base.ok_or("no PT_LOAD segments")?;
    if end < base {
        return Err("segment addresses wrap".to_string());
    }
    let mut bytes = Vec::with_capacity((end - base) as usize);
    for a in base..end {
        bytes.push(*placed.get(&a).unwrap_or(&0));
    }
    // Belt and braces: the base is what the channel will use, not something read from the ELF.
    let expected = abi::payload_exec_addr();
    if base != expected {
        return Err(format!(
            "the payload is linked at {base:#x} but the channel executes it at {expected:#x}"
        ));
    }
    Ok(FlatImage { base, bytes, entry, footprint: end - base })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real payload, when it has been built for the bare-metal target. This is the check that
    /// ties the three sources of truth together: the linker script (generated from `layout`), the
    /// ELF entry point, and `abi::payload_exec_addr()`.
    #[test]
    fn the_built_payload_matches_the_channel_contract() {
        let candidates = [
            "../target/aarch64-unknown-none-softfloat/payload/a9boot-payload",
            "target/aarch64-unknown-none-softfloat/payload/a9boot-payload",
            "../../target/aarch64-unknown-none-softfloat/payload/a9boot-payload",
        ];
        let path = candidates.iter().map(std::path::Path::new).find(|p| p.exists());
        let path = match path {
            Some(p) => p,
            None => {
                eprintln!(
                    "skipping: the payload ELF is not built. Build it with:\n  cargo build -p \
                     a9boot-payload --profile payload --target aarch64-unknown-none-softfloat"
                );
                return;
            }
        };
        let elf = std::fs::read(path).unwrap();
        let flat = flatten(&elf).expect("the payload ELF must flatten");
        flat.check().expect("the payload must satisfy the channel contract");
        assert_eq!(flat.base, abi::payload_exec_addr());
        assert_eq!(flat.entry, flat.base, "_start must be the first byte, or the link is wrong");
        assert!(flat.footprint <= a9boot_core::layout::PAYLOAD_MAX_FOOTPRINT);
        assert!(flat.bytes.len() >= 2000, "a payload of {} bytes is suspicious", flat.bytes.len());
        eprintln!("payload: {}", flat.summary());
    }

    #[test]
    fn non_elf_input_is_refused_by_name() {
        assert!(flatten(&[0u8; 128]).unwrap_err().contains("not an ELF file"));
        let mut e = vec![0u8; 128];
        e[0..4].copy_from_slice(&ELF_MAGIC);
        e[4] = 2;
        e[5] = 2;
        assert!(flatten(&e).unwrap_err().contains("not little-endian"));
    }
}
