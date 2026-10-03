//! The arm64 `Image` header: what the kernel tells the loader about itself.
//!
//! booting.rst ("Call the kernel image") defines a 64-byte little-endian header:
//!
//! ```text
//!   u32 code0;            /* Executable code */            offset  0
//!   u32 code1;            /* Executable code */            offset  4
//!   u64 text_offset;      /* Image load offset, LE */       offset  8
//!   u64 image_size;       /* Effective Image size, LE */    offset 16
//!   u64 flags;            /* kernel flags, LE */            offset 24
//!   u64 res2 = 0;                                          offset 32
//!   u64 res3 = 0;                                          offset 40
//!   u64 res4 = 0;                                          offset 48
//!   u32 magic = 0x644d5241;  /* "ARM\x64" */               offset 56
//!   u32 res5;                                              offset 60
//! ```
//!
//! **The loader reads these; it does not assume them.** `text_offset` in particular has changed
//! value across kernel versions and configurations, and "The Image must be placed text_offset
//! bytes from a 2MB aligned base address anywhere in usable system RAM and called there."
//! A loader that hardcodes `0x80000` is correct until the day it silently is not.
//!
//! `flags` bits 1-2 are the kernel page size: 0 unspecified, 1 = 4K, 2 = 16K, 3 = 64K. A9 is a
//! 16K-page part and `a9linux/artefacts/config_16k` sets `CONFIG_ARM64_16K_PAGES=y`, so a
//! mismatch here means the wrong kernel image was staged — which on the device is
//! indistinguishable from "the kernel is broken". Refuse it by name instead.

use crate::{Error, Result};

pub const HEADER_LEN: usize = 64;
/// "ARM\x64" little-endian.
pub const MAGIC: u32 = 0x644d_5241;

pub mod flags {
    /// Bit 0: kernel endianness (1 = big endian).
    pub const BE: u64 = 1 << 0;
    /// Bits 1-2: kernel page size.
    pub const PAGE_SIZE_MASK: u64 = 0b11 << 1;
    pub const PAGE_SIZE_SHIFT: u32 = 1;
    /// Bit 3: physical placement (0 = base as close as possible to the base of DRAM; 1 = the
    /// 2 MiB aligned base must keep all `image_size` bytes inside the 48-bit physical range).
    pub const PLACEMENT: u64 = 1 << 3;
}

pub mod page_size {
    pub const UNSPECIFIED: u64 = 0;
    pub const K4: u64 = 1;
    pub const K16: u64 = 2;
    pub const K64: u64 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub code0: u32,
    pub code1: u32,
    pub text_offset: u64,
    pub image_size: u64,
    pub flags: u64,
    pub magic: u32,
    pub res5: u32,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Header> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::new("IMAGE_TOO_SHORT", bytes.len() as u64));
        }
        let u32_at = |o: usize| -> u32 {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };
        let u64_at = |o: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[o..o + 8]);
            u64::from_le_bytes(b)
        };
        let magic = u32_at(56);
        if magic != MAGIC {
            return Err(Error::new("IMAGE_MAGIC_BAD", magic as u64));
        }
        Ok(Header {
            code0: u32_at(0),
            code1: u32_at(4),
            text_offset: u64_at(8),
            image_size: u64_at(16),
            flags: u64_at(24),
            magic,
            res5: u32_at(60),
        })
    }

    pub fn is_big_endian(&self) -> bool {
        self.flags & flags::BE != 0
    }

    pub fn page_size_flag(&self) -> u64 {
        (self.flags & flags::PAGE_SIZE_MASK) >> flags::PAGE_SIZE_SHIFT
    }

    pub fn placement_high(&self) -> bool {
        self.flags & flags::PLACEMENT != 0
    }

    /// Strict check for this project's kernel: little-endian, 16K pages, a real `image_size`.
    ///
    /// Each failure has its own code because each one has a different cause and a different
    /// fix: `IMAGE_PAGE_SIZE_NOT_16K` is "wrong config", `IMAGE_PAGE_SIZE_UNSPECIFIED` is "this
    /// kernel cannot tell us, so we cannot verify it", `IMAGE_SIZE_ZERO` is "this header
    /// predates v3.17 or was not produced by a real build".
    pub fn validate_for_a9(&self) -> Result<()> {
        if self.is_big_endian() {
            return Err(Error::new("IMAGE_BIG_ENDIAN", self.flags));
        }
        match self.page_size_flag() {
            page_size::K16 => {}
            page_size::UNSPECIFIED => {
                return Err(Error::new("IMAGE_PAGE_SIZE_UNSPECIFIED", self.flags))
            }
            other => return Err(Error::new("IMAGE_PAGE_SIZE_NOT_16K", other)),
        }
        if self.image_size == 0 {
            return Err(Error::new("IMAGE_SIZE_ZERO", 0));
        }
        Ok(())
    }

    /// Compare the file against the header, keeping **reserve** and **transfer** apart.
    ///
    /// `image_size` is `_end - _text`: the kernel's **memory footprint**, which includes `.bss`
    /// (`a9linux/artefacts/kernel/BUILD-LOG.md:845`). The file contains only the *stored* portion,
    /// so `file_len < image_size` is the normal, expected relationship — MEASURED on both kernels
    /// we ship: `image_size = 0x1370000`, file `0x12d7200`, gap `0x98e00` (626,176 B of `.bss`).
    ///
    /// The structural invariant is therefore `file_len <= image_size`: stored bytes cannot exceed
    /// the footprint the kernel's own linker asserted. The gap is the kernel's `.bss`, which its
    /// `head.S` clears, so the loader's obligation is to **reserve** `image_size` (and keep every
    /// other blob out of that span) while **transferring** `file_len`.
    ///
    /// What this check deliberately does **not** claim: it cannot detect a truncated tail. The
    /// header does not say how many bytes the stored portion should have, so `file_len` short of
    /// the true file size looks exactly like a large `.bss`. Tail truncation is caught by
    /// verifying the *artefact* (a declared size or hash), and a truncated *transfer* is caught by
    /// the loader's per-chunk read-back — not by this comparison. Saying so is the point: a check
    /// that silently passes for the wrong reason is how this project has lost rounds.
    pub fn check_extent(&self, file_len: u64) -> Result<ImageExtent> {
        if file_len > self.image_size {
            return Err(Error::new("IMAGE_FILE_EXCEEDS_FOOTPRINT", file_len));
        }
        Ok(ImageExtent {
            reserve: self.image_size,
            transfer: file_len,
            bss_gap: self.image_size - file_len,
        })
    }

    /// Where the kernel is entered: the start of the Image, never `+ text_offset` again.
    /// booting.rst: "The primary CPU must jump directly to the first instruction of the kernel
    /// image."
    pub fn entry_addr(&self, base_2m: u64) -> Result<u64> {
        base_2m
            .checked_add(self.text_offset)
            .ok_or(Error::new("IMAGE_ENTRY_OVERFLOW", base_2m))
    }

    /// How much address space to reserve from the 2 MiB aligned base: `text_offset` (the gap the
    /// kernel expects to sit above the base) plus `image_size`, rounded up to a 2 MiB multiple so
    /// that the *next* blob starts in its own 2 MiB region.
    pub fn span_from_base(&self) -> Result<u64> {
        let end = self
            .text_offset
            .checked_add(self.image_size)
            .ok_or(Error::new("IMAGE_SPAN_OVERFLOW", self.image_size))?;
        Ok(crate::align_up(end, crate::layout::TWO_MIB))
    }
}

/// The two quantities a loader must never conflate: how much address space to **reserve**
/// (`image_size`, `.bss` included) and how many bytes to **transfer** (the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageExtent {
    pub reserve: u64,
    pub transfer: u64,
    /// `reserve - transfer`: the kernel's own `.bss` and any other zero-initialised tail. Cleared
    /// by the kernel's `head.S`, not transferred by the loader.
    pub bss_gap: u64,
}

impl ImageExtent {
    /// `no_std` and no allocator here: the fields are the interface, and the host formats them.
    pub const fn is_exact(self) -> bool {
        self.bss_gap == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{IMAGE_2M_BASE, TWO_MIB};
    extern crate alloc;
    use alloc::vec;

    /// The real numbers from the shipped device kernel (`BUILD-LOG.md:845`): the footprint is
    /// `0x1370000`, the file is `0x12d7200`, and the difference is `.bss`.
    #[test]
    fn reserve_and_transfer_are_two_quantities_and_the_gap_is_bss() {
        let mut img = vec![0u8; 0x200];
        img[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes()); // "ARMd" magic
        img[8..16].copy_from_slice(&0u64.to_le_bytes()); // text_offset
        img[16..24].copy_from_slice(&0x0137_0000u64.to_le_bytes()); // image_size
        img[24..32].copy_from_slice(&(2u64 << 1).to_le_bytes()); // flags: 16 KiB granule, LE
        let h = Header::parse(&img).unwrap();
        h.validate_for_a9().unwrap();
        let e = h.check_extent(0x12d_7200).unwrap();
        assert_eq!(e.reserve, 0x0137_0000);
        assert_eq!(e.transfer, 0x12d_7200);
        assert_eq!(e.bss_gap, 0x98e00);
        assert!(!e.is_exact());
        // Equality is the degenerate case (no .bss), and it is allowed.
        let e = h.check_extent(0x0137_0000).unwrap();
        assert!(e.is_exact());
        assert_eq!(e.bss_gap, 0);
    }

    /// The negative control in the other direction: a file larger than the footprint the kernel's
    /// own linker asserted cannot be a stored Image, and is refused **by name**.
    #[test]
    fn a_file_larger_than_the_footprint_is_refused_by_name() {
        let mut img = vec![0u8; 0x200];
        img[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
        img[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        img[24..32].copy_from_slice(&(2u64 << 1).to_le_bytes());
        let h = Header::parse(&img).unwrap();
        let err = h.check_extent(0x1001).unwrap_err();
        assert_eq!(err.code, "IMAGE_FILE_EXCEEDS_FOOTPRINT");
        assert_eq!(err.detail, 0x1001);
    }

    fn header_bytes(text_offset: u64, image_size: u64, flags: u64) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&0xd280_0000u32.to_le_bytes()); // a plausible code0 (movz x0,#0)
        b[8..16].copy_from_slice(&text_offset.to_le_bytes());
        b[16..24].copy_from_slice(&image_size.to_le_bytes());
        b[24..32].copy_from_slice(&flags.to_le_bytes());
        b[56..60].copy_from_slice(&MAGIC.to_le_bytes());
        b
    }

    #[test]
    fn parses_a_16k_image() {
        let bytes = header_bytes(0x80000, 0x200_0000, (page_size::K16 << 1) | 0);
        let h = Header::parse(&bytes).unwrap();
        assert_eq!(h.text_offset, 0x80000);
        assert_eq!(h.image_size, 0x200_0000);
        assert!(!h.is_big_endian());
        assert_eq!(h.page_size_flag(), page_size::K16);
        h.validate_for_a9().unwrap();
        assert_eq!(h.entry_addr(IMAGE_2M_BASE).unwrap(), IMAGE_2M_BASE + 0x80000);
        // 0x80000 + 0x200_0000 = 0x208_0000, rounded up to a 2 MiB multiple = 0x220_0000.
        assert_eq!(h.span_from_base().unwrap(), 0x220_0000);
    }

    /// A 4K kernel is the `defconfig` mistake this project already made once (HANDOFF §5).
    #[test]
    fn a_4k_kernel_is_refused_by_name() {
        let bytes = header_bytes(0x80000, 0x1000, page_size::K4 << 1);
        let err = Header::parse(&bytes).unwrap().validate_for_a9().unwrap_err();
        assert_eq!(err.code, "IMAGE_PAGE_SIZE_NOT_16K");
        assert_eq!(err.detail, page_size::K4);
    }

    #[test]
    fn an_unspecified_page_size_is_refused_rather_than_guessed() {
        let bytes = header_bytes(0x80000, 0x1000, 0);
        let err = Header::parse(&bytes).unwrap().validate_for_a9().unwrap_err();
        assert_eq!(err.code, "IMAGE_PAGE_SIZE_UNSPECIFIED");
    }

    #[test]
    fn a_big_endian_kernel_is_refused() {
        let bytes = header_bytes(0x80000, 0x1000, (page_size::K16 << 1) | flags::BE);
        let err = Header::parse(&bytes).unwrap().validate_for_a9().unwrap_err();
        assert_eq!(err.code, "IMAGE_BIG_ENDIAN");
    }

    #[test]
    fn a_missing_magic_is_refused_before_anything_else() {
        let mut bytes = header_bytes(0x80000, 0x1000, page_size::K16 << 1);
        bytes[56..60].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(Header::parse(&bytes).unwrap_err().code, "IMAGE_MAGIC_BAD");
        assert_eq!(Header::parse(&[0u8; 8]).unwrap_err().code, "IMAGE_TOO_SHORT");
    }

    #[test]
    fn zero_image_size_is_refused() {
        let bytes = header_bytes(0x80000, 0, page_size::K16 << 1);
        assert_eq!(
            Header::parse(&bytes).unwrap().validate_for_a9().unwrap_err().code,
            "IMAGE_SIZE_ZERO"
        );
    }

    /// The span is 2 MiB-aligned so the next blob never shares a 2 MiB region with the kernel.
    #[test]
    fn span_is_two_mib_aligned() {
        let bytes = header_bytes(0, 0x1000, page_size::K16 << 1);
        let h = Header::parse(&bytes).unwrap();
        assert_eq!(h.span_from_base().unwrap(), TWO_MIB);
        assert_eq!(h.span_from_base().unwrap() % TWO_MIB, 0);
    }
}
