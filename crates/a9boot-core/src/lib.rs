//! `a9boot-core` — the shared truth for a9boot.
//!
//! This crate is compiled **twice**: for the host (`x86_64-pc-windows-msvc`, where every
//! function here is unit-tested) and for the on-device payload
//! (`aarch64-unknown-none-softfloat`). It is therefore `no_std`, allocation-free, and
//! dependency-free. Anything that needs to allocate, print, or retry belongs in
//! `a9boot-host`.
//!
//! Nothing in this crate talks to hardware. Nothing in it is a guess: every constant
//! carries an evidence label (MEASURED / INSPECTED / INFERRED / UNVERIFIED) and the
//! citation for it, in the style of HANDOFF §9.5. Where a value is INFERRED, the
//! falsification test lives in `a9boot/UNVERIFIED.md` and in the doc comment itself.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod abi;
pub mod image;
pub mod layout;
pub mod plan;

/// A failure with a **stable, greppable code** and a numeric detail.
///
/// Same discipline as `a9pwn`'s verdict codes: four different problems get four
/// different names, never one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Stable, uppercase. Never reword an existing code; add a new one.
    pub code: &'static str,
    /// The offending value: an address, a size, an offset, a length.
    pub detail: u64,
}

impl Error {
    pub const fn new(code: &'static str, detail: u64) -> Self {
        Self { code, detail }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// `align_up` for powers of two. `align` must be a power of two.
pub const fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

/// `align_down` for powers of two.
pub const fn align_down(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}
