//! `a9boot-host` — the host half of a9boot.
//!
//! Boundary discipline for this crate:
//!
//! * pure logic (device-tree editing, layout, packet construction) is separated from I/O, so it
//!   can be tested without a device and reviewed without a phone;
//! * `channel` speaks the post-pwn command ABI and nothing else;
//! * `transport` is the only place that could ever talk to hardware, and by default it cannot.
//!
//! The device is never opened by this crate in a default build. See `transport::open_live`.

pub mod bounded;
pub mod bundle;
pub mod capacity;
pub mod channel;
pub mod elf;
pub mod evidence;
pub mod exec;
pub mod fdt;
pub mod pagetable;
pub mod firstlight;
pub mod transport;
pub mod walk;

/// Round down to a power-of-two multiple. Used when turning a measured "last address that
/// responded" into an extent that is safe to declare.
pub const fn round_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

/// Round up to a power-of-two multiple.
pub const fn round_up(v: u64, align: u64) -> u64 {
    (v + (align - 1)) & !(align - 1)
}
