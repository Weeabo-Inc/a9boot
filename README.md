<div align="center">
	<h2>a9boot</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-aarch64%20%2B%20host-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-payload%20executing%20at%20EL3-brightgreen.svg?style=flat-square)]()

### Replaces pongoOS *and* m1n1: takes a pwned A9 and hands mainline Linux a correct Non-secure EL1 state.

The pre-boot loader for the iPhone SE 1st gen (Apple A9 `s8003`, board `n69ap`). No pongoOS, no m1n1 — a pwned checkm8 device goes in, and a kernel with a device tree that actually describes the machine comes out.

**Read [`DESIGN.md`](DESIGN.md) first** — it is the contract. Then [`UNVERIFIED.md`](UNVERIFIED.md) for every assumption with the test that would falsify it, and [`QEMU-CONTRACT.md`](QEMU-CONTRACT.md) for what a QEMU harness can and cannot prove.

---

### What does this do?

It drives the resident checkm8 handler through the ROM's own DFU buffer: `MEMC` for memory, `EXEC` to run our code in the ROM's EL3 context, and a staged-then-verified upload where **nothing is executed unless the staged image compares byte-for-byte with the host's**.

```
  command      EXEC DESCRIBE (2), packet 11240 bytes = 6 DNLOAD transfers
  staged at    0x180380110 (entry 0x180380110), inside the ROM's DFU buffer
  verification 6 read-back chunk(s) of 2048 bytes, compared byte for byte
  trigger      UPLOAD wLength 128 — the 0xFFFF trigger
```

The payload's reply (recovered from the wire) carries the CPU state at entry:

```
current_el = 0xC (EL3)   scr_el3 = 0x43E   sctlr_el3 = 0x30C5183D (MMU on)
ttbr0_el3  = 0x1800875C0  tcr_el3 = 0x8081A51B (T0SZ=27 -> 37-bit VA, TG0=0b10 -> 16K)
```

---

### The failure this exists to prevent

**Assuming our code gets its own address space.** It does not: the payload runs in the ROM's EL3 context and inherits its `TTBR0_EL3`. Reading an unmapped address does not fault politely — it hangs the bus, wedges EP0, and can cost the device. One such read did.

That is why the loader is built around *proving* things first: a canary read of the resident handler, a staged-image verification before every trigger, a page-table walk that answers "may I touch this?" **without touching it**, and a capacity ladder whose probe writes nothing anywhere. The walk refuses to report `UNMAPPED` unless a known-mapped address comes back `MAPPED` in the same run — a walk that says no to everything is not evidence about an address.

---

### Layout

| Crate | What | Target |
|---|---|---|
| `crates/a9boot-core` | Layout, `Image` header, channel ABI, layout planner. `no_std`, no dependencies, unit-tested on the host | host **and** `aarch64-unknown-none-softfloat` |
| `crates/a9boot-host` | Device-tree editor, command codec, plan/probe, ELF flattener. The only crate that could touch a device, and by default it cannot | host |
| `crates/a9boot-payload` | The on-device EL3 trampoline. Stateless, non-resident, executed in place inside the DFU buffer | `aarch64-unknown-none-softfloat` |

---

### Status

**MEASURED on hardware:** the payload is delivered, verified byte-for-byte, triggered, and executes at EL3, returning a well-formed reply (`current_el = 0xC`). `§12` step 1 — the CPU-state anchor — is delivered. The page-table walk is correct as to encoding and granule but still needs `T0SZ` fed to it before it can answer DRAM reachability.

The capacity ladder is MEASURED: a 11,240-byte, 6-transfer command is accepted, so the payload ships as one command. Staging requires DFU state 8 — measured 5/5; in state 5 the accumulation does not reproduce the image, and the loader refuses by name rather than jumping into a half-written buffer.
