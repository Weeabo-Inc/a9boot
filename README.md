# a9boot

The pre-boot loader for the iPhone SE 1st gen (Apple A9 `s8003`, board `n69ap`): it replaces **both
pongoOS and m1n1**, taking a pwned DFU device and handing plain mainline Linux a correct
Non-secure EL1 state with a device tree that describes the machine.

**Read [`DESIGN.md`](DESIGN.md) first** — it is the contract. Then
[`UNVERIFIED.md`](UNVERIFIED.md) for every assumption with the test that would falsify it, and
[`QEMU-CONTRACT.md`](QEMU-CONTRACT.md) for what a QEMU harness can and cannot prove.

## The two halves

| Crate | What | Target |
|---|---|---|
| `crates/a9boot-core` | The shared truth: physical layout, `Image` header, channel ABI, layout planner. `no_std`, no dependencies, compiled for **both** sides and unit-tested on the host | `x86_64-pc-windows-msvc` **and** `aarch64-unknown-none-softfloat` |
| `crates/a9boot-host` | The host side: device-tree editor, command codec, plan/probe, ELF flattener. The only crate that could ever touch a device, and by default it cannot | `x86_64-pc-windows-msvc` |
| `crates/a9boot-payload` | The on-device EL3 trampoline. Stateless, non-resident, executed in place inside the ROM's DFU buffer | `aarch64-unknown-none-softfloat` |

## Build and test

```powershell
cd E:\Reverseing\Arlo\a9boot

# Everything that can be built and tested on this machine. 75 tests, no device, no network.
cargo test --offline

# The offline report: layout, device-tree diff, descriptor, and every packet that would be sent.
cargo run --offline --plan --image <Image> --dtb <sbc.dtb> [--initramfs <initramfs.gz>] `
          --payload target\aarch64-unknown-none-softfloat\payload\a9boot-payload

# The unified post-pwn experiment (DRAM extent + AUSB tunables). Sends nothing.
cargo run --offline -- probe

# The payload. `--profile payload` (panic=abort, LTO, size) lives in the workspace root because
# cargo only allows `panic`/`lto` to be set there.
cargo build --offline -p a9boot-payload --profile payload --target aarch64-unknown-none-softfloat
```

Notes that will save you a round trip:

* **Do not run `cargo build --workspace` or `cargo test --workspace`.** The payload cannot be built
  for the host, which is why it is excluded from `default-members`. Use a bare `cargo test`, or
  `-p a9boot-core` / `-p a9boot-host`.
* The payload's linker script is **generated** from `a9boot-core::layout` by `build.rs`, so its link
  address cannot drift from `abi::payload_exec_addr()`. A map file lands in the build directory
  (`a9boot-payload.map`) — that is where the footprint numbers in `DESIGN.md` come from.
* The real device tree is optional: the DTB round-trip test uses
  `../a9linux/dts/ref/dts/s8003-n69.dtb` when it exists and skips with a message when it does not.
  Nothing in the test suite is skipped *silently*.

## What this build cannot do, deliberately

**The default build has no USB capability at all.** `transport::open_live()` returns a named
refusal and `selftest` asserts it:

```
FAIL  default build has no USB capability: this build CAN open a device; the default must not
```

There is no command in this crate that opens a device. The real transport is an optional
`usb` feature (approved, matching `a9pwn`'s `rusb 0.9`), and device access is **Lead-only**
regardless (HANDOFF §9.1) — a second agent on one DFU device loses the session.

Everything in `plan` and `probe` is a *dry run*: it computes and prints what a live run would send,
through the same code path a live run uses (`bundle::execute_steps`), so the printed packets are
not a sketch.

## Status

| Item | State |
|---|---|
| Design | v0.2, reviewed by the Lead, dt-engineer's contract folded in |
| `cargo test --offline` | 75 pass (35 core + 40 host), 0.12 s |
| Payload build | succeeds; MEASURED 10,640 B image + 2 KiB stack = 12,688 B footprint, 16 KiB budget |
| Channel ABI | decoded from the reference and pinned by tests, including the `MEMC` data offset |
| Device tree | the six contract writes + the AUSB PHY tunables + `/reserved-memory` children, tested against the real board DTB |
| Hardware | **never touched by this crate.** No device was opened, no driver bound, no reset issued |
| Live upload | **Written and compiled, UNVERIFIED-BY-TEST**: `src/transport/live.rs`, entry point `a9boot-host probe --live`, only with `--features usb`. No test here can exercise it; device access is Lead-only |
| Blocked on | **a pwned device.** The first live checkm8 attempt failed `PAD_TIMEOUT_NOT_STALL` (a host-side abort-window bug, since fixed and re-measured); every probe-group item is downstream of that rung — `UNVERIFIED.md` §0 |

## Running the probe (Lead-only, after the first `PWND:[checkm8]`)

```powershell
# The flavour that can talk to the device. The default build cannot, on purpose.
cargo run --offline -p a9boot-host --features usb -- probe --live
```

It prints the transport, checks `CPID:8003 BDID:02 PWND:[checkm8]` **before sending anything**, then
reads the AUSB tunables and walks DRAM in 128 MiB steps. Every failure path has its own code
(`LIVE_NO_DEVICE`, `LIVE_OPEN_FAILED`, `LIVE_CLAIM_FAILED`, `LIVE_NO_SERIAL*`, `LIVE_DNLOAD_*`,
`LIVE_UPLOAD_*`), because four different problems get four different messages. Without `--live` the
same command prints the packet plan and sends nothing.
