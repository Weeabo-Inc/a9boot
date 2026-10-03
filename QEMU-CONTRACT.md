# What a9boot needs from the QEMU harness — and what it must never be asked to prove

**Audience:** `qemu-validator` (owner of the harness). **Author:** `a9boot-engineer`.
This mirrors `DESIGN.md` §9 and `UNVERIFIED.md` §D so there is one list, not three.

`a9boot` will **not** build a second harness. What follows is what I will hand you, what I need
back, and the boundary I will respect in every report I write.

## 1. What I will hand you

| Artefact | Path (after a build) | Notes |
|---|---|---|
| Payload, flat loadable image | via `a9boot-host` — `elf::flatten` on the ELF | base `0x1_8038_0110`, ~10.6 KiB, entry at offset 0. It is a bare-metal AArch64 image and needs **no** MMIO to run `PING`, `DESCRIBE` or `PREPARE` |
| Payload ELF + linker map | `target/aarch64-unknown-none-softfloat/payload/a9boot-payload` and `…/build/*/out/a9boot-payload.map` | The map is the source of the footprint numbers |
| Descriptor encoder/decoder | `a9boot_core::abi::{Descriptor,Reply,Mailbox}::{encode,decode}` (a library, not a binary) | Your test wants to *assert on bytes*, not parse source |
| Host DTB editor | `a9boot_host::bundle::edit_dtb` + `a9boot_host::fdt` | Produces the exact DTB a9boot hands the kernel, from a real `s8003-n69.dtb` |

## 2. What I need you to prove

1. **Descriptor validation, exhaustively.** `abi::Descriptor::validate()` must accept what
   `bundle::build_descriptor` produces and reject each of the failure modes with its own status
   code. I test this on the host already (`descriptor_validation_names_its_failures`); in the
   harness the value is running the *same* checks as compiled aarch64 code, where a `u64`/`usize`
   width mistake would show up.
2. **The command dispatch, with a scripted descriptor.** `PING` and `DESCRIBE` must return a
   well-formed `Reply` whose `command` echoes the request. `PREPARE` must return `OK` for a valid
   descriptor and the *named* status for each invalid one — never a silent pass.
3. **The EL1 stub's register checks, as code.** The stub reads `SCTLR_EL1`, `VBAR_EL1` and
   `TTBR0_EL1` and writes `record::EL1_STATE_UNEXPECTED` if they are not what was asked for. A
   harness that can pre-set those registers can exercise both branches — including the branch that
   matters most, the one that *refuses* to jump.
4. **The host-side DTB edit.** Run `edit_dtb` against the real `s8003-n69.dtb` and assert the four
   mandatory properties (`memory/reg`, `bootargs`, `linux,initrd-start/end`), the six framebuffer
   mode properties with `status = "disabled"`, the four AUSB PHY properties when tunables are
   supplied, and the `/reserved-memory` children — **all plain, never `no-map`**. Then re-parse and
   diff, per `LOADER-FILL.md` §9.

## 3. What it must never be asked to prove

QEMU's `virt` machine is not an A9. None of the following can come from the harness, and a
report that implies otherwise would be exactly the failure mode this project keeps paying for
(HANDOFF §9.5):

* **`SCR_EL3.FIQ` and the AIC's FIQ-routed timers** (`UNVERIFIED.md` U-3). Whether the boot-time
  value lets Non-secure EL1 see them is a property of this silicon and this ROM.
* **The EL3→EL1 transition itself** (U-4's premise): that `SCR_EL3.NS = 1` redirects EL3's EL1
  register accesses to the Non-secure bank. QEMU may or may not model it; either way, what QEMU
  does is not what an A9 does.
* **DRAM reachability from the ROM's EL3 translation** (U-1), the DFU buffer (U-2), or the
  executability of that buffer (U-14). All three are properties of the ROM and its page tables.
* **The AUSB PHY tunables** (U-13) and the gadget console (channel (c) in `DESIGN.md` §5.3).
* **The UART** (U-6) and the panel (U-7), including the question of whether either is physically
  reachable at all.

## 4. The one thing I ask you to write down

In your harness report, please state the boundary in your own words — **"a QEMU run is evidence
about our code, never about this device"** — and list which of my checks ran and which could not.
That sentence, in a document `qemu-validator` owns, is worth more than another passing test: it is
what stops a future reader from mistaking a green harness for a green phone.
