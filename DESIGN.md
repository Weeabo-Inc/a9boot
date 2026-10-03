# a9boot — pre-boot loader for Apple A9 (s8003, n69ap). DESIGN.

**Status:** v0.2. v0.1 was reviewed by the Lead (all five decisions answered, one correction
accepted — §4.5). v0.2 folds in `a9linux/dts/LOADER-FILL.md`, `CONSOLE-SIGNALS.md` and
`PLACEHOLDER-INVENTORY.md` from `dt-engineer`'s task-7, which are now part of the input contract,
and records the workspace that implements this document.
**Owner of this file:** `a9boot-engineer`. Write scope: `a9boot/` only.
**Inputs:** HANDOFF.md §4/§5/§6.4/§8.10/§8.11/§9.7; `a9pwn/docs/GASTER-SPEC.md`;
`research/refs/gaster/*` (Apache-2.0); `a9linux/src/dts-ref/*`; `a9linux/dts/*` (dt-engineer);
`a9linux/artefacts/config_16k`; `docs.kernel.org/arch/arm64/booting.html` (7.3.0-rc5).
**Forbidden input, not used:** m1n1 source (§0.5/§9.9). Nothing here is derived from it.

**Evidence labels used throughout — every number carries one:**

| Label | Means |
|---|---|
| **MEASURED** | read out of a built artefact or a live device by this session (states which) |
| **INSPECTED** | read out of source/headers/spec on disk, cited file:line |
| **INFERRED** | reasoned from the above; a falsification test exists (§12) |
| **UNVERIFIED** | not yet established by any of the three; see `UNVERIFIED.md` |

---

## 1. Scope, and what this replaces

`a9boot` is the loader that runs **after** `a9pwn` has a pwned device, and **before** Linux. It
replaces both pongoOS and m1n1 (§4 of HANDOFF): m1n1 cannot be entered cold because its own
artefacts link into someone else's VA space, so chaining to it means supplying the MMU/cache state,
boot args and device tree ourselves — which is writing the loader.

**In scope:** the host-side uploader, the on-device trampoline, the loader's DT obligations, and the
observability that makes a boot claim *measurable*.
**Out of scope:** the checkm8 exploit (`a9pwn/src/stages.rs` owns it — a9boot starts after
`PWND:[checkm8]` exists and does not duplicate or re-tune it); the kernel build
(`kernel-engineer`); the DTB source and its `LOADER-FILL` contract (`dt-engineer`); the initramfs
(`rootfs-engineer`); the QEMU harness (`qemu-validator`).

---

## 2. The two halves, and the channel between them

### 2.1 Host side

The host does every piece of work that needs RAM, allocation, or re-trying: reading blobs, planning
the layout, **editing the device tree** (§4.4), generating the boot descriptor, chunking transfers,
and reading telemetry back. The host decides all addresses before the phone is touched, and prints
them (`a9boot-host plan`) for review.

### 2.2 On-device side

The on-device payload is deliberately small, stateless and **non-resident**:

- it is delivered **inside the same control transfer as the command that invokes it**, and runs
  **in place** from the ROM's DFU buffer in SRAM;
- it therefore needs no relocation, no second bootstrapping stage, and no expectation that it
  survives the blob-streaming phase;
- Rust `no_std`, size-budgeted (§7.4), all assembly as inline `asm!` (§7.3).

Consequence: **the kernel/DTB/initramfs are streamed by the ROM's own primitives, not by our code**
(§3.3). Our payload is invoked only for `PING`, `DESCRIBE`, `PREPARE` and `GO` — a handful of times
per boot.

### 2.3 The channel (INSPECTED, `research/refs/gaster/payload_handle_checkm8_request.S`)

After PATCH, `dfu_handle_request` points at a resident 248-byte handler copied to
`payload_dest = 0x1800E0F08` (`= boot_tramp_end - 192 - 56`, HANDOFF §8.2; `gaster.c:1111`).
That handler is the channel. Decoded from the reference (this is **the** ABI a9boot must speak):

```
handler(_main, entry at payload_dest + 12):
    ldrh w2, [x0]      ; w2 = (bmRequestType) | (bRequest << 8)
    cmp  w2, #0x2A1    ; 0xA1 = class, device-to-host, interface ; 0x02 = DFU_UPLOAD
    bne  _main         ; anything else -> original ROM handler (handle_interface_request)
    ldrh w2, [x19,#2]  ; wValue
    cmp  w1, w2 ...    ; wValue must be 0xFFFF  (LD 0xFFFF first, compare)
```

So: **command input = a `DFU_DNLOAD` (bmRequestType `0x21`, bRequest `0x01`) to the ROM, followed by
a `DFU_UPLOAD` (`0xA1`, `0x02`, `wValue = 0xFFFF`)** — exactly `gaster_command()`
(`gaster.c:1477-1493`). The DNLOAD data lands at the ROM's DFU buffer,
`insecure_memory_base = 0x1_8038_0000`. **Two independent sources agree on that address**: this
decode (**INSPECTED**, `a9pwn/src/config.rs` ← `gaster.c:637`) and the Lead's **MEASURED**
`a9pwn plan` against the live device, which prints `insecure_memory_base = 0x180380000` for CPID
`0x8003`. Agreement with an independent measurement is worth recording, because this address is
where every byte of the loader passes through. The UPLOAD then:

| Offset in buffer | Field | Meaning |
|---|---|---|
| `+0x00` | `magic` | `EXEC_MAGIC = 0x6578656365786563` ("execexec") → call; `MEMC_MAGIC = 0x6D656D636D656D63` ("memcmemc") → memcpy (`gaster.c:49-51`) |
| `+0x08` | `func` | `blr x8` target (EXEC), or unused (MEMC) |
| `+0x10..0x50` | `x0..x7` | argument registers, `x7` overlapping the first 8 bytes of appended data |
| `+0x48..` | payload data | appended **after** the 72-byte header (`gaster.c:1518-1521`) |
| reply | buffer again | handler then does `stp done_magic, x0, [buffer]` and sends `wLength` bytes from the buffer back: `[0]=DONE_MAGIC`, `[8]=return value`, `[0x10..]` = whatever the callee wrote there |

Two consequences that shape a9boot:

1. **`x7` is the first 8 bytes of the appended data, not a free argument.** a9boot passes
   `x0 = command`, `x1 = descriptor PA`, `x2 = reply PA`, and never needs `x3..x7`.
2. **The reply buffer is the same buffer the command arrived in.** Any command can therefore return
   structured telemetry in the very same UPLOAD round trip. That is the observability primitive in
   §5 and it costs no extra device-side code.

`memcpy_addr = 0x1_0001_1030` (ROM, **INSPECTED** `a9pwn/src/config.rs` ← `gaster.c:629`) is callable
through `MEMC_MAGIC`, giving the host a 3-argument (dst, src, len) read/write primitive over
everything the ROM's EL3 translation reaches. **This is the whole upload mechanism** and it is
already proven on this hardware: it is how the exploit payload itself is placed.

### 2.4 The five host-side channel operations

| Op | DNLOAD contents | UPLOAD | Used for |
|---|---|---|---|
| `mem_write(dst, src, len)` | `MEMC` header, len = payload len, dst/src set, data appended | 16 B | fill DRAM |
| `mem_read(dst, src, len)` | `MEMC` header with dst = `buffer+0x10`, src = address to read | `16+len` | read DRAM back (verification, mailbox, probe) |
| `exec(func, args)` | `EXEC` header | `16+reply` | invoke the a9boot payload |
| `probe(len)` | `MEMC` header + `len` bytes of pattern | `16+len` | establish the DFU buffer's usable capacity (§3.4) |
| `ident()` | none | 16 B | confirm the device is still the pwned A9 (serial contains `PWND:[checkm8]`) |

Every op is a pure function from a byte vector to a byte vector, implemented in
`a9boot-host::channel` and unit-tested against the offsets above. **No hardware is needed to test
them**; `MockTransport` replays a recorded command/response log.

---

## 3. Physical layout

### 3.1 The A9 physical map (INSPECTED)

| Range | What | Source |
|---|---|---|
| `0x0_8000_0000` – `0x0_8800_0000` | **DRAM**, 2 GiB. Note the base is 34-bit. | `s800-0-3-common.dtsi:33-36` node name `memory@800000000` with `#address-cells = <2>`; and `s800-0-3.dtsi:138` `dma-ranges = <0x0 0x00000000 0x8 0x00000000 0x1 0x00000000>` — the USB complex's 32-bit view of `0x0_00000000` is physical `0x8_00000000` |
| `0x1_0000_0000` | boot ROM (VROM); `memcpy` at `+0x11030`, patch site at `+0x812C` | `a9pwn/src/config.rs` ← `gaster.c:627-629` |
| `0x1_8000_0000` – `~0x1_8040_0000` | SRAM: ROM heap/trampoline (`boot_tramp_end = 0x1_800E_1000`), resident handler, `ttbr0_addr = 0x1_800C_8000`, DFU buffer `0x1_8038_0000` | `a9pwn/src/config.rs`; `GASTER-SPEC.md` §4.3 |
| `0x2_0000_0000` + | peripherals: AIC `0x2_0E10_0000`, WDT `0x2_102B_0000`, UART0 `0x2_0A0C_0000`, PMGR `0x2_0E00_0000` | `s800-0-3.dtsi` |

`DRAM_BASE = 0x8_0000_0000` (not `0x8000_0000`) is the single most error-prone number in this
document — HANDOFF §8 exists because of that class of mistake, so it is asserted in
`a9boot-core::layout` and checked by test.

**DRAM size 2 GiB is INFERRED** (iPhone SE 1st gen 2 GB RAM; `a9linux/briefs/*`). The kernel is told
what we put in the DT's `memory` node, and rung-1 operation *measures* it (§3.5).

### 3.2 The layout (host-computed; `a9boot-host plan` prints it; `a9boot-core::layout` holds it)

```
                        PA range                        size      purpose                          reserved
 0x8_0000_0000  DTB ............... 0x8_0020_0000      2 MiB     FDT, own 2 MiB region            memreserve
 0x8_0020_0000  Image 2 MiB base .. +text_offset+image_size      arm64 Image (header-driven)      kernel's own
                     (text_offset read from the Image header, never hardcoded)
                initramfs ......... align_up(image_end, 64K)     initrd                           memreserve
 0x8_7800_0000  FB ................ 0x8_7C00_0000      4 MiB     simple-framebuffer               memreserve (rung 2)
 0x8_7FE0_0000  LOADER ............ 0x8_8000_0000      2 MiB     loader area, always reserved     memreserve
                 +0x0_0000  payload staging (8 KiB, only in DRAM-resident fallback)
                 +0x1_0000  boot descriptor (4 KiB)
                 +0x1_1000  telemetry mailbox (4 KiB)
                 +0x2_0000  EL1 vector table (2 KiB aligned)
                 +0x2_8000  EL1 scratch stack (16 KiB; SP_EL1 = top)
                 +0x3_0000  cpu-release-addr mailbox (naturally aligned 64-bit, zeroed)
 0x1_8038_0000  DFU buffer (SRAM, ROM-owned)           ≥8 KiB   command staging                  n/a - not in DRAM
```

Invariants, checked by `a9boot-core::plan` and asserted by test:

1. Every blob is inside `[DRAM_BASE, DRAM_BASE + 0x4000_0000)` — the first 1 GiB-aligned window —
   because booting.rst requires an initrd to lie "entirely within a 1 GB aligned physical memory
   window of up to 32 GB in size that fully covers the kernel Image as well". With 2 GiB of RAM
   there are exactly two such windows; the plan refuses to straddle them.
2. The DTB sits in its own 2 MiB region, not shared with the Image: booting.rst requires that the
   DTB "must not be placed within any 2M region which must be mapped with any specific attributes".
3. `Image` is placed at `2 MiB aligned base + text_offset`, `text_offset` **read from the Image
   header** (`a9boot-core::image`), never assumed to be `0x80000`.
4. Nothing overlaps the ROM's SRAM, the resident handler at `0x1_800E_0F08..0x1_800E_1000`, or the
   DFU buffer.
5. Every region the kernel must not allocate is in the FDT memory-reservation block (§4.4).

**Why these ranges are safe.** DRAM above the kernel's own reservation is otherwise free memory that
the kernel's allocator would happily use; the loader therefore *removes* it from circulation by
memreserve rather than hoping. The DFU buffer is in SRAM, i.e. **outside the `memory` node**, so
post-handoff DFU traffic cannot corrupt kernel RAM (§5.3). The loader area is at the very top of
DRAM, so the framebuffer and the kernel cannot collide with it.

### 3.3 Streaming, and the transfer budget

There are **two different limits**, and conflating them is how a plan becomes unimplementable:

| Limit | Value | Why |
|---|---|---|
| One control transfer | `DNLOAD_CHUNK` = 0x800 | one EP0-sized transfer; the reference's proven unit. A command larger than this becomes several consecutive transfers, which the ROM accumulates into its buffer |
| One command | the DFU buffer's capacity (`ASSUMED_BUFFER_CAPACITY` = 16 KiB until the capacity probe measures it) | a command that overruns the buffer is **corruption, not a stall**, so `TransferBudget::check` refuses it by name |

`TransferBudget::data_per_command()` is therefore `min(capacity - 0x48, 0x800)` = 2048 bytes by
default, and the host streams `Image`, DTB and initramfs through `mem_write` commands of that size,
**verifying each chunk by reading it back before advancing**. A chunked write's commands are
contiguous and cover the blob exactly once, and both properties are asserted by test.

This is what the first dry run caught: with no budget, the plan emitted the 2.6 MiB initramfs as a
*single* packet. The printed size was the evidence, and `no_packet_exceeds_the_channel_budget` plus
`a_large_blob_is_chunked_into_transfer_sized_commands` are the regression tests.

### 3.4 Buffer capacity, and why we do not guess it

Apple's DFU ROM accumulates successive `DNLOAD`s into its buffer (that is how a multi-hundred-KB
iBSS arrives in stock DFU, **INFERRED**), but the buffer's **size is UNVERIFIED**. Rather than
assume, `a9boot-host probe` writes a pattern of `N` bytes, reads it back, and compares, for
`N = 0x800, 0x1000, 0x2000, ...`, stopping at the first failure. It is safe because it only ever
*reads* DRAM and writes inside the buffer region. The established value is printed and recorded as a
command-line parameter; if it is below the payload's size requirement, the host **refuses with a
named error** instead of proceeding.

### 3.5 Measuring instead of believing — the one procedure

`a9boot-host probe` is the **unified post-pwn experiment**: the same steps as dt-engineer's
register sequence, implemented once (`bundle::probe_steps` / `bundle::run_probe`) so there is one
procedure rather than two. It uses only the ROM's own primitives, so it can run the moment the
first `PWND:[checkm8]` appears — before any loader code exists.

| Probe | Method | Settles |
|---|---|---|
| DRAM writable from EL3 | `mem_write` a 32-byte pattern to each of 17 addresses from `DRAM_BASE` upward in 128 MiB steps, `mem_read` back, compare | **U-1** (does the ROM's EL3 map cover DRAM at all) and **U-5** (the real extent, so the declared size is measured rather than assumed) |
| AUSB PHY tunables | one `mem_read` of 8 bytes at `0x2_0C000038` | **U-13**, which gates the USB gadget console |
| Buffer capacity | write/read back 2 KiB, 4 KiB, 8 KiB, 16 KiB … and stop at the first failure | **U-2**, the payload's delivery budget |
| Device is ours | identity: `CPID 0x8003`, `BDID 0x02`, serial contains `PWND:[checkm8]` | any wrong-device run |

Failure at the **first** address is not a small failure: it means DRAM is unreachable through the
ROM's EL3 translation, nothing can be staged, and the design stops at PLAN B (§11.1). The probe
therefore runs first and refuses by name, rather than discovering this halfway through a 16 MiB
kernel upload.

`Probe::dram_extent()` reports what to *declare*: the last address that round-tripped, rounded
down to 128 MiB. Over-declaring hands the kernel dead pages and corrupts rather than panics
(`LOADER-FILL.md` §2), so the declared size is a measurement — or, until the probe runs, the
nominal 2 GiB marked INFERRED. **No smaller "safe" number is invented**: a wrong small size
silently halves the machine.

---

## 4. The boot contract

### 4.1 What the host uploads

| Blob | Form | Notes |
|---|---|---|
| Kernel | **plain `Image`** | booting.rst §3: "The AArch64 kernel does not currently provide a decompressor" — decompression is the loader's job, so a9boot consumes an uncompressed `Image` and **refuses `Image.gz` by name** rather than mis-parsing it. `CONFIG_EFI_ZBOOT=y` means the build's default target may be `vmlinuz.efi`; `kernel-engineer` should emit plain `Image` as well (one `gunzip -c` in the VM). The 64-byte header is parsed and validated: magic `0x644d5241` ("ARM\x64"), flags bits 1-2 = `2` (16K), bit 0 = 0 (LE), and `image_size` must equal the file length — a truncated image is refused on the host, not discovered on the device. `text_offset` is read from the header and never assumed. |
| DTB | `dt-engineer`'s source DTB, **edited on the host** | §4.4 |
| initramfs | `initramfs.gz` | Passed as an initrd (not unpacked by us): the kernel unpacks it. |
| Descriptor | generated | §7.2 |
| Payload | `a9boot-payload` (ELF) | The host flattens the ELF itself (`a9boot-host::elf`) and verifies `entry == payload_exec_addr()` and the footprint. §7 |

### 4.2 What the on-device trampoline must do before jumping

booting.rst ("Before jumping into the kernel, the following conditions must be met") requires all of
this; each row names where a9boot does it.

| Requirement (booting.rst) | a9boot action | Where |
|---|---|---|
| `x0` = DTB physical address; `x1 = x2 = x3 = 0` | set in the final asm | `payload/src/el.rs` |
| All of DAIF masked | `msr daifset, #0xf` | `el.rs` |
| **CPU in non-secure state, EL1** (A9 has **no EL2** — HANDOFF §8.10, `s800-0-3.dtsi:299`) | see §4.3 | `el.rs` |
| **MMU off** | `SCTLR_EL1 = RES1 bits only` (see correction §4.5) | `el.rs` |
| D-cache off; the loaded image cleaned to PoC | `dc cvac` over Image, DTB, initramfs, descriptor, then `dsb sy` | `el.rs` |
| I-cache must hold no stale entries for the image | `ic ialluis` + `isb` | `el.rs` |
| `CNTFRQ` programmed, `CNTVOFF` consistent on all CPUs | read `CNTFRQ_EL0`; if 0, program 24 MHz (`clkref`, `s800-0-3.dtsi:21-26`); report the value read | `el.rs` |
| All writable sysregs at/below entry EL initialised | `TTBR0_EL1`, `TTBR1_EL1`, `TCR_EL1`, `MAIR_EL1`, `VBAR_EL1`, `CPACR_EL1` written to known values | `el.rs` |
| `SCR_EL3.FIQ` same on all CPUs and **same as at boot time** | read, preserve, never write that bit | `el.rs` |
| **A usable stack at the entry EL** (not in booting.rst; `stext` does `bl preserve_boot_args` before it installs its own) | `SP_EL1` = top of the loader-area scratch stack; `SPSR_EL3.M[0] = 1` (EL1h) | `el.rs` |
| Parked CPUs: `cpu-release-addr` = naturally-aligned 64-bit zero-initialised location **inside a reserved region**; poll with `wfe`, jump on non-zero, secondaries enter with `x0..x3 = 0` | rung 1: **not implemented** (§9); the loader area already reserves the mailbox address | `plan`, `el.rs` |

### 4.3 The EL question — where we land, and how we get to EL1

**Where the payload runs: EL3, AArch64, with the ROM's MMU on.** Evidence (**INSPECTED**):
`payload_A9.S:64` executes `tlbi alle3`, and `:59-62` toggles AP bits in the page-table entry at
`ttbr0_vrom_addr = 0x1_800C_8400`. Both are only meaningful at EL3. So we arrive in the same
translation regime as the ROM's own `memcpy` — which is why §3.5's DRAM probe answers a question
about *our* code as well.

That is also the trap: **we need Linux at non-secure EL1, and the EL1 system registers are banked by
security state.** Writing `TTBR0_EL1`/`SCTLR_EL1`/`TCR_EL1` while `SCR_EL3.NS = 0` writes the
*secure* copies; after setting `NS = 1` the CPU uses the *non-secure* copies. The order is therefore
load-bearing:

```
 1. daifset #0xf                     ; mask everything
 2. read SCR_EL3                     ; remember it; never touch SCFG/FIQ bits
 3. write SCR_EL3.NS = 1             ; from here, EL1 sysregs are the NON-SECURE bank
 4. write the EL1 registers (SCTLR_EL1/TTBR0_EL1/TCR_EL1/MAIR_EL1/VBAR_EL1/CPACR_EL1/SP_EL1)
 5. CNTFRQ_EL0 check
 6. dc cvac over the loaded ranges; ic ialluis; dsb sy; isb
 7. SPSR_EL3 = EL1h + DAIF masked (0x3C5); ELR_EL3 = Image entry PA
 8. x0 = DTB PA; x1 = x2 = x3 = 0
 9. eret
```

`SCR_EL3.FIQ` is **read and preserved**: booting.rst requires it to equal the boot-time value on
every CPU. Whether that boot-time value actually lets Linux's FIQ-routed arch-timer interrupts reach
EL1 is a platform question we must not guess — the A9 DT routes the timers as `AIC_FIQ`
(`s800-0-3.dtsi:295-302`). The payload therefore **reports `SCR_EL3`, `CurrentEL`, `SCTLR_EL3`,
`TTBR0_EL3`, `TCR_EL3`, `CPTR_EL3`, `MIDR_EL1` and `MPIDR_EL1` to the host before anything else**
(`DESCRIBE`), and that report is the input to the decision. `UNVERIFIED.md` item U-3.

### 4.4 Device-tree obligations (the placeholder set is the spec)

`a9linux/dts/LOADER-FILL.md` §3/§7/§10 is the frozen contract. `a9boot-host::bundle::edit_dtb`
implements it, and the tests assert each write against the real board DTB when it is present.

| # | Node / property | Filled with | Why |
|---|---|---|---|
| 1 | `/memory@800000000` `reg` | `<0x08 0x00000000 0x00 0x80000000>` | MEASURED by the Lead and `kernel-engineer`: the built DTB ships `reg = <0x08 0x00 0x00 0x00>`, i.e. **size 0**. Without this the kernel has no RAM. 4 cells, because the root is `#address-cells = <2>`/`#size-cells = <2>` |
| 2 | `/chosen/bootargs` | **injected** (the property does not exist) | `CONFIG_CMDLINE=""` and no fallback: `LOADER-FILL.md` §4's string, verbatim. `earlycon`, `console=ttySAC0` with **no `,baud`**, `keep_bootcon`, `ignore_loglevel`, `initcall_debug`, `clk_ignore_unused`, `pd_ignore_unused` |
| 3–4 | `/chosen` `linux,initrd-start` / `-end` | **written unconditionally**: the real start and the real byte count staged, or explicit `<0 0>` when there is no initramfs. **2 cells each** (one u64) | `BLK_DEV_INITRD=y`. Four cells would silently truncate the address to its low half. The **size must come from the transfer this host performed**, never from a table: qemu-validator measured the reference template's implied size at 2,670,592 B while rootfs-engineer's real Debian initramfs is 7,503,864 B — the kernel would unpack the first 2.67 MB of a 7.5 MB archive and die with a `VFS` error that reads like a rootfs bug. The `linux,` prefix is load-bearing too: without it the kernel ignores the property entirely and panics with `VFS: Cannot open root device` |
| 5 | `/chosen/framebuffer@0` `reg`, `width`, `height`, `stride`, `format` | `0x8_7800_0000`/4 MiB, `640`, `1136`, `2560`, `a8r8g8b8` | Mode information. `simpledrm.c:674-686` errors out on any missing one |
| 5b | …`status` | **`"disabled"` unless a display module actually lit the panel** | The binding's own assumption is "the display hardware has already been set up to scan out from the memory pointed to by the reg property" (`simple-framebuffer.yaml:12-17`). Filling this while the panel is dark is the blank-screen-instead-of-error failure. Rung 1 leaves it disabled; see §5.2 and §6 |
| 6 | `/soc/bus@20c000000/phy@20c000030` `apple,cfg0-device`, `cfg1-device`, `cfg0-host`, `cfg1-host` | **readbacks** of `0x2_0C000038` and `0x2_0C00003C` (device pair), mirrored for the host pair | `ausb.c:149-156` returns `-ENODEV` unless all four are present, so **on the current DTB the PHY never registers, dwc2 defers forever and USB is dead** — which is what makes the gadget console of §5.1 impossible. The device values are not guesses: the SecureROM programmed that PHY, because that is how DFU is talking to us. Found by `dt-engineer` (§7 of their contract), and it is the placeholder that unblocks the only remaining human-readable channel |
| 7 | `/reserved-memory` children | `loader@87fe00000`, `framebuffer@878000000`, `dtb@800000000`, `initramfs@…` — all **plain, never `no-map`** | The DTS ships an empty `reserved-memory` node marked `/* To be filled by loader */`, so children are the contract's mechanism. `no-map` is refused on purpose: the kernel must read the DTB and the initrd, and in rung 2 it must be able to **write** the spin-table mailbox inside the loader area |
| — | `/cpus/cpu@0..1` `cpu-release-addr` | **written unconditionally**: `<0 0>` in rung 1, the real mailbox in rung 2 | `smp_spin_table.c:71-72` returns `-ENODEV` when it is zero and `smp.c:810-818` skips the CPU: one core, no hang, no warning storm. A *wrong* non-zero value is a wild write into low memory plus a hung CPU1 — so rung 1 writes zero **over** whatever the template said rather than trusting it |

**The hand-off assertion (`bundle::handoff_contract`).** Both of the values above are dangerous as
template constants, so the loader re-reads its own finished tree and proves it agrees with the
transfer it planned: the initrd pair must equal the address and the **byte count of the write step
that stages it** (derived from the step sequence, not from a file length), `cpu-release-addr` must
be the value this rung intends, `memory/reg` must be the plan's size, the un-prefixed
`initrd-start`/`initrd-end` names must be **absent**, and no blob may sit inside the kernel image's
span — `__primary_switched` zeroes the image's bss before `setup_arch` reads the tree, so a blob
there is total silence with no output anywhere (qemu-validator's first stub map did exactly that).
It runs **inside `build_steps`**, so a dry run and a live run refuse identically, and an initramfs
the plan expects but no step stages is the named refusal `HANDOFF_INITRD_SIZE_UNKNOWN` rather than
a guess. `plan` prints the asserted contract, so one dry run validates both the memory layout and
the DT hand-off.

Two further cross-checks the host performs, because a half-applied contract is worse than none: the
command line and the AUSB tunables must agree about `console=ttyGS0` (a token with no PHY tunables
waits forever for a gadget that cannot bind; tunables with no token leave the console unread), and
the edited DTB is **re-parsed** and its `memory` node re-read before it is allowed near the device.

Editing happens **host-side** (`a9boot-host::fdt`: parse → owned tree → serialise with padding).
That is not an implementation detail: it is what lets the final DTB — and therefore every value the
kernel will be handed — be printed, diffed and reviewed before hardware is touched, and it removes
the resize/slack arithmetic that makes an in-place FDT patcher go wrong quietly. `LOADER-FILL.md`
§9 gives the verification recipe (`dtc` round-trip and diff); the expected diff against the
*minimum* target DTB is four properties, and a9boot's output differs from that only by the
reservations and the AUSB properties it additionally owns.

### 4.5 Correction to the task text (do not silently comply)

Task-8 says the trampoline must provide "*MMU on with 16K granule page tables*" before jumping to
the kernel. **That is the opposite of what the kernel wants.** booting.rst is unambiguous:
"**The MMU must be off.**" and "The instruction cache may be on or off … The address range
corresponding to the loaded kernel image must be cleaned to the PoC." The kernel builds its own
16K-granule tables in `__create_page_tables`/`__enable_mmu` and enables the MMU itself.

The 16K granule still matters, in three places: it is a property of the kernel we build
(`CONFIG_ARM64_16K_PAGES=y`, `a9linux/artefacts/config_16k`), it fixes the DTB's 2 MiB block rule
(§3.2 invariant 2), and it is the granule of the ROM's `TTBR0_EL3` (`gaster.c:47`
`ARM_16K_TT_L2_SZ = 0x2000000`) — which matters only in PLAN B (§11.4), where any replacement table
must keep that granule and keep every existing mapping, because the USB stack we depend on lives in
those mappings.

**a9boot therefore provides no page tables for the kernel.** It provides a clean, known EL1 state
with the MMU off. The Lead reviewed this and **accepted the correction**: the original wording
conflated m1n1's requirement (an OS that must be entered in a VA space that already exists, hence
HANDOFF §4's `vmaddr` problem) with Linux's (a kernel that maps itself from a clean EL1 state).
What the task text asked for is recorded here as *wrong*, deliberately, so that it is not
"rediscovered" later.

---

## 5. Observability — how we know Linux is running

This is a first-class requirement (Lead, in-session), and the honest answer changed once
`dt-engineer`'s `CONSOLE-SIGNALS.md` landed: **the UART is probably unreachable**, and the channel
that replaces it is a USB gadget console over the cable that is already plugged in. Five channels
are therefore specified, in the order they become available. The one that matters most is (c),
because it is the first one that can show *kernel* messages.

### 5.1 Channel (a): the same-round-trip reply — MEASURED, and the only channel with no unknowns

Every a9boot command returns telemetry in the same `DFU_UPLOAD` that triggers it (§2.4). This is
not an inference: it is the platform's own reply path, and it is exercised offline against the
channel simulator in
`bundle::tests::the_full_sequence_runs_against_the_simulator_and_verifies_every_write`.

Consequence: **"the loader reached `eret`" is a measured fact.** The `DESCRIBE` reply carries
`CurrentEL`, `SCR_EL3`, `SCTLR_EL3`, `TTBR0_EL3`, `TCR_EL3`, `CPTR_EL3`, `MIDR_EL1`, `MPIDR_EL1`,
`CNTFRQ_EL0` and `SCTLR_EL1`, so the claims in §4.3 are answered with data (U-3, U-4) instead of
being trusted, and every staged chunk is read back and compared before the next one is sent.

### 5.2 Channel (b): the `VBAR_EL1` fault mailbox — the design's best idea, made first-class

Before `eret`, the payload copies a 2 KiB `VBAR_EL1` vector block plus its handler into the
reserved loader area. Every one of the sixteen entries branches to a handler that stores
`ESR_EL1`, `FAR_EL1`, `ELR_EL1` and `SPSR_EL1` into the mailbox at `0x8_7FE1_1000`, writes the
mailbox magic, and parks. `GO` also writes a `HANDOFF` record **immediately before** `eret`.

So a boot that dies between `eret` and the first console line is not silent: it is a named cause.
"A blank device" becomes one of a small set of distinguishable outcomes —

| Mailbox content | Meaning |
|---|---|
| `HANDOFF`, no fault | The loader handed off. Anything after this is the kernel's business |
| `EL1_FAULT` + `ESR_EL1` | The kernel took a synchronous exception at EL1, with the faulting address and the return address recorded |
| `EL1_STATE_UNEXPECTED` | The EL1 registers are not what EL3 wrote, i.e. U-4's banked-register premise is false. **This is the design's riskiest architectural assumption, tested on the device rather than trusted** |
| `PAYLOAD_PANIC` + a line/column | A Rust panic in the payload, with its location |
| Magic is zero | The payload never wrote anything: it never ran, or it faulted before the write |

The host reads it back through the still-resident EL3 handler
(`mem_read(MAILBOX_ADDR) → DFU_UPLOAD`). That is safe with respect to the kernel for a specific,
checkable reason: **the DFU buffer is in SRAM (`0x1_8038_0000`), outside the memory node the
kernel is given, and the operation is read-only with respect to DRAM.** `layout::check()` asserts
that separation. It is nevertheless *best effort* for two honest reasons: setting `SCR_EL3.NS = 1`
may change how the USB controller's DMA is attributed (U-9), and the kernel's `dwc2` driver will
eventually reset the controller and end the channel (U-10). Its value is the window between
handoff and that probe — which is exactly where a boot currently goes dark.

### 5.3 Channel (c): the USB gadget console — the primary human-readable channel

`console=ttyGS0`: the kernel drives the device's own USB controller as a CDC-ACM gadget and the
host sees `/dev/ttyACM0` on the cable it already has. Everything on the kernel side is already
enabled (`CONFIG_USB_GADGET`, `CONFIG_USB_DWC2_DUAL_ROLE`, `CONFIG_USB_CONFIGFS`,
`CONFIG_USB_CONFIGFS_ACM`, `CONFIG_USB_CONFIGFS_SERIAL`, and `apple,dwc2` matching
`dwc2/params.c:369`).

**It is blocked by one loader placeholder, and a9boot is what unblocks it**: the AUSB PHY tunables
(§4.4 row 6). Without them the PHY returns `-ENODEV`, dwc2 defers forever, and USB is dead even
though the DT says `dr_mode = "peripheral"`. With them, `console=ttyGS0` gives the first channel
that can print a kernel boot log — `earlycon` and `initcall_debug` cannot, because on this path
nothing else is watching.

The two `console=` tokens coexist deliberately: Linux registers both consoles and `/dev/console` is
the last one named, so appending `ttyGS0` *adds* a channel rather than replacing the UART one. The
host refuses a plan where the token and the tunables disagree (§4.4).

**Dependency on another workstream, stated plainly:** `console=ttyGS0` needs something in the
initramfs to bind the gadget (configfs + `acm`), or the console device never appears. That is
`rootfs-engineer`'s side of this contract, and it is the *only* part of channel (c) that a9boot
does not own.

### 5.4 Channel (d): the UART — kept, and not depended on

`dt-engineer` establishes (INFERRED, high confidence, from the Lightning pinout) that the debug
UART is **not reachable through the connector**: eight pins, no TX/RX. Board test points are
UNKNOWN, and a DCSD-class cable only works in a mode **iBoot** enables — which never runs on this
path. So the UART is an upside, not a dependency.

The loader obligations stay in the code (the DT contract's bootargs, and the clock/pinmux
obligations of `LOADER-FILL.md` §6), because they are cheap and because a byte on
`0x2_0A0C_0000` is falsifiable. But **nothing in rung 1 is allowed to depend on the UART**, and
the bootargs carry no forced baud — `s3c24xx_serial_get_options()` reads `UBRDIV` back and cancels
the loader's baud error, so forcing one would only risk trusting the DT's `clkref` instead.

### 5.5 Channel (e): the panel — rung 2, not a rung-1 signal

The display pipeline is a loader obligation with no driver behind it: `CONSOLE-SIGNALS.md` Q2
establishes that no mainline driver matches an A9 display controller and that the A9 device tree
contains **no display controller node at all**, so nothing in the kernel can initialise MIPI DSI,
the panel power rails or the panel init sequence. `simple-framebuffer` is a *consumer* by
definition. One genuine mercy: the backlight is Linux's job (`apple,dwi-bl` is already
`status = "okay"`, `CONFIG_BACKLIGHT_APPLE_DWI=y`), so the loader needs the pipeline, not the lamp.

**Constraint, adopted from the Lead's review — a constraint, not a plan:** rung 1 does **not**
initialise the display, and `framebuffer@0` stays `status = "disabled"`. a9boot never claims a
panel it did not light, because a framebuffer node that says `okay` while the screen is dark
produces a blank screen instead of an error. The six mode properties are filled anyway, so that a
display module has a socket to plug into and so that rung 1 and rung 2 produce the *same* plan
apart from one flag.

### 5.6 Host-side USB state, and its honest limit

Three distinguishable bus states: still enumerated as `05AC:1227` with `PWND:[checkm8]`; gone from
the bus; re-enumerated as something else. The middle two prove that *someone* reset the controller
— i.e. the kernel reached a driver probe — and **not** that Linux is running. A watchdog reset
looks the same, which is why this is a supporting signal and never the headline.

### 5.7 The honest ceiling, re-stated

Without channel (c) or (d), **there is no channel that shows kernel messages.** The mailbox can say
that the kernel took a specific fault; it cannot say that `start_kernel` was reached, that the
initramfs mounted, or that the AIC was found. Any "Linux boots" claim made in that state would be
an inference from the absence of a fault — precisely the plausible-looking claim HANDOFF §9.5
forbids.

**Rung-1 success is therefore: "the loader handed off cleanly, the mailbox shows no fault, and the
USB bus moved to a named state" — which is a weaker claim than "Linux runs", and will be reported
as exactly that.** If channel (c) lands, the claim strengthens to "the kernel printed its boot log
over the cable", and that will be quoted, not paraphrased.

### 5.8 Evidence ledger (each rung, its signal, its falsifier)

| Rung | Claim | Signal | Falsifier |
|---|---|---|---|
| R0 | ROM primitives reach DRAM, and the AUSB tunables are readable | the probe's write/read round trip and the two register reads (§3.5) | a mismatch → PLAN B; zero tunables → no gadget console |
| R1 | Every blob was staged correctly | per-chunk read-back compare | any mismatch → abort with the offset |
| R2 | The loader reached the point of no return | `GO` reply **and** a `HANDOFF` record in the mailbox | no reply → payload fault; no record → it died before the write |
| R3 | The kernel took control at EL1 | mailbox quiet (no `EL1_FAULT`) **and** a named USB transition | `ESR_EL1` recorded → named fault; nothing at all → nothing proven |
| R4 | Linux is running | **channel (c) output** (`ttyGS0`), quoted | — |
| R5 | Userland | initramfs output on the same channel | — |

## 6. Rung 1 vs rung 2 (scope decision)

**Rung 1 (this design, the first hardware target): single CPU, USB gadget console as the primary
channel, no display.**
- `cpu-release-addr` is left at `<0 0>`, so the kernel skips cpu1 cleanly
  (`smp_spin_table.c:71-72` + `smp.c:810-818`, INSPECTED). `maxcpus=` is deliberately *not* passed:
  the guard is the mechanism, and a redundant parameter would hide it if the guard ever changed.
- The AUSB PHY tunables are filled from the probe, so `console=ttyGS0` has a chance of becoming the
  first channel that can print a kernel log (§5.3). If the probe returns nothing usable, the
  tunables are omitted and the bootargs keep the contract string without the `ttyGS0` token — the
  host refuses the half-configured combination (§4.4).
- No display init; `framebuffer@0` stays `disabled` (§5.5).
- Success = §5.8 R0–R3, and R4 if the gadget binds.

**Rung 2:** dual CPU via `spin-table` (`cpu-release-addr = 0x8_7FE3_0000`, with the A9 PMGR CPU1
power-on and reset release — **the reverse-engineering work** — plus a `wfe` polling stub in the
loader area), and the display bring-up of §5.5 as its own task. Both are additive: the layout does
not move between rungs, on purpose, so that a rung-2 change cannot invalidate a rung-1 measurement.

---

## 7. The Rust workspace

```
a9boot/
  Cargo.toml                    workspace; default-members = core + host
  crates/a9boot-core/           no_std, no deps. layout, Image header, ABI, plan. Tested on host.
  crates/a9boot-host/           std. fdt editor, channel codec, transport trait, plan/CLI.
  crates/a9boot-payload/        no_std aarch64 bin. entry + sysregs + eret. size-budgeted.
```

### 7.1 `a9boot-core` (shared truth, no_std)

`layout` (every address in §3.2 as a `const`, with the `0x8_0000_0000` assertion and the window
invariants), `image` (arm64 Image header parse + validate), `abi` (command codes, descriptor and
mailbox byte layouts, status codes), `plan` (given blob sizes → addresses + memreserve list +
bootargs), `cache` (line-size-aware range walk). Everything here is pure and unit-tested on the
host, so the payload that *uses* it is thin.

### 7.2 `a9boot-host`

- `fdt`: parse → owned tree → edit → serialise (with padding). Adds `/chosen/bootargs`,
  `linux,initrd-start/end`, the memreserve entries, and the filled placeholders of §4.4.
- `channel`: the byte-exact codec of §2.3 (`EXEC`/`MEMC` headers, 72-byte header, `x7` overlap,
  reply parse).
- `transport`: `trait PwnedTransport` + `MockTransport` (replays a log). The live implementation is
  behind a non-default `rusb` feature (§11.3) — **not enabled by default, never exercised by me.**
- CLI: `selftest` (offline checks), `plan --image --dtb --initramfs` (prints the full layout, the
  DTB diff, and every byte of every command, sending nothing), `probe --dry-run`, and (feature
  gated) the live paths the **Lead** runs.

### 7.3 Assembly policy

There are **no `.S` files.** Everything uses inline `asm!` in Rust, and only where the architecture
leaves no alternative — because there is no Rust intrinsic for a system register, for cache
maintenance, or for an exception return, and `eret` cannot be expressed at all:

| Site | Why it must be asm |
|---|---|
| `mrs`/`msr` of `SCR_EL3`, `SCTLR_EL1`, `TTBR0_EL1`, `TCR_EL1`, `MAIR_EL1`, `VBAR_EL1`, `CPACR_EL1`, `SPSR_EL3`, `ELR_EL3`, `CNTFRQ_EL0`, `SP_EL1` | no intrinsic; `CurrentEL`/`DAIF` read-modify-write |
| `dc cvac`, `ic ialluis`, `dsb sy`, `isb`, `tlbi` | cache/TLB maintenance has no intrinsic, and getting it wrong is silent |
| `eret` | not expressible; also the only instruction that performs the EL change |

The `eret` block is `asm!` with `options(noreturn)`, with the register/`SPSR` contract written out
in comments at the site.

### 7.4 Target story, and what it took to build

- **Host: `x86_64-pc-windows-msvc`, Rust 2021, no new dependencies.** `cargo test` at the workspace
  root builds `a9boot-core` + `a9boot-host` (they are `default-members`) and runs **75 tests**,
  including the DTB round-trip against the real board DTB when it is present.
- **Payload: `aarch64-unknown-none-softfloat`.** Soft-float on purpose: the payload may run with
  FP/SIMD trapped (`CPTR_EL3.TFP` is the ROM's business), nothing in it uses floating point, and the
  soft-float ABI keeps the compiler from emitting FP/SIMD for structure copies.
  `--profile payload` (`opt-level = "z"`, LTO, `panic = "abort"`, strip) — `panic` and `lto` can only
  be set at the workspace root, which is why the profile lives in `a9boot/Cargo.toml`.
  ```
  cargo build -p a9boot-payload --profile payload --target aarch64-unknown-none-softfloat
  ```
  The target was installed with the Lead's approval (`rustup target add …`); a target is toolchain,
  not a dependency. **MEASURED footprint: 10,640 bytes of image + 2 KiB stack = 12,688 bytes**, from
  `a9boot-payload.map`, against a **16 KiB** budget.
- **The link address is generated, not agreed.** `a9boot-payload/build.rs` is a *build-dependency*
  on `a9boot-core` and writes the linker script from `abi::payload_exec_addr()`, so the payload's
  link base and the host's idea of where it executes cannot drift. Two independent checks confirm
  it on the built artefact: the linker map shows `_start` at `0x1_8038_0110`, and
  `a9boot-host::elf` flattens the ELF and asserts `entry == payload_exec_addr()`. The linker also
  `ASSERT`s the footprint against the same budget the host checks.
- **The three constants that *are* duplicated in assembly** (`MAILBOX_ADDR`, `MAILBOX_MAGIC`, and
  the mailbox field offsets, used by the vector handler and the EL1 stub, which run at EL1 with no
  page tables and cannot look anything up) have a tripwire test:
  `bundle::tests::assembly_literals_match_the_constants_they_duplicate` and
  `mailbox_offsets_used_by_assembly_are_the_structs_offsets`. Change the layout and the test fails
  next to the constants instead of the mailbox failing silently on the device.
- **Build gates, all offline:** `cargo build`, `cargo test` (75 pass) and the payload build all
  succeed with `--offline`. `cargo clippy --all-targets` reports style warnings only (literal
  grouping, `is_multiple_of`, one intentional `impl Default`), no errors.

### 7.5 Payload delivery, and why it is stateless

The payload is appended to the `EXEC` command that invokes it, so it is re-delivered each time and
never needs to survive the streaming phase. §3.4's probe establishes the buffer capacity and
`TransferBudget::check` refuses a command that will not fit; **the 16 KiB figure is the *budget*
the payload is held to, not an assumption about the buffer** — the budget is smaller than any
plausible buffer on purpose, and the measured capacity is what the live path actually uses.

---

## 8. Host-side command sequence (rung 1)

> **Sequencing, not design:** steps 0–1 need a **pwned** device, because the probe drives the ROM's
> own `memcpy` through the resident checkm8 handler. The first live checkm8 attempt failed with
> `PAD_TIMEOUT_NOT_STALL` (a host-side abort-window bug, since fixed and re-measured), so nothing
> below step 1 can be measured yet. The probe is ready and queued — see UNVERIFIED.md §0.

```
 0. ident()                                    ; CPID/BDID/PWND must match, or stop
 1. probe(): AUSB tunables? DRAM reachable? extent? buffer capacity?   (§3.5 - named refusal)
 2. exec(PING)                                 ; payload runs from the DFU buffer; DESCRIBE reply
 3. for each blob chunk: mem_write(); mem_read(); compare
 4. host edits the DTB; mem_write the final DTB
 5. exec(PREPARE, descriptor)                  ; payload validates the descriptor + ranges
 6. exec(GO, descriptor)                       ; cache clean, EL setup, eret. Never returns.
 7. poll mailbox() until timeout               ; the only post-handoff evidence that exists
```

Steps 0–5 are fully scripted, reversible, and each ends with a measured reply. Step 6 is the point
of no return; the payload writes a "handoff" record to the mailbox immediately *before* `eret` so
that "we jumped" and "we crashed on entry" are distinguishable.

---

## 9. QEMU: what I need from `qemu-validator` (they own the harness — I will not duplicate it)

What a QEMU harness *can* prove, and what it cannot, must be stated by them; my requirements:

1. Run the **payload's command path** on `qemu-system-aarch64 -M virt` as a bare-metal EL3 image:
   exercise `PING`/`DESCRIBE`/`PREPARE` against a **host-generated descriptor and DTB**, and assert
   the payload's replies match the host codec's expectations. This tests the ABI and the descriptor
   validation, i.e. the parts most likely to be wrong in a way that is invisible on hardware.
2. Run the **host's plan + FDT edit** against `s8003-n69.dtb` and assert the edited blob re-parses,
   every placeholder is filled, the memreserve list is present, and `linux,initrd-start/end` exist.
3. **Cannot-prove boundary (theirs to state, mine to respect):** QEMU's `virt` machine is not an A9.
   It cannot prove `SCR_EL3`/`TTBR0_EL3` behaviour, the A9 EL3→EL1 transition, the AIC/FIQ question
   (U-3), DRAM reachability from the ROM's tables (U-1), or anything about the DFU channel.
4. What I will hand them: the payload ELF/bin + the `--descriptor` decoder so a test can assert the
   payload's *reply bytes* rather than its source.

The same list, addressed to `qemu-validator` directly and asking them to state the boundary in
their own words, is [`QEMU-CONTRACT.md`](QEMU-CONTRACT.md).

---

## 10. Open items and their status

| # | Item | Owner | Status |
|---|---|---|---|
| 10.1 | `LOADER-FILL.md` as the DTB contract | dt-engineer | **RECEIVED** and implemented (§4.4). Note two deliberate differences from their *minimum* target DTB, both in a9boot's favour and both enumerated: a9boot adds the `/reserved-memory` children for the regions it owns, and the AUSB PHY properties when the probe supplies them |
| 10.2 | Is the iPhone SE UART physically observable? | dt-engineer | **ANSWERED**: probably not (Lightning pinout). The UART is therefore demoted to an upside (§5.4), and rung 1 no longer depends on it |
| 10.3 | `apple_wdt` register sequence, and whether the ROM leaves the watchdog armed | kernel-engineer | OPEN. Would arm a *visible* reset signal, and closes U-8 |
| 10.4 | Which kernel artefact will exist | kernel-engineer | **ASKED**: plain `Image`. `Image.gz` is refused by name rather than half-supported (§4.1) |
| 10.5 | `rusb 0.9` as a non-default feature; the `aarch64-unknown-none-softfloat` target | Lead | **APPROVED and done**: the target is installed, the payload builds, and the default host build has **no USB capability at all** — `transport::open_live()` returns a named refusal, asserted by `selftest` and by test |
| 10.6 | An initramfs that binds the USB gadget (configfs + `acm`) so `console=ttyGS0` exists | rootfs-engineer | OPEN, and it is the only part of channel (c) a9boot does not own (§5.3) |
| 10.7 | The live transport implementation | Lead | **WRITTEN, awaiting review**: `crates/a9boot-host/src/transport/live.rs`; entry point `a9boot-host probe --live`; compiled only with `--features usb`. Every path is **UNVERIFIED-BY-TEST** (UNVERIFIED.md U-16) — no test here can exercise it — and the default build still cannot open a device, which `selftest` asserts. Device access stays Lead-only (HANDOFF §9.1) |
| 10.8 | One probe procedure rather than two | Lead + dt-engineer | **DONE**: `a9boot-host probe` implements dt-engineer's register sequence *and* the DRAM walk in one step list, using only the ROM's primitives |
| 10.9 | A pwned device to run it on | Lead | **NOT LANDED**: the first live checkm8 attempt failed `PAD_TIMEOUT_NOT_STALL`; the host-side cause is fixed and re-measured (1.000/2.000/4.000/5.000 ms). Every probe-group item is downstream of this — sequencing, not design (UNVERIFIED.md §0) |

## 11. PLAN B, and the risks we are managing

### 11.1 PLAN B — if the ROM's EL3 map does not cover DRAM

Then `mem_write` to `0x8_xxxxxxxx` will fault or corrupt, and no blob can be staged. The fallback is
to **extend** `TTBR0_EL3` from the DFU buffer: allocate a new L2/L3 table in SRAM, copy the ROM's
existing entries, add DRAM as normal cacheable memory, point `TTBR0_EL3` at it, `tlbi alle3`.
Constraints: the granule is fixed by `TCR_EL3.TG0` (16K, `gaster.c:47` says the ROM's tables are
16K-granule), **no existing mapping may be lost** (the USB stack lives in them), and a mistake loses
the DFU session until the phone is physically re-plugged. It is therefore attempted only after probe
R0 fails, never speculatively, and it is its own review item.

### 11.2 Risk register

| Risk | Consequence | Mitigation |
|---|---|---|
| `TTBR0_EL3` never touched | we keep the USB stack we depend on | §4.3 keeps the ROM's EL3 regime (and its FIQ bit) alive |
| Payload fault while running from the DFU buffer | the `UPLOAD` never returns; host sees a named timeout, no corruption | payload is stateless; a fresh `DNLOAD`+`UPLOAD` re-runs it. Rust `#[panic_handler]` writes a reason to the mailbox before parking |
| Wrong blob address | silent corruption of the kernel image or the loader | every blob's read-back verification (§3.3) + §3.2 invariants checked in `plan` |
| Claiming a framebuffer we did not light | blank screen instead of an error | `status` stays `disabled` unless a display module reports success (§4.4) |
| Losing the DFU session | phone needs a physical re-plug | no writes outside DRAM + SRAM DFU buffer; nothing on `D:`; the Lead owns the hardware |

---

## 12. Falsification tests (one per INFERRED claim)

| Claim | Label | Test that falsifies it |
|---|---|---|
| DRAM base `0x8_0000_0000` | INSPECTED (node unit-address + `dma-ranges`) | the probe's write/read round trip at `DRAM_BASE` |
| DRAM is 2 GiB | INSPECTED (product spec) | the probe's 128 MiB-step walk; `Probe::dram_extent()` reports what to declare |
| The ROM's EL3 map reaches DRAM | INFERRED | probe step 1 — **the single measurement the whole layout rests on** (U-1) |
| The DFU buffer holds the payload's 12,688-byte footprint | INFERRED | the capacity probe (U-2) |
| The DFU buffer region is executable, not just writable | INFERRED | `EXEC PING` returns a reply; a timeout means it is not (U-14) |
| The payload runs at EL3 with the ROM's MMU on | INSPECTED (`tlbi alle3` in the reference payload) | `DESCRIBE` reply: `CurrentEL`, `SCTLR_EL3`, `TTBR0_EL3` |
| The AUSB tunables are readable from `0x2_0C000038` | INFERRED (the ROM programmed the PHY) | two probe reads, non-zero and equal; then whether the PHY probes (U-13) |
| `SCR_EL3.FIQ` lets NS FIQs reach EL1 | UNKNOWN | `DESCRIBE` reports `SCR_EL3`; if FIQ = 1 the timer path is the next experiment (U-3) |
| EL1 sysreg writes from EL3 land in the NS bank | ARCHITECTURAL | the EL1 stub's read-back; a mismatch records `EL1_STATE_UNEXPECTED` (U-4) |
| The mailbox is readable after handoff | UNKNOWN | post-`GO` `mem_read`; a timeout means U-10 is false and the fallback is the USB transition |
| FB `640x1136`, stride 2560, `a8r8g8b8` | INFERRED | a lit panel with wrong colours/geometry (rung 2 only) |
| `Image` `text_offset` | MEASURED per build | the host rejects a header whose magic/page-size/`image_size` disagree with the file |

The full list, including the ones that cannot be settled offline, is `UNVERIFIED.md`; the QEMU
boundary is `QEMU-CONTRACT.md`.
