# a9boot — UNVERIFIED list

**Every claim in `DESIGN.md` that is not MEASURED or INSPECTED, with the test that would falsify
it.** Task-8 deliverable 3. Labels follow HANDOFF §9.5.

**Status legend:** `OPEN` = nothing has tested it yet · `PROBE` = the post-pwn experiment settles
it before any loader code runs · `BOOT` = settled only by a real boot attempt · `SETTLED-BY-TEST`
= falsified or confirmed offline in this workspace, with the test named.

The three that would hurt most, in dt-engineer's ranking (`LOADER-FILL.md` §8), are **U-5**
(over-declared DRAM corrupts rather than panics), **U-1** (if the ROM's translation does not reach
DRAM, the whole design stops) and **U-3** (a wrong `SCR_EL3.FIQ` costs the timer interrupt).

---

## 0. SEQUENCING — everything here is downstream of a rung that has not landed

**Rung 0 is live, moving, and unproven. The Lead's measurements on hardware, in order:**

* *Attempt 1* — `PAD_TIMEOUT_NOT_STALL`: the pad request never STALLed (0 STALLs in 6,000 attempts;
  5,997 NAKs with `libusb_rc = -7`). The cause was host-side: Windows could not honour a sub-tick
  timeout, so the abort window truncated at a ~15.5 ms tick for every non-zero value.
* *The tick fix, re-measured* — the window now truncates where it says: `4 → 4403 µs`, `5 → 5376`,
  `0 → 1185`, `1 → 1657` (before the fix, every non-zero window was ~11.5 ms).
* *Attempt 2* — **SETUP's pass condition was reached three times** (`pad_status=STALL`,
  `pad_micros=27929`), and the run continued through SPRAY and PATCH. So the exploit is no longer
  blocked at the sweep; it is blocked **at or after PATCH**, with the reset itself the prime suspect
  (our own tool has always reported `Unverified` for it, and the Lead is measuring whether the device
  is re-enumerated at all).

**What that changes, and what it does not.**

* It does **not** change the design or anything below it. `a9boot` starts after a pwned device
  exists; nothing in `DESIGN.md` depends on *how* the pwn is achieved, and the channel decode (§2.3)
  comes from the reference payload, not from a session.
* It **does** change the sequence: **every PROBE-group item below is blocked until a `PWND:[checkm8]`
  serial is seen.** The probe drives the ROM's own `memcpy` through the resident checkm8 handler, so
  with no handler there is no channel, no readback, and no measurement. The probe is *ready and
  queued*, not *pending*.
* "Reached SETUP's pass condition and ran PATCH" is real progress and it is **not** a pwn. U-1, U-2,
  U-5, U-13 and U-14 still have no measurement, and everything built on them — which is the whole
  layout — remains INFERRED.

Recorded here rather than in a status message on purpose: a reader who does not know that the pwn
rung is unlanded would see "PROBE" next to U-1 and assume a measurement exists.

Recorded here rather than in a status message on purpose: a reader who does not know that the pwn
rung is unlanded would see "PROBE" next to U-1 and assume a measurement exists.

---

## A. Settled offline in this workspace

| # | Claim | How it was settled |
|---|---|---|
| U-0a | The payload's link address equals the address the channel executes it at | **SETTLED** — `a9boot-host::elf::tests::the_built_payload_matches_the_channel_contract` flattens the real built ELF and asserts `entry == abi::payload_exec_addr() == 0x1_8038_0110`. Measured from `a9boot-payload.map`, and asserted again by the linker (`ENTRY(_start)` plus the generated script) |
| U-0b | The payload fits the transfer that delivers it | **SETTLED** — measured 10,640 B image + 2 KiB stack = 12,688 B footprint against a 16 KiB budget (`layout::PAYLOAD_MAX_FOOTPRINT`), asserted by the linker script's `ASSERT` **and** by `elf::FlatImage::check` |
| U-0c | The reply area cannot overlap the payload's own code | **SETTLED** — `abi::tests::reply_cannot_overwrite_the_payload` (reply ends at `0x110`, payload starts at `0x110`) |
| U-0d | The `MEMC` command's appended data starts where `x1` says | **SETTLED** — this was a **real bug** found by `channel::tests::memc_packet_puts_len_in_x2`: the header was sized for `EXEC` (`0x110`) for `MEMC` too, so the ROM would have copied zeros from `base+0x48`. The test now pins `dnload.len() == 0x48 + len` |
| U-0e | DT cells are big-endian, and `linux,initrd-*` is one u64 | **SETTLED** — `fdt::tests::cell_endianness_is_big_endian_on_the_wire`, `u64_properties_are_two_cells`, plus a round-trip against the real `s8003-n69.dtb` |
| U-0f | DAIF/MMU/page-table requirements are the kernel's, not m1n1's | **SETTLED by citation** — booting.rst "The MMU must be off"; see DESIGN.md §4.5 |
| U-0g | A **stale template** `linux,initrd-start`/`-end` cannot survive into the hand-off | **SETTLED** — `a_stale_template_initrd_pair_is_overwritten_with_the_loaded_size` seeds the reference template's pair (2,670,592 B implied) and asserts the finished tree carries the loaded byte count and nothing else |
| U-0h | The initrd size the DTB states is the size the loader **actually stages** | **SETTLED** — `bundle::handoff_contract` derives it from the write step that targets `plan.initrd_addr`, asserts `end − start` equals it, and refuses by name (`HANDOFF_INITRD_SIZE_UNKNOWN`) when no step stages an initramfs the plan expects (`an_unknown_initrd_size_refuses_by_name`) |
| U-0i | The initrd properties carry the **`linux,` prefix** | **SETTLED** — `an_unprefixed_initrd_property_is_refused_by_name`. Without it the kernel ignores the property and the boot panics with `VFS: Cannot open root device`: a property-name bug wearing a rootfs bug's clothes |
| U-0j | No blob is placed inside the kernel image's span | **SETTLED** — asserted in `handoff_contract` and guarded in `Plan::check` (`PLAN_BLOB_INSIDE_KERNEL`). `__primary_switched` zeroes the image's bss before `setup_arch` reads the tree, so a blob there is total silence with no output anywhere |
| U-0k | `cpu-release-addr` is `<0 0>` in rung 1 **even if the template said otherwise** | **SETTLED** — `rung_1_writes_zero_over_a_stale_cpu_release_addr` seeds a bogus `0x8_7000_0000`, runs the real edit path, and asserts zero (and that rung 2 can fill it) |
| U-0l | The plan's idea of the DTB size is the **edited** blob's size | **SETTLED** — `Plan::adopt_edited_dtb`: the edited tree is 27,664 B against the source's 22,880 B on the real board DTB (measured), and the method asserts that adopting the size moves no region |

---

## B. Settled by the post-pwn probe (no loader needed)

The probe is `a9boot-host probe`, implemented once in `bundle::probe_steps` / `run_probe` and
shared with dt-engineer's register sequence so there is **one** procedure, not two.

| # | Claim | Label | If it is false | Test |
|---|---|---|---|---|
| **U-1** | The ROM's EL3 translation covers DRAM (`0x8_0000_0000`) | INFERRED | Nothing can be staged; the design stops at PLAN B (DESIGN.md §11.1), which needs `TTBR0_EL3` surgery and can lose the DFU session | **PROBE step 1**: write a 32-byte pattern to `DRAM_BASE` through `MEMC`, read it back, compare |
| **U-2** | The DFU buffer holds at least the payload's 12,688-byte footprint (and ideally a whole `Image`) | INFERRED from stock DFU loading a ~200 KiB iBSS | The payload cannot be delivered; a smaller payload build is required. **Named refusal, not a corruption** | **PROBE**: write/read back increasing lengths (2 KiB, 4 KiB, 8 KiB, 16 KiB, …) and stop at the first failure |
| **U-5** | DRAM is nominally 2 GiB (`layout::DRAM_SIZE`) | INSPECTED as a *product spec*, not measured on this device | **Worst case: corruption, not a panic.** Over-declaring hands the kernel dead pages | **PROBE**: the 128 MiB-step walk from `DRAM_BASE` to `+2 GiB`, plus the last 32 bytes. `Probe::dram_extent()` reports what to *declare* |
| **U-13** | `0x2_0C000038`/`0x2_0C00003C` hold the AUSB tunables (non-zero, stable across two reads) | INFERRED — the SecureROM programmed this PHY, because that is how DFU is talking to us | USB stays dead: the PHY probe returns `-ENODEV` (`ausb.c:149-156`), dwc2 defers forever, and the `ttyGS0` gadget console never appears. **Not boot-fatal** | **PROBE**: two `MEMC` reads of those addresses, compared (implied by `AusbTunables::looks_plausible`), then whether the PHY probes at boot |
| U-14 | The DFU buffer region is **executable** from EL3, not just writable | INFERRED (high confidence): the exploit copies its own handler to `0x1_800E_0F08` and executes it, and both addresses fall inside the same SRAM mapping | `EXEC` faults: the host sees a `UPLOAD` timeout and no reply | **PROBE/PING**: `bundle` step `EXEC PING`; a timeout is the signal |

---

## C. Settled only by a boot attempt

| # | Claim | Label | If it is false | Test |
|---|---|---|---|---|
| **U-3** | `SCR_EL3.FIQ`'s boot-time value lets the A9's `AIC_FIQ`-routed arch-timer interrupts reach Non-secure EL1 | UNKNOWN — nobody has established it | No timer interrupt: the kernel hangs early with no output. This is why the payload never writes that bit (booting.rst requires it unchanged) and reports it instead | **DESCRIBE** reports `SCR_EL3` before anything is attempted; if FIQ = 1, the next experiment is clearing it deliberately and documenting the deviation |
| **U-4** | Writing `TTBR0_EL1`/`SCTLR_EL1`/`TCR_EL1`/`MAIR_EL1`/`VBAR_EL1`/`SP_EL1` from EL3 **after** setting `SCR_EL3.NS = 1` targets the Non-secure bank | ARCHITECTURAL claim, not measured here | The kernel is entered with whatever the NS bank happened to hold — an invisible, unreproducible death | **The EL1 stub reads them back** (`mrs sctlr_el1`, `vbar_el1`, `ttbr0_el1`). A mismatch writes `record::EL1_STATE_UNEXPECTED` to the mailbox and parks instead of jumping. The payload's own run then reports it |
| **U-9** | Post-handoff DFU traffic cannot corrupt kernel DRAM, because the DFU buffer is in SRAM, outside the memory node | INSPECTED + INFERRED | The mailbox channel would be unsafe to use, and the loader would have to stop answering | Read the mailbox after handoff and confirm the kernel is unaffected; `PROBE` confirms the buffer address (MEASURED by the Lead via `a9pwn plan`) |
| **U-10** | The resident EL3 handler can still service `DFU_UPLOAD` after the EL1 PSTATE is masked (i.e. DAIF is banked per-EL, or the mask does not affect EL3 delivery) | UNKNOWN | The mailbox is unreadable after handoff. **This is why the mailbox is labelled best-effort and why the same-round-trip reply exists**: the loader's own progress is measured *before* the point of no return, and needs none of this | **BOOT**: after `GO`, `a9boot-host` reads the mailbox; a timeout means U-10 is false, and the fallback evidence is the USB state transition |
| **U-11** | DRAM is accessible from the **Non-secure** world | INFERRED (Linux must run there) | Nothing works at all | The EL1 vector handler's first action on a fault is a **Non-secure** store to the mailbox: if U-11 holds, the record appears |
| **U-12** | Leaving `cpu-release-addr = <0 0>` gives a clean single-CPU boot | INSPECTED from kernel source (`smp_spin_table.c:71-72` + `smp.c:810-818`), not measured on this device | A hang or a warning storm on an otherwise working boot | **BOOT**: the first boot's console/mailbox; a hang before `start_kernel` with `initcall_debug` absent is the signal |
| **U-6** | The UART needs the loader to enable its clock, ungate `ps_uart0`, mux its pins and set the baud — and the UART is **probably unreachable** through Lightning anyway | INFERRED (dt-engineer, `CONSOLE-SIGNALS.md` Q1) | Total loss of the console — which is exactly why rung 1 no longer depends on it (DESIGN.md §5) | A byte at `0x2_0A0C_0000`, or a DCSD-class cable during **stock** DFU (if it does not print there, it will not print for us) |
| **U-7** | The framebuffer is `640x1136`, stride `2560`, format `a8r8g8b8` at `0x8_7800_0000` | INFERRED | Wrong colours, or a sheared image — cosmetic, and only reachable in rung 2 | A lit panel with a known pattern; the `format` experiment is in `LOADER-FILL.md` §10 |
| **U-8** | The A9 watchdog is **not** armed when our payload runs | INFERRED (iBoot normally arms it; iBoot never ran on this path) | A reset mid-boot, visible as the device re-appearing in DFU | Read `0x2_102B_0000` region before `GO`; a reset within the watchdog period after a clean handoff is the signal |
| U-15 | The payload never reads `x7`/`x8` (both are not arguments: `x7` is the first 8 bytes of our own image, `x8` is our entry address) | INSPECTED (the reference handler loads them that way) | Silent garbage in one argument | Code inspection; `a9boot_main` takes only `x0..x2` |
| **U-19** | The `UPLOAD` reply survives a cancelled/unlinked transfer | **MEASURED FALSE, and it cost us the milestone's evidence** (task-12): the trigger's URB came back `-2` (unlinked) with **64 bytes actually transferred**, and the wire shows `DONE_MAGIC` first — the payload ran — but rusb's **synchronous** `read_control` returns only `Err`, so `actual_length` and the bytes are discarded and the run is reported as `LIVE_UPLOAD_FAILED[status=TIMEOUT]`. Graded partials of 64/128/192/198 are recoverable on this device (RUNG1-EVIDENCE §6, `libusb1-sys` async), so the fix is to read the UPLOAD through the **async** API and keep `actual_length` | The next run repeats the loss: a success with a short reply stays indistinguishable from a hang | Async `Transfer::read_control` + `transfer.actual_length()`, and a success criterion of **`DONE_MAGIC` present in the received bytes**, not `status == OK` |
| **U-16** | The live transport works at all: `rusb 0.9` finds the pwned device, claims interface 0, reads the declared serial index, chunks `DNLOAD` at 0x800 and gets a full reply to the `0xFFFF` `UPLOAD` | **PARTIALLY MEASURED, still OPEN** — and on the tenth measurement it did more than the tool reported: the payload was staged, verified, triggered and **answered with `DONE_MAGIC`** (`a9pwn-traces/linux/r27-execping.txt`); the run was mis-reported for the reason in U-19. **U-16** The tool ran on hardware twice (session 3): the three-way gate, the identity check, `DFU_GET_STATUS` (status 0, state 2 dfuIDLE) and the `DNLOAD` (72 B, `C 0/72` accepted) all worked; the `UPLOAD` was never answered — unlinked after 1002 ms — under both `minimal` and `terminated` framing. `transport/live.rs` remains UNVERIFIED-BY-TEST beyond those four facts, and no test in this workspace can exercise one line of it, by construction | A timeout is not a channel, so nothing downstream is unblocked | The Lead's next `firstlight --live --sequence reference` (Lead-only). Every failure path has its own code: `LIVE_NO_DEVICE`, `LIVE_OPEN_FAILED`, `LIVE_CLAIM_FAILED`, `LIVE_NO_SERIAL_INDEX`, `LIVE_NO_SERIAL`, `LIVE_DNLOAD_FAILED`, `LIVE_DNLOAD_SHORT`, `LIVE_UPLOAD_FAILED`, `LIVE_SUFFIX_*`, `LIVE_TERMINATOR_*`, `LIVE_GET_STATUS_*`, `STATE_WALK_MISMATCH` |

---

## C2. Known gaps between the documents and the code (found by adversarial review)

* **U-2 has no implementation.** `DESIGN.md` §3.4/§3.5 describe a capacity ladder and a
  command-line parameter; `probe_steps()` contains no such step and `TransferBudget::from_probe` has
  no callers. The capacity is still the assumed 16 KiB.
* **U-13's falsifier asks for two reads; `probe` does one**, and `looks_plausible` only rejects
  zero/all-ones. Two `--read` options are the manual substitute.
* `DESIGN.md` §2.4's `probe(len)`/`ident()` channel operations do not exist as functions.
* `DESIGN.md` §2.3's "+0x48.. payload data" describes the `MEMC` case; `EXEC` appends at `0x110`.

## D. What a QEMU harness can and cannot prove

`qemu-validator` owns the harness; this is what I will use it for and what I will not claim from
it. Detail in `QEMU-CONTRACT.md`.

| Settled by QEMU | Not settled by QEMU, ever |
|---|---|
| The payload's command dispatch and descriptor validation (U-4's *logic*, not its architecture) | Anything about the A9's EL3/`SCR_EL3`/`TTBR0_EL3` behaviour (U-1, U-3, U-4's premise) |
| The reply/descriptor byte layouts, both directions | The DFU channel, the buffer, or the ROM's translation (U-1, U-2, U-14) |
| The host's DTB edit against the real `s8003-n69.dtb`, including the four mandatory properties and the reservations | The panel, the AUSB PHY tunables, or the UART (U-6, U-7, U-13) |
| The EL1 stub's register checks, as *code* | Whether EL1 exists as the A9 implements it |

A QEMU run is evidence about **our code**, never evidence about **this device**. Stated here so
that no future reader can mistake one for the other (HANDOFF §9.5).
