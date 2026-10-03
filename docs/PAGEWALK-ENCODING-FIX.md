# Pagewalk encoding fix, granule parameter, and cross-check

**Scope:** `crates/a9boot-host/src/pagetable.rs` (+ its tests), `crates/a9boot-host/src/main.rs`
(CLI plumbing). No phone access. No other files touched.

## 1. The encoding inversion (the bug)

ARM ARM VMSAv8-64 translation-table descriptor, `bits[1:0]`:

| bits[1:0] | L0 | L1 | L2 | L3 |
|-----------|----|----|----|----|
| `0b00` | invalid | invalid | invalid | invalid |
| `0b01` | block | block | block | **invalid/reserved** |
| `0b10` | reserved | reserved | reserved | reserved |
| `0b11` | table | table | table | **page** |

`Descriptor::decode` had `0b01`/`0b11` **swapped** at L1/L2 (`(0b11,_)=>Block`,
`(0b01,_)=>Table`). Fixed to the truth above. The old tests asserted the bug (the fixture at the
old `:395` wrote `0b11` and labelled it "block, AF"), so they were corrected, not deleted, and a
new `descriptor_type_bits_match_the_arm_arm` test pins every arm.

## 2. Cross-check against a non-synthetic, hardware-measured descriptor

`r45-table.json` read the ROM's L0 table at `ttbr0_el3 = 0x1800875C0`: `entry[0] =
0x00800001800C8003`, entries `[1..] = 0`. Decoded correctly:

- `bits[1:0] = 0b11` → **Table**;
- `bits[47:12] = 0x1800C8000` → the **L1 table** (the "gaster constant" `0x1800C8000`, which the
  walk had previously used *as the root* — it was a correct L1 address, never a correct root).

`measured_hardware_entry_is_a_table_pointing_at_the_l1_table` asserts `kind == Table` and
`output_base == 0x1800C8000`. This value has the property the old `0x8_0000_0000`-style fixtures
lacked: block (`bits[47:30]`) and table (`bits[47:12]`) masks DISAGREE on it, so re-inverting the
encoding makes this test FAIL.

A second cross-check, `a_descriptor_with_nonzero_bits_13_12_pins_the_granule`, uses a table
descriptor with `bits[13:12] = 0b11` so the 4K (`bits[47:12]`) and 16K (`bits[47:14]`) decoders
produce DIFFERENT table addresses — closing the granule-axis analogue of the same ambiguity.

**Gap, stated explicitly:** no Linux-kernel page-table dump from the QEMU boot was obtainable this
session (no `TTBR0_EL1` dump exists in the tree). The measured ROM L0 entry is the non-synthetic
reference used here; the "external kernel descriptor" reference remains open.

## 3. Granule decision (HONEST, no guess)

`TCR_EL3.TG0` is **not yet measured** (it sat past the 64-byte DESCRIBE reply cut). The kernel is
built `Image-16k`, so TG0 is *likely* 16K, but the walk does **not** assume it. A
`--granule {4k,16k,64k}` CLI parameter was added (default `4k`, documented as a placeholder), and
the `Granule` type carries every granule-dependent fact in ONE place so they cannot drift apart:

| granule | page shift | index bits/level | entries/level | levels (48-bit) | first level |
|---------|-----------:|-----------------:|--------------:|----------------:|------------:|
| 4K      | 12         | 9                | 512           | 4               | 0           |
| 16K     | 14         | 11               | 2048          | 4               | 0           |
| 64K     | 16         | 13               | 8192          | 3               | 1           |

- **Table/page output address field**: `bits[47:12]` (4K), `bits[47:14]` (16K), `bits[47:16]` (64K).
- **Per-level index shift** `level_shift(L) = page_shift + (last_level − L) × index_bits`:
  4K `39/30/21/12`; 16K `47/36/25/14`; 64K `42/29/16`.
- **Block output base / size** (block at level N covers the index at N and below, so its mask is
  `bits[47 : level_shift(N)]`):

| granule | L1 block | L2 block |
|---------|----------|----------|
| 4K      | 1 GiB `bits[47:30]` | 2 MiB `bits[47:21]` |
| 16K     | **64 GiB `bits[47:36]`** | **32 MiB `bits[47:25]`** |
| 64K     | **4 TiB `bits[47:42]`** | **512 MiB `bits[47:29]`** |

> **Note for the record:** a draft of these numbers circulated with the 16K/64K L1/L2 block sizes
> one level down (16K "L1 32 MiB / L2 16 KiB"; 64K "L1 512 MiB / L2 64 KiB"). That lists the L2
> block as "L1" and the page as "L2 block" and omits the real L1 block. The values in the table
> above are the ones used, and they match Linux `arch/arm64/include/asm/pgtable-hwdef.h`
> (`PMD_SHIFT=(PAGE_SHIFT-3)*2+3`, `PUD_SHIFT=(PAGE_SHIFT-3)*3+3`,
> `PGDIR_SHIFT=(PAGE_SHIFT-3)*LEVELS+3`), which is derived from the ARM ARM. `granule_facts_are_self_consistent`
> pins them.

`T0SZ` is likewise **not measured**; the walk assumes the common 48-bit input case and says so.

## 4. Safety properties preserved

- `Mapping::may_touch()` returns `true` **only** for `Mapped` (pinned by
  `may_touch_is_true_only_for_mapped`).
- The `NO_POSITIVE_CONTROL` refusal is enforced in `pagewalk_live`: the known-mapped controls
  (handler `0x1800E0F08`, DFU buffer `0x180380110`) are walked FIRST through the same code path,
  and if any does not come back `Mapped` the run refuses with exit 7 instead of printing
  uninterpretable UNMAPPED answers.
- The `root` line now distinguishes `explicitly provided via --root` from the INSPECTED
  `gaster.c:627-631` candidate.

## 5. Build/test results

- `cargo test -p a9boot-host` — **133 passed**.
- `cargo test -p a9boot-host --features usb` — **133 passed**.
- `CARGO_TARGET_DIR=target/usb cargo build --release --features usb` — **built**.

`a9boot/target/usb/release/a9boot-host` sha256:
`8f167d91c6898ae01c877394e3c3e68fc0937419631932d146ade2ff933e62a3`
