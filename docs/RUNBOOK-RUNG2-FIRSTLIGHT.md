# RUNBOOK — rung 2, first light: the pwned payload's EXEC/MEMC channel

**Audience:** the Lead, who is the only person who runs these. Everything here is a command to
copy-paste, what PASS looks like, what FAIL looks like, and **what each failure would mean**.
**Owner:** `loader-engineer`. **Scope:** `a9boot/**`. **Status:** the codec is tested; **the device
bindings are UNVERIFIED-BY-TEST** until the first exchange parses.

---

## 0. The one-line version — and the ORDER (S8: cheapest and most certain first)

**A fresh pwn is a resource, and one unmapped read can destroy it** (MEASURED: `0x20E80110` got no
reply, wedged EP0, and the recovery reset dropped the device). So the order is fixed, cheapest and
most certain first, and the ladder in step 0 comes before any payload is sent:

```sh
cd <HOME>/Documents/iOS/arlo-ios-move/a9boot
D=./target/usb/release/a9boot-host

# 0. U-2: how large can ONE command be? Read-only in effect; run it BEFORE anything large.
A9BOOT_LIVE_CONFIRMED=yes $D capacity --live --json ../a9pwn-traces/linux/rung2-capacity.json
# 1. The channel itself (MEASURED working on a fresh pwn).
A9BOOT_LIVE_CONFIRMED=yes $D firstlight --live --sequence reference --json ../a9pwn-traces/linux/rung2-ref-1.json
# 2. Two different addresses: the staleness/provenance upgrade.
A9BOOT_LIVE_CONFIRMED=yes $D firstlight --live --sequence reference \
    --read 0x20c000038:8 --read 0x20c000030:8 --json ../a9pwn-traces/linux/rung2-ref-2.json
# 3. The handler's own bytes: the cheapest CONTENT-VERIFIED read in the address space.
A9BOOT_LIVE_CONFIRMED=yes $D firstlight --live --sequence reference --read 0x1800e0f08:32 \
    --json ../a9pwn-traces/linux/rung2-handler.json
# 4. EXEC: deliver our payload, verified before it runs.
A9BOOT_LIVE_CONFIRMED=yes $D exec --live --cmd PING \
    --payload target/aarch64-unknown-none-softfloat/payload/a9boot-payload \
    --json ../a9pwn-traces/linux/rung2-exec-ping.json
```

Read the exit code first, then `VERDICT`, then the JSON. **One attempt per process.** Re-idle with
`DFU_CLRSTATUS` before every attempt.

**THE FRESH-PWN RULE (MEASURED, `RUNG2-EVIDENCE.md` §1.1).** The command hook does **not** survive;
the `PWND:[checkm8]` marker does. Five attempts: four on a stale pwn got `NO REPLY`, the fifth — a
genuinely fresh pwn on a power-cycled device — PASSed. And `a9pwn run` **short-circuits when the
marker is already present** (`stages.rs:1981-1989`), so "I re-pwned it" can be false while the
marker is true. **A stale marker is not a live payload.** Any channel work runs immediately after a
genuine pwn, with no intervening reset.

**THE LADDER NEVER TOUCHES AN UNKNOWN ADDRESS.** `capacity` uses one command per step whose header
is `memcpy(0, 0, 0)` — no destination, no source, no length — so it writes **nothing** except the
`DNLOAD` it is measuring, and the reply echoes the appended data back. The resident handler is
2.6 MiB below the buffer, so no step that stops at 16 KiB can reach it. Reading an address the ROM
does not map is what cost the device; the ladder is the answer, not a risk.

---

## 1. Safety rules that are not negotiable

| # | Rule | Why |
|---|---|---|
| S1 | **Never run anything from `a9boot` against the device except the two `--live` commands below.** | The default build has no USB capability at all; `--live` needs the `usb` feature, the flag *and* `A9BOOT_LIVE_CONFIRMED=yes`. A pwned device is a loaded gun: one careless write is a wild write into SRAM. |
| S2 | **On a timeout, STOP. Do not retry without re-idling.** | MEASURED: a cancelled control transfer can wedge EP0 on this bootrom (`RUNG1-EVIDENCE.md` §3). A retry sends a second `DNLOAD` on top of a buffer whose state is now unknown. |
| S3 | **Re-idle with a bare `DFU_CLRSTATUS` (Lead-only: `a9pwn probe-clrstatus --send --length 0 --watch-ms 3000`) before every attempt, and record the state you started from.** | MEASURED: a `DNLOAD` leaves the machine in `0x05 dfuDNLOAD-IDLE`; a bus reset moved it `6→7` and did *not* reach idle; the bare `CLRSTATUS` reliably lands on `0x02`. Its cost: the device drops and re-enumerates (~435 ms, new address), so any cached address or handle is dead. |
| S4 | **One attempt per process.** | `LiveTransport::open()` enumerates by VID/PID every run and caches nothing across runs, which is what re-enumeration requires. A shell that holds a handle across the re-idle is testing a stale device. |
| S5 | **Never publish `ECID`/`UDID`/serial.** The tools redact (`channel::redact_descriptor`, asserted by test). If you paste output, paste the redacted form. | Hard rule. |
| S6 | **Do not declare a DRAM extent from the walk** until §7's cache question is answered. | A cache-served write/read-back passes on memory that does not exist; over-declaring hands the kernel dead pages and corrupts rather than panics (U-5). |
| S7 | The device's serial string index **moves** between re-enumerations (measured: 4 in one session, 6 in another). | `live.rs` uses the index the device descriptor *declares*, never a constant. Do not "optimise" that to a number. |

---

## 2. The artefacts

Built by me; hashes MEASURED at build time (re-check with `sha256sum` before a session — if they
differ, say so rather than running).

| Artefact | Bytes | sha256 |
|---|---|---|
| `a9boot/target/usb/release/a9boot-host` (**the one to run**; `--features usb`) | 9,608,368 | `7883d4eb2d0bb4dad7b8997b4e182f6213f8b47fb47eca7ddfd720110f1c157c` |
| `a9boot/target/release/a9boot-host` (default: **cannot** open a device) | 8,719,400 | `7303ff6f010f3d18412a296a0b04cec5b9269b8e8559314835f159778535ebc6` |
| `a9boot/target/aarch64-unknown-none-softfloat/payload/a9boot-payload` (aarch64 ELF; flat image 10,640 B) | 76,800 | `60b7420ca0735fc9b0c51579c1720a0428d5db5b0653a5d7466d0fd51abed78a` |

**Build from scratch** (the two flavours must use *different target dirs* — a plain `cargo build`
overwrites the usb binary and silently removes USB capability, which fails safe but wastes a
session):

```sh
cd a9boot
export PATH="$HOME/.cargo/bin:$PATH"
CARGO_TARGET_DIR=target/usb cargo build --offline --release -p a9boot-host --features usb
cargo build --offline --release -p a9boot-host
cargo build --offline -p a9boot-payload --profile payload --target aarch64-unknown-none-softfloat
sha256sum target/usb/release/a9boot-host target/aarch64-unknown-none-softfloat/payload/a9boot-payload
```

`rustup target add aarch64-unknown-none-softfloat` is already done on this box; the payload is kept
out of `default-members` on purpose so a plain `cargo test` still works (do not change that).

---

## 3. Phase A — offline, before the device is touched

```sh
cd a9boot
cargo test --offline                      # 35 core + 95 host
cargo test --offline --features usb       # same 95, plus the usb-gated code compiled
./target/release/a9boot-host selftest     # every check PASS, "no device was opened"
./target/usb/release/a9boot-host firstlight --sequence reference   # dry run: prints the 7 steps, exit 6
./target/usb/release/a9boot-host probe --only ausb                 # dry run: 1 packet, exit 6
```

PASS = every check PASS and the dry run exits **6 (UNKNOWN)**. Exit 6 is deliberate: a dry run
verified nothing and must not exit the way a verified run does. **If a dry run ever prints
`VERDICT PASS`, stop and tell me — that is a bug, not a success.**

---

## 4. Phase B — the first live exchange

```sh
A9BOOT_LIVE_CONFIRMED=yes ./target/usb/release/a9boot-host \
    firstlight --live --sequence reference --json ../a9pwn-traces/linux/rung2-ref-1.json
```

### What it sends, in order (this is the reference's own framing, `gaster.c:977-988` + `:829-834`)

| # | Wire | Meaning |
|---|---|---|
| 1 | `S 21 01 0000 0000 0048 / 72` | command `DNLOAD`: `MEMC` header, dst `0x1_8038_0010`, src `0x2_0C000038`, len 8 |
| 2 | `S 21 01 0000 0000 0010 / 16` | 16 zero bytes (`DFU_FILE_SUFFIX_LEN`, `gaster.c:41,987`) |
| 3 | `S 21 01 0000 0000 0000 / 0` | zero-length `DNLOAD`: end of download (`gaster.c:833`) |
| 4–6 | `S a1 03 0000 0000 0006 / 6` ×3 | `DFU_GET_STATUS` must read **state 6**, then **7**, then **8** |
| 7 | `S a1 02 ffff 0000 0018 / 24` | `DFU_UPLOAD`, `wValue 0xFFFF`: the trigger and the reply |

`--sequence minimal` (DESIGN.md §2.3: steps 1 and 7 only) was hardware attempt 1; `--sequence dfu`
(steps 1, 3, 7) was attempt 2. Both got `NO REPLY`. `reference` is what the reference actually
sends and what our own `a9pwn/src/stages.rs` implements.

Before arming, `firstlight --sequence reference` with no `--live` prints exactly this list. Compare
it to the usbmon capture, not to this table.

### PASS looks like

* exit **0**, `VERDICT PASS`, `actual_length == wLength` (24 == 24), and the reply's first eight
  bytes are `DONE_MAGIC` (`65 6e 6f 64 65 6e 6f 64` on the wire, `donedone` as the reference spells
  it) followed by a return value;
* the JSON records the exact `dnload_hex`, `upload_hex`, both sha256s, `duration_us`, `status`,
  `actual_length`, and the parsed `magic`/`retval`;
* **the value is only evidence if `state=PARSED`.** `AUSB_CFG0/CFG1` are then recorded with an
  interpretation sentence; a zero or all-ones pair is reported as `ZERO OR ALL-ONES: suspect`.

The **success criterion is both**: `actual_length == wLength` **and** the reply begins with
`[DONE_MAGIC][retval]`. Channel, requested length and transfer status are diagnostics — a green
`status=OK` with the wrong bytes is a FAIL, and a plausible-looking value with no `DONE_MAGIC` is
not a value at all.

### FAIL, and what each one means

| Exit | What you see | What it MEANS | Do |
|---|---|---|---|
| 3 | `REFUSED: live device access needs A9BOOT_LIVE_CONFIRMED=yes` | the gate did its job; nothing was opened | arm it |
| 3 | `this build has no USB capability` | you are running the non-usb binary | run `target/usb/release/...` |
| 3 | `identity check refused before sending anything: CPID …/BDID …/not PWND` | the wrong device, the wrong board, or no checkm8 payload resident. Nothing was sent. | `a9pwn ident`; do not "work around" it |
| 4 | `LIVE_NO_DEVICE` | nothing at `05ac:1227` | plug in / DFU |
| 4 | `LIVE_OPEN_FAILED[status=ACCESS]` / `LIVE_CLAIM_FAILED` | permissions, or another process holds interface 0 (a second holder loses the session) | close the other tool |
| 5 | `LIVE_UPLOAD_FAILED[status=TIMEOUT]` | the `DNLOAD` was accepted and the `UPLOAD` was never answered: the handler did not run, or ran and did not reach `usb_core_do_transfer` | **STOP.** Re-idle, then re-rank hypotheses. Do not retry blindly (S2) |
| 8 | `STATE_WALK_MISMATCH[status=WALK]… expected state 6 (dfuMANIFEST-SYNC), saw status 0 state 5 (dfuDNLOAD-IDLE)` | the framing is right, the machine is not where the reference expects it. Its own exit code *and* its own status token, so it cannot be read as a USB status | `CLRSTATUS`, re-idle, one retry; if it repeats, the ROM's transition differs from the reference's |
| 7 | `REPLY_BAD_MAGIC` | the transfer **completed** and the handler answered from the buffer — but the buffer's first word is not `DONE_MAGIC`, so it did not dispatch our command. Different bug from "no reply": the `DNLOAD` did not land where the handler reads it | stop; report the raw bytes |
| 7 | `REPLY_MAGIC_WITHOUT_RETVAL` / `REPLY_TRUNCATED` / `REPLY_DATA_SHORT` | a **short reply**: the transfer completed (`status=OK`) with `actual_length < wLength`, and the bytes we did get are in the JSON. The handler ran (or something wrote `DONE_MAGIC`), but the reply is incomplete. This is **not** "no data" | stop |
| 7 | `SUSPECT_STALE_REPLY` | two reads to **different** addresses returned byte-identical bytes. The reply cannot be attributed to its request: either the ROM's `DNLOAD` offset did not reset (the handler answered from an older command) or the two registers genuinely match. The first must be excluded before the second is believed. (The per-exchange field is `exchange_verdict`, so a grep for `"verdict": "PASS"` only ever finds a run that really passed.) | stop; the raw bytes are in the JSON |
| 6 | `UNKNOWN`, `exchanges: []`, every field `UNREAD` | nothing was sent, or the run selected no steps. **This is not a measurement of the device.** | — |

A warning never overrides the verdict, and the verdict never hides a warning: read `warnings[]` in
the JSON as well as the top-level `verdict`. **A single-exchange run carries
`PROVENANCE UNVERIFIED`**: `DONE_MAGIC` is INSPECTED from the reference, not measured, and the
handler echoes the buffer unchanged when the command magic does not match
(`payload_handle_checkm8_request.S:68-74`) — so one exchange cannot separate "our command ran" from
"the buffer already began with `DONE_MAGIC`". The second read (different address) or `--write` is
what upgrades the reply from *the channel answered* to *the channel answered **this** request*.

---

## 5. Phase C — repeatability and the content-verifiable write

Only after Phase B PASSes.

```sh
# two DIFFERENT addresses: this is what can detect a stale reply
A9BOOT_LIVE_CONFIRMED=yes ./target/usb/release/a9boot-host firstlight --live --sequence reference \
    --read 0x20c000038:8 --read 0x20c000030:8 --json ../a9pwn-traces/linux/rung2-ref-2.json

# the only step whose result cannot be a stale buffer: the read-back must equal bytes generated
# seconds ago (the per-run seed is recorded in the JSON)
A9BOOT_LIVE_CONFIRMED=yes ./target/usb/release/a9boot-host firstlight --live --sequence reference \
    --write 0x800000000:4096 --json ../a9pwn-traces/linux/rung2-ref-write.json
```

* Two reads to the same address **cannot** detect staleness; the tool says so.
* The 4 KiB write is 2 commands of 2048 data bytes = **2 `DNLOAD` transfers each** — the first
  evidence that a multi-transfer command accumulates correctly, which the whole loader depends on.
  It writes only inside DRAM, and only ever to the address you name (`WriteSpec::parse` refuses
  anything outside `0x8_0000_0000..0x8_8000_0000`).
* PASS = `state=PARSED`, `actual_length == wLength`, read-back verified byte for byte.

---

## 6. Phase D — `probe --only ausb` (read-only, no DRAM write)

```sh
A9BOOT_LIVE_CONFIRMED=yes ./target/usb/release/a9boot-host probe --live --only ausb \
    --json ../a9pwn-traces/linux/rung2-ausb.json
```

This reads `AUSB_CFG0/CFG1` through the same channel and **sends no DRAM write at all**
(`probe_steps_filtered(Some(Ausb), _)` contains no `WriteVerify`; asserted by test). PASS = exit 0 with the tunables recorded (the closing stdout line points at `U-13`); the JSON records
`dram_walk_ran: false`,
`dram_measured: false`, `dram_extent: null`.

**`dram_extent: null` means UNMEASURED, and `0` would not have meant "no DRAM".** The transcript
refuses to print a number it did not measure.

---

## 7. The DRAM walk, and why it stays deferred (U-1 / U-5)

`probe --live --only dram` writes a distinct 32-byte pattern to each of 17 addresses from
`0x8_0000_0000` upward in 128 MiB steps and reads each back.

**Its PASS is not sufficient evidence for a declared DRAM extent, and this is the whole reason the
selector exists.** If the ROM's EL3 context runs with the MMU and D-cache on and maps DRAM as Normal
cacheable, a write followed by a read-back in the same cache line is served by the cache and
"round-trips" on memory that may not exist. Distinct per-address patterns catch **aliasing and
mirroring**; they cannot catch a cache-served illusion. Declaring the extent from that is the exact
failure U-5 describes: corruption, not a panic.

**What CAN be said today:**

* a **FAILURE** at an address is real evidence (no cache invents a failure), and a failure at the
  *first* address is PLAN B (`DESIGN.md` §11.1) and stops the design;
* a **PASS** is evidence that the channel copies bytes correctly, and **not** evidence about how
  much DRAM exists.

**What would settle it, in order of cost:**

1. **our payload's `DESCRIBE`** (`EXEC`) reports `SCTLR_EL3`/`SCTLR_EL1` (U-3/U-4). It needs the
   payload delivered — a later rung, and `EXEC` is itself UNVERIFIED-BY-TEST.
2. **a read-only look at the live EL3 translation tables.** `gaster`'s config for CPID `0x8003`
   puts the ROM's `TTBR0_EL3` tables at `0x1_800C_8000` (`gaster.c:627-631`), an address the exploit
   itself writes through the ROM's `memcpy`, so reading it is a plain `MEMC` read:
   `firstlight --live --sequence reference --read 0x1800c8000:2048 --read 0x1800c8800:2048`
   (a single read is bounded by the channel's 2048-byte read chunk). Decoding it gives the DRAM
   descriptors' `AF` and `AttrIndx`; **partial** evidence — it can rule DRAM *out* (AF clear, or no
   descriptor) but cannot rule cacheability *in*, because `MAIR_EL3` is not readable.
   The address is INSPECTED-from-config, not MEASURED on our unit.
3. **an eviction-pressure experiment** (write more distinct data than the cache can hold, then re-read
   the first address). Expensive in commands, and the failure mode of a wrong guess is the
   corruption U-5 warns about. Do not improvise it.

Until one of those lands, the honest statement is: **DRAM extent UNMEASURED; U-1 unreachable
except as "the walk failed/succeeded"; U-5 open.**

---

## 8. The four quantities every exchange has, and which one is the success criterion

Written down before the first send, so a green run cannot be over-read:

| quantity | where it comes from | role |
|---|---|---|
| **channel** | `bmRequestType`, `bRequest`, `wValue`, `wIndex` | addressing. The resident handler matches `bmRequestType \| bRequest << 8` against `0x2A1` and `wValue` against `0xFFFF`; get it wrong and the request routes to the ROM instead. **Necessary, never sufficient.** |
| **length** | `wLength` | **an input to the device**: the handler reads it back out of the setup packet (`ldrh w2, [x19, #0x6]`) and sends exactly that many bytes from the buffer. |
| **status** | the URB/libusb result (`OK`, `TIMEOUT`, `STALL`, …) | **diagnostic.** A completed transfer with garbage bytes is a FAIL. |
| **actual_length** | bytes actually transferred | **half the success criterion.** On a failed control transfer `rusb`'s synchronous API does not report a partial length, so the evidence records `null` — and a partial reply on a timed-out `UPLOAD` is therefore **not observable** through this API. That limitation is recorded, not papered over. |

**SUCCESS CRITERION: `actual_length == wLength` AND the reply begins with `[DONE_MAGIC][retval]`.**
It is in every JSON as `success_criterion`.

---

## 9. The evidence file

`--json FILE` writes `a9boot.evidence/1`: the exact `dnload_hex` and `upload_hex` (full, not
truncated), their SHA-256s (self-contained implementation, FIPS known-answer tested), `duration_us`
and `start_us` per exchange, `status`, `actual_length`, the parse state with the fault **name**,
the identity **redacted**, the sequence name and its step list, `warnings[]`, `not_proved_by_this_run[]`
and the verdict.

To check it yourself without trusting the tool:

```sh
jq -r '.exchanges[0].request.dnload_hex' FILE | xxd -r -p | sha256sum   # must equal dnload_sha256
jq -r '.exchanges[0].response.upload_hex' FILE | xxd -r -p | sha256sum  # must equal upload_sha256
```

`UNREAD` in a parsed field is a **state**, never a zero: a field that was not read says `UNREAD` or
`null`, so "no data" can never be mistaken for "the value is 0".

---

## 10. What stays UNVERIFIED until you run it

* the whole of `transport/live.rs`: `rusb` open/claim/read, `DNLOAD` chunking, the 7-step order,
  the `GET_STATUS` walk, the reply `UPLOAD` (U-16);
* that `REPLY_OFF = 0x10` inside `0x1_8038_0000` is where the payload writes its reply (INSPECTED
  from the reference handler; the exploit's own `memcpy_addr`/`insecure_memory_base` agree, but the
  channel has never carried our bytes);
* that the reply we get is *ours*: `DONE_MAGIC` is the discriminator and it is INSPECTED;
* the DFU buffer's capacity (U-2), until a multi-transfer command verifies;
* everything in §7 about DRAM; `EXEC`/payload delivery (U-14) entirely.

## 10b. Phase E — the EXEC path, and what it does NOT unlock

```sh
$D exec --live --cmd PING --payload target/aarch64-unknown-none-softfloat/payload/a9boot-payload \
    --sequence reference --json ../a9pwn-traces/linux/rung2-exec-ping.json
```

**Order, and why it is not negotiable:** stage (trigger deferred) → read the staged bytes back →
compare byte for byte → re-stage → trigger. The handler runs whatever the buffer holds the instant
the `0xFFFF` `UPLOAD` arrives, so an unverified jump is a wild jump into SRAM. The read-back
destroys part of what it verified (the reply area overlaps the payload from `base+0x110`), which is
exactly why the sequence re-stages afterwards. If the comparison fails: **exit 9, nothing executed.**

Exact bytes: `EXEC` header at `0x1_8038_0000` (magic `execexec`, `func = 0x1_8038_0110`,
`x0 = command`, `x1 = DESCRIPTOR_ADDR`, `x2 = reply_addr`, `x3 = anchor slot`), payload appended at
`+0x110`: **11,240 bytes = 6 `DNLOAD` transfers** (the payload image measured 10,968 B after the
anchor was added; the runbook's older 10,640 is superseded). Expected reply: `wLength 128`,
`[DONE_MAGIC][retval = 0]`, then a 112-byte `abi::Reply` whose `command` echoes PING and whose
`current_el` is `0xc`.

**PASS cannot be satisfied by a buffer echo**: an echoed buffer begins with our own `EXEC_MAGIC`, so
`DONE_MAGIC` is absent (`REPLY_BAD_MAGIC`); a stale `MEMC` reply has register bytes where `Reply`
belongs, so the `command` echo and `current_el` checks reject it. The PASS rows are in the JSON as
`exec_pass_criterion`.

**What EXEC does NOT unlock — and this re-scopes §12 steps 1, 3 and 4.** Our payload is called by
the resident handler and runs **in the ROM's EL3 context, with the ROM's `TTBR0_EL3`**. It inherits
that translation; it does not get a new one. So EXEC alone does **not** make PMGR (`0x20E0xxxx`) or
DRAM reachable — a `mem_read` of an address the ROM does not map will fault in our payload exactly
as it faulted in the ROM's `memcpy`, and now it takes our payload (and the reply path) with it.
DESCRIBE reports `ttbr0_el3`, which is the *measurement* that says which map we are under.

Therefore the next step after a successful PING is **not** an unguarded `mem_read` of PMGR. It is
one of:
1. `exec --cmd DESCRIBE` — registers only, no memory outside our own buffer. It answers U-3/U-4.
2. A **fault-guarded probe**: a payload command that installs its own `VBAR_EL3` vector, touches the
   address under test, and records `ESR_EL3`/`FAR_EL3` in the reply, restoring `VBAR_EL3` after. An
   unmapped address then becomes a *named result* instead of a dead device. This is the design that
   removes the failure mode that cost us a pwn, and it is the next thing to build.
3. Otherwise: leave PMGR to Linux, which owns its own translation and its own drivers.

## 10b2. Phase G — never read an unmapped address again (the canary + page-table walk)

This replaces the plan's §12 steps 1/3/4 as originally written. Our payload **inherits the ROM's
`TTBR0_EL3`**, so executing our own code does not give us our own address space: a read of an
address the ROM does not map faults in our payload exactly as it faulted in the ROM's `memcpy`, and
takes the reply path with it. That is what cost us a device on `0x20E80110`.

The discipline, in order, and the code enforces it:

1. **Canary** — `firstlight --live --read 0x1800e0f08:32` reads the resident handler's first 32
   bytes. The CPU is *executing* that page on this very request, so it is mapped by definition, and
   the expected bytes come from a file (`exec::HANDLER_FIRST_32_HEX`, 248-byte reference build). A
   match proves SRAM reads work end to end. If the canary fails, nothing else in this phase runs.
2. **Tables + walk, one command:**
   ```sh
   A9BOOT_LIVE_CONFIRMED=yes $D pagewalk --live --lookup 0x800000000 --lookup 0x20e80110 \
       --json ../a9pwn-traces/linux/rung2-pagewalk.json
   ```
   It runs the canary itself (and refuses to read the tables if it fails), reads
   `ROM_TTBR0_TABLES = 0x1_800C_8000` (INSPECTED: `gaster.c:627-631`,
   `ttbr0_addr` for CPID `0x8003`; 512 × 8 bytes per level). It is 96 KiB from the canary and in the
   same SRAM block, which is why the canary comes first.
3. **Walk** — returns `MAPPED`, `NOT_ACCESSIBLE`, `UNMAPPED` or `UNKNOWN`. `may_touch()` is
   `true` only for `MAPPED`, the verdict is FAIL with a `DO NOT TOUCH …` warning otherwise, and
   **the walk refuses to follow a table pointer outside known-mapped SRAM**
   (`TABLE_POINTER_OUTSIDE_KNOWN_MEMORY`) — the instrument cannot fault on a garbage pointer.
4. **Only then** touch the address — and treat `UNKNOWN` as a refusal, not as a pass. "I could not
   read the tables" and "the address is not mapped" are different answers and are spelled
   differently on purpose.

What the walk does **not** claim: it says the *translation* exists. It does not say the memory
behind it exists, and `MAIR_EL3` is not readable through this channel, so no cacheability claim is
made from `AttrIndx` alone. A descriptor with `AF` clear is reported `NOT_ACCESSIBLE` — it still
faults, and calling it mapped would be the same mistake in a different hat.

The fault-guarded probe (install `VBAR_EL3`, touch the address, record `ESR_EL3`/`FAR_EL3`, restore
the vector, verify the restore by reading `VBAR_EL3` back) remains the belt to this braces, and is
the next unit of work: an exception vector that has never executed on hardware is exactly the kind
of thing this project has learned not to point at a device without review.

## 10c. Phase F — the CPU-state anchor (`LOADER-FILL.md` §12 step 1)

```sh
for slot in 0 1 2 3 4; do
  $D exec --live --cmd ANCHOR --payload target/.../a9boot-payload --sequence reference  # x3 = slot
done
```

`_start` saves the entry state **before any Rust code runs**: `x9..x30` (the ROM's own leftovers),
the handler's `SP`, `SPSR_EL3` and `ELR_EL3` — the payload returns them in windows of `ANCHOR_WORDS`
(12) via the reply's tail fields, selected by `x3` (`ANCHOR_REG_WINDOWS = 3`). Windows 3+ read
96 bytes of **the handler's own stack** at `SP + (slot - 3) * 96`: that is the 4 KiB §12 step 1
wants, at an address the ROM chose, with no guessed address anywhere. The host decodes the windows
with `exec::decode_anchor` and names the registers (`ANCHOR_WINDOW_NAMES`). Why the reply and not a
dump address: an anchor written anywhere else would corrupt the buffer it is read from.

## 11. Stop conditions (stop and report, do not experiment)

1. Any `TIMEOUT` on the `UPLOAD` — re-idle, then re-rank hypotheses (S2).
2. `PWND:[checkm8]` absent from the serial at any point.
3. `REPLY_BAD_MAGIC` twice with the same framing.
4. `SUSPECT_STALE_REPLY`.
5. `probe --only dram` failing at the **first** address (PLAN B).
6. Anything that would write outside `0x8_0000_0000..0x8_8000_0000` or outside the DFU buffer.

---

## 12. Known spec-vs-code gaps (found by the adversarial review, kept visible)

These are places where a document promises more than the code does. None of them affects the first
exchange; all of them would mislead a later reader, so they are recorded here rather than left in
the dark:

1. **The DFU buffer-capacity probe (U-2) is not implemented.** `DESIGN.md` §3.4/§3.5 and
   `UNVERIFIED.md` U-2 describe a write/read-back capacity ladder and a command-line parameter for
   it; `probe_steps()` has no such step and `TransferBudget::from_probe` has **no callers** — every
   path uses the assumed 16 KiB. The capacity is therefore still UNVERIFIED, and the 4 KiB
   `--write` in Phase C is the first thing that tests it above 2 KiB.
2. **U-13's falsifier says "two reads, non-zero and equal"; the code does one read.**
   `AusbTunables::looks_plausible` checks non-zero/non-all-ones only. Two `--read` options are the
   manual way to do it today.
3. **`DESIGN.md` §2.4's `probe(len)` and `ident()` operations do not exist in `channel.rs`**
   (EXEC/MEMC read/write only; identity is `check_identity` on the serial descriptor).
4. **`DESIGN.md` §2.3's "+0x48.. payload data" is the MEMC case only**; EXEC appends the payload at
   `0x110` (`abi.rs:77`), which is why the two packet builders size the header differently.
5. Test count in older docs says 75; it is **35 + 95** today.

Anything a reader needs to trust must come from a JSON `state: PARSED` with
`actual_length == wLength`, not from a summary in prose.
