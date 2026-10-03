//! The cache-safe DRAM walk (`LOADER-FILL.md` §2/§12 step 4, UNVERIFIED.md U-1/U-5).
//!
//! ## The false positive this exists to prevent
//!
//! A write followed by a read-back **in the same cache line** is served by the cache. On a mapping
//! the ROM declared Normal-cacheable, that "round-trips" on memory that may not exist, and the
//! loader would declare an extent it cannot back — which is the corruption case, not the panic
//! case (`LOADER-FILL.md` §2). Distinct patterns per address catch aliasing and mirroring; they do
//! **not** catch this.
//!
//! ## The rule, as an ordered sequence of operations
//!
//! Every sample is exactly these six operations, in this order, and the order is asserted:
//!
//! 1. `write` the sample's own pattern to the address (`STR`/`STP`);
//! 2. `dc cvac` each line of the sample — clean by VA to the point of coherency, so the line is
//!    written **out** of the D-cache before anyone reads it;
//! 3. `dsb sy` — the clean must have completed, not merely been issued;
//! 4. `dc ivac` each line — invalidate the same lines, so a read **cannot** be served by the copy
//!    that is still in the cache;
//! 5. `dsb sy` — the invalidate must have completed;
//! 6. `read` the sample back and compare.
//!
//! With 2–5 in place a matching read-back is evidence about *memory*. Without them it is evidence
//! about the cache, which is what the previous plan would have reported.
//!
//! ## What the walk proves, and what it does not
//!
//! **Does prove:** each sampled address accepts a write and returns it after the cache has been
//! pushed out and invalidated — so the memory behind the sampled address exists and holds data.
//! **Does not prove:** that the extent is contiguous (only samples are tested); that memory between
//! samples exists; that the *next* stage (Linux, with its own translation and caching) sees the
//! same thing; that a failure at one sample means everything above it fails (the ladder stops, it
//! does not map). A failure is strong evidence; a pass is a lower bound, exactly like the capacity
//! ladder.
//!
//! ## The negative control
//!
//! The walk must be shown to **report absence**. Two ways, and both are implemented: the
//! `a9boot-payload` walk uses the same ordered table below, and the host-side test drives the
//! sequence over a device model whose DRAM is unreachable — the walk must come back `Absent` for
//! every sample and must never report a pass. Before the walk touches DRAM at all it runs the same
//! six operations on **the DFU buffer itself**: known-good SRAM whose contents we can read back
//! through the channel. If the self-test fails, the walk reports `SelfTestFailed` and declares
//! nothing — a walk that cannot say "yes" anywhere cannot be trusted to say "no".

use a9boot_core::layout::{DRAM_BASE, DRAM_SIZE};

/// One operation in a sample. The order in [`sample_ops`] is the contract, and the test pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkOp {
    /// Write the sample's pattern.
    Write,
    /// `dc cvac` each line: clean to the point of coherency.
    CleanToPoc,
    /// `dsb sy`.
    BarrierAfterClean,
    /// `dc ivac` each line: invalidate, so the read must come from memory.
    Invalidate,
    /// `dsb sy`.
    BarrierAfterInvalidate,
    /// Read back and compare.
    ReadVerify,
}

/// The six operations, in the only order that makes a pass mean anything.
pub const WALK_SAMPLE_OPS: [WalkOp; 6] = [
    WalkOp::Write,
    WalkOp::CleanToPoc,
    WalkOp::BarrierAfterClean,
    WalkOp::Invalidate,
    WalkOp::BarrierAfterInvalidate,
    WalkOp::ReadVerify,
];

/// The cache line the A9 (Twister) uses, matching `a9boot_payload::el::CACHE_LINE`.
pub const CACHE_LINE: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub addr: u64,
    pub len: usize,
    /// Seed for this sample's pattern: distinct per address, so a shifted or aliased read is a
    /// mismatch rather than a lucky match.
    pub seed: u8,
}

/// The 128 MiB-step walk from `DRAM_BASE` to the end of the nominal range, plus the last 32 bytes —
/// the same set `bundle::dram_walk_addresses()` uses, so there is one ladder in the project.
pub fn samples(step: u64, sample_len: usize) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut a = DRAM_BASE;
    let mut seed = 0u8;
    while a < DRAM_BASE + DRAM_SIZE {
        out.push(Sample { addr: a, len: sample_len, seed });
        a += step;
        seed = seed.wrapping_add(1);
    }
    out.push(Sample { addr: DRAM_BASE + DRAM_SIZE - 0x20, len: sample_len.min(0x20), seed });
    out
}

/// The default walk: 128 MiB steps, a 64-byte sample (one cache line) per step.
pub fn default_samples() -> Vec<Sample> {
    samples(0x0800_0000, CACHE_LINE as usize)
}

/// Per-sample pattern, derived from the seed *and the address*, so two samples cannot collide and
/// a sample read at the wrong address cannot match by accident.
pub fn sample_pattern(s: &Sample) -> Vec<u8> {
    let a = s.addr.to_le_bytes();
    (0..s.len)
        .map(|i| {
            a[i % 8]
                .wrapping_mul(37)
                .wrapping_add(s.seed)
                .wrapping_add((i as u8).wrapping_mul(0x11))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleOutcome {
    /// Wrote, cleaned, invalidated, read back, matched: the memory is real.
    Present,
    /// The read-back did not match: either the memory is absent or it mangled the data. Both mean
    /// "do not declare this address".
    Absent,
    /// The access faulted (reported by the fault-guarded probe). Same conclusion, different name.
    Faulted,
}

impl SampleOutcome {
    pub fn name(self) -> &'static str {
        match self {
            SampleOutcome::Present => "DRAM_SAMPLE_PRESENT",
            SampleOutcome::Absent => "DRAM_SAMPLE_ABSENT",
            SampleOutcome::Faulted => "DRAM_SAMPLE_FAULTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkReport {
    pub samples: Vec<(u64, SampleOutcome)>,
    pub self_test_ok: bool,
    /// Last address that came back present. **A lower bound on the contiguous extent only if
    /// every sample below it was present** — which `contiguous_from_base` checks rather than
    /// assumes.
    pub last_present: Option<u64>,
    pub first_absent: Option<u64>,
}

impl WalkReport {
    /// The extent that may be declared: `0` unless the self-test passed and **every** sample from
    /// `DRAM_BASE` up to the last present one was present. A hole stops the declaration at the
    /// hole, because over-declaring corrupts rather than panics.
    pub fn declared_extent(&self) -> u64 {
        if !self.self_test_ok {
            return 0;
        }
        let mut extent = 0;
        for (addr, outcome) in &self.samples {
            if *outcome == SampleOutcome::Present {
                extent = (addr - DRAM_BASE) + 0x20;
            } else {
                break;
            }
        }
        extent.min(DRAM_SIZE)
    }

    /// What the walk proved, in the words the evidence file uses.
    pub fn declaration(&self) -> String {
        if !self.self_test_ok {
            return "DRAM extent: UNMEASURED — the walk's self-test on the DFU buffer failed, so it \
                    cannot say 'present' anywhere and its 'absent' answers mean nothing either. \
                    Nothing is declared."
                .to_string();
        }
        match self.first_absent {
            None => format!(
                "DRAM extent \u{2265} {:#x} ({} MiB): every sample came back present after clean + \
                 invalidate. A LOWER BOUND, not the size of DRAM: only the sampled addresses were \
                 tested.",
                self.declared_extent(),
                self.declared_extent() / (1024 * 1024)
            ),
            Some(a) => format!(
                "DRAM extent {:#x} ({} MiB), first absent sample at {a:#x}. Declare no more than \
                 the last present sample: over-declaring hands the kernel dead pages and corrupts \
                 rather than panics (LOADER-FILL.md §2).",
                self.declared_extent(),
                self.declared_extent() / (1024 * 1024)
            ),
        }
    }

    /// The things a reader must not infer from this.
    pub fn does_not_prove() -> &'static [&'static str] {
        &[
            "that DRAM between the samples exists (only samples are tested; the step is 128 MiB)",
            "that the address is not an alias of another sample (a distinct per-address pattern \
             catches simple aliasing, not a full alias map)",
            "that a later stage — Linux, with its own translation and cache attributes — will see \
             the same extent",
            "that a failure at one sample means every address above it fails (the walk stops; it \
             does not map)",
            "that the ROM's EL3 translation covers DRAM at all, beyond the samples it walked",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sample_cleans_and_invalidates_between_the_write_and_the_verify() {
        // This ordering IS the false-positive fix. If an edit moves the invalidate before the
        // clean, or drops the second barrier, a cache-served read-back becomes a "pass" again and
        // the walk declares DRAM that does not exist.
        assert_eq!(
            WALK_SAMPLE_OPS,
            [
                WalkOp::Write,
                WalkOp::CleanToPoc,
                WalkOp::BarrierAfterClean,
                WalkOp::Invalidate,
                WalkOp::BarrierAfterInvalidate,
                WalkOp::ReadVerify,
            ]
        );
        let pos = |op: WalkOp| WALK_SAMPLE_OPS.iter().position(|o| *o == op).unwrap();
        assert!(pos(WalkOp::Write) < pos(WalkOp::CleanToPoc));
        assert!(pos(WalkOp::CleanToPoc) < pos(WalkOp::BarrierAfterClean));
        assert!(pos(WalkOp::BarrierAfterClean) < pos(WalkOp::Invalidate));
        assert!(pos(WalkOp::Invalidate) < pos(WalkOp::BarrierAfterInvalidate));
        assert!(pos(WalkOp::BarrierAfterInvalidate) < pos(WalkOp::ReadVerify));
    }

    #[test]
    fn patterns_are_distinct_per_address_and_not_constant() {
        let s = default_samples();
        assert!(s.len() >= 17);
        assert_eq!(s[0].addr, DRAM_BASE);
        let p0 = sample_pattern(&s[0]);
        let p1 = sample_pattern(&s[1]);
        assert_ne!(p0, p1, "two samples must not share a pattern");
        assert_eq!(p0.len(), CACHE_LINE as usize);
        assert!(p0.chunks(2).any(|c| c[0] != c[1]), "not constant");
        // The same address is stable: the walk is reproducible for a given sample set.
        assert_eq!(p0, sample_pattern(&s[0]));
    }

    #[test]
    fn negative_control_absence_declares_nothing_and_stops_at_the_hole() {
        // The walk's job when the memory is not there: say so, and declare nothing above it.
        let w = WalkReport {
            samples: vec![
                (DRAM_BASE, SampleOutcome::Present),
                (DRAM_BASE + 0x0800_0000, SampleOutcome::Present),
                (DRAM_BASE + 0x1000_0000, SampleOutcome::Absent),
                (DRAM_BASE + 0x1800_0000, SampleOutcome::Present),
            ],
            self_test_ok: true,
            last_present: Some(DRAM_BASE + 0x1800_0000),
            first_absent: Some(DRAM_BASE + 0x1000_0000),
        };
        // Even though a later sample passed, the declaration stops at the hole: the extent is the
        // last present sample plus its length, and nothing above the hole counts.
        assert_eq!(w.declared_extent(), 0x0800_0000 + 0x20);
        let d = w.declaration();
        assert!(d.contains("first absent sample"), "{d}");
        assert!(d.contains("corrupts rather than panics"), "{d}");
        assert_eq!(SampleOutcome::Absent.name(), "DRAM_SAMPLE_ABSENT");
        assert!(WalkReport::does_not_prove().iter().any(|s| s.contains("alias")));
    }

    #[test]
    fn negative_control_a_failed_self_test_declares_nothing_at_all() {
        // If the walk cannot say "present" on known-good memory, its "absent" answers carry no
        // information either — and it must not quietly declare zero as if zero were a measurement.
        let w = WalkReport {
            samples: vec![(DRAM_BASE, SampleOutcome::Absent)],
            self_test_ok: false,
            last_present: None,
            first_absent: Some(DRAM_BASE),
        };
        assert_eq!(w.declared_extent(), 0);
        assert!(w.declaration().contains("UNMEASURED"), "{}", w.declaration());
    }

    #[test]
    fn a_full_pass_is_a_lower_bound_and_says_so() {
        let mut samples = Vec::new();
        let mut a = DRAM_BASE;
        while a < DRAM_BASE + DRAM_SIZE {
            samples.push((a, SampleOutcome::Present));
            a += 0x0800_0000;
        }
        // The walk's own tail sample (`samples()`), which is what makes the extent reach the end.
        samples.push((DRAM_BASE + DRAM_SIZE - 0x20, SampleOutcome::Present));
        let w = WalkReport {
            last_present: samples.last().map(|(a, _)| *a),
            samples,
            self_test_ok: true,
            first_absent: None,
        };
        assert_eq!(w.declared_extent(), DRAM_SIZE);
        let d = w.declaration();
        assert!(d.contains("LOWER BOUND"), "{d}");
        assert!(d.contains("only the sampled addresses were tested"), "{d}");
    }
}
