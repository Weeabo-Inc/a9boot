//! The timeout-bounded access: **a read that does not answer must leave the device recoverable.**
//!
//! ## Why this is the prerequisite for every remaining hardware step
//!
//! PMGR (`0x20E80110`) got no reply at all, EP0 wedged, and the recovery reset dropped the phone.
//! If the ROM runs with translation off — which is what `--find-root` found nothing to contradict,
//! and what a SecureROM normally does — then that was not a translation fault at all. It was an
//! **unclocked MMIO access, which hangs the bus**: no exception fires, no vector can catch it, and
//! no page-table walk can predict it. The transaction simply never completes.
//!
//! So the guard cannot be a fault handler. It has to bound the *waiting*:
//!
//! 1. try the access with a short per-attempt timeout;
//! 2. if it does not answer, try again with a longer one — a device that is merely slow is not a
//!    device that is hung;
//! 3. if the longest attempt does not answer, **stop, name the address, and declare nothing**;
//! 4. never retry past the deadline, because on this bootrom a cancelled control transfer can wedge
//!    EP0 (`RUNG1-EVIDENCE.md` §3) — the thing that lost the device last time was not the hang but
//!    the recovery.
//!
//! The property this module provides is deliberately modest and checkable: **the tool says by name
//! that it stopped, and a hung address is never reported as a value.** Whether the device is
//! *recoverable* afterwards is a separate question and is recorded as such — the bounded attempt
//! minimises the damage; it does not promise the pwn survives.

use std::time::{Duration, Instant};

/// A ladder of per-attempt timeouts, increasing. The default is short-then-generous, because the
/// interesting case is a device that answers *fast* or not at all.
pub const DEFAULT_LADDER_MS: [u64; 3] = [50, 250, 1000];

/// What a bounded access concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bounded<T> {
    /// The device answered — with whatever it answered, which the caller still has to verify. This
    /// type says "a reply arrived", never "the reply is right".
    Answered { value: T, attempts: usize, waited_ms: u64 },
    /// No attempt answered. `detail` carries the transport's own words, and the caller must treat
    /// this as **the answer to "may I read this?"**, not as a transport hiccup.
    NoAnswer { attempts: usize, waited_ms: u64, detail: String },
}

impl<T> Bounded<T> {
    pub fn name(&self) -> &'static str {
        match self {
            Bounded::Answered { .. } => "BOUNDED_ANSWERED",
            Bounded::NoAnswer { .. } => "BOUNDED_NO_ANSWER",
        }
    }

    /// The operator-facing sentence. `addr` is included because "the device did not answer" without
    /// the address is not a diagnosis.
    pub fn report(&self, addr: u64, what: &str) -> String {
        match self {
            Bounded::Answered { attempts, waited_ms, .. } => format!(
                "BOUNDED_ANSWERED: {what} at {addr:#x} answered on attempt {attempts} after \
                 ~{waited_ms} ms. That is a reply, not a verification: the caller still checks the \
                 bytes."
            ),
            Bounded::NoAnswer { attempts, waited_ms, detail } => format!(
                "BOUNDED_NO_ANSWER: {what} at {addr:#x} did not answer in {attempts} attempt(s) \
                 over ~{waited_ms} ms ({detail}). Treat {addr:#x} as UNREADABLE AND STOP: this is \
                 the shape of an unclocked-MMIO hang (RUNG2-EVIDENCE.md §3), and no fault guard can \
                 catch it. Do not retry past the deadline, and do not probe further addresses in \
                 this session until the state has been re-read."
            ),
        }
    }
}

/// Run one access under an increasing timeout ladder, stopping at the first answer.
///
/// `set_timeout(ms)` applies the attempt's timeout; `attempt()` performs exactly one access and
/// returns `Ok` only if the transport completed it. **`attempt` is called at most `ladder.len()`
/// times**, which is the whole safety property: the number of cancelled transfers is bounded, and
/// the caller learns how many happened.
pub fn ladder<T, S, A>(ladder_ms: &[u64], mut set_timeout: S, mut attempt: A) -> Bounded<T>
where
    S: FnMut(u64),
    A: FnMut() -> Result<T, String>,
{
    let start = Instant::now();
    let mut last = String::new();
    let mut attempts = 0usize;
    for ms in ladder_ms {
        set_timeout(*ms);
        attempts += 1;
        match attempt() {
            Ok(v) => {
                return Bounded::Answered {
                    value: v,
                    attempts,
                    waited_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => last = e,
        }
    }
    Bounded::NoAnswer {
        attempts,
        waited_ms: start.elapsed().as_millis() as u64,
        detail: last,
    }
}

/// The default ladder, as a `Duration` list for a transport that wants durations.
pub fn default_ladder() -> Vec<Duration> {
    DEFAULT_LADDER_MS.iter().map(|ms| Duration::from_millis(*ms)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_slow_device_is_given_a_longer_attempt_and_then_answers() {
        // The ladder's job: "slow" and "hung" must be distinguished before the session is written
        // off. Attempt 1 times out, attempt 2 answers.
        let tries = Cell::new(0);
        let timeouts = std::cell::RefCell::new(Vec::new());
        let r = ladder(
            &DEFAULT_LADDER_MS,
            |ms| timeouts.borrow_mut().push(ms),
            || {
                tries.set(tries.get() + 1);
                if tries.get() < 2 {
                    Err("LIBUSB TIMEOUT".to_string())
                } else {
                    Ok(vec![0xde, 0xad])
                }
            },
        );
        match r {
            Bounded::Answered { value, attempts, .. } => {
                assert_eq!(value, vec![0xde, 0xad]);
                assert_eq!(attempts, 2);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(*timeouts.borrow(), vec![50, 250], "each attempt gets its own timeout");
    }

    #[test]
    fn negative_control_an_address_that_never_answers_stops_the_ladder_and_is_named() {
        // The PMGR shape: no reply, ever. The access must stop after a BOUNDED number of attempts,
        // say so by name, and never hand back a value.
        let tries = Cell::new(0);
        let r: Bounded<Vec<u8>> = ladder(&DEFAULT_LADDER_MS, |_| {}, || {
            tries.set(tries.get() + 1);
            Err("LIBUSB TIMEOUT".to_string())
        });
        assert_eq!(tries.get(), DEFAULT_LADDER_MS.len(), "attempts are bounded by the ladder");
        let rep = r.report(0x20E8_0110, "memc read len 4");
        assert!(rep.contains("BOUNDED_NO_ANSWER"), "{rep}");
        assert!(rep.contains("0x20e80110"), "{rep}");
        assert!(rep.contains("unclocked-MMIO hang"), "{rep}");
        assert!(rep.contains("Do not retry past the deadline"), "{rep}");
        assert_eq!(r.name(), "BOUNDED_NO_ANSWER");
        assert!(matches!(r, Bounded::NoAnswer { .. }), "no value may be returned");
    }

    #[test]
    fn a_single_short_ladder_bounds_the_cancelled_transfers() {
        // The safety quantity is the number of cancelled transfers (each can wedge EP0), so a
        // one-rung ladder must produce exactly one attempt.
        let tries = Cell::new(0);
        let _: Bounded<()> = ladder(&[25], |_| {}, || {
            tries.set(tries.get() + 1);
            Err("timeout".into())
        });
        assert_eq!(tries.get(), 1);
    }
}
