//! A keyed cache whose misses are minted exactly once, however many callers
//! race for the same key.
//!
//! Separate from [`IdentityCache`](super::IdentityCache) so it can be
//! model-checked: minting a personality is IPC to a forked child, which loom
//! cannot run, but the map/gate/cell protocol around it is ordinary shared
//! memory. The models take the mint as a closure.

use std::collections::HashMap;
use std::hash::Hash;

use crate::errno::Errno;
use crate::sync::{Arc, Mutex, OnceCell};

/// One key's slot: the value once minted, plus a gate that serializes the
/// callers who arrive while it is still empty.
#[derive(Debug)]
struct Slot<V> {
    cell: OnceCell<V>,
    gate: Mutex<()>,
}

impl<V> Slot<V> {
    fn empty() -> Slot<V> {
        Slot {
            cell: OnceCell::new(),
            gate: Mutex::new(()),
        }
    }
}

/// Values minted on demand, one mint per key.
#[derive(Debug)]
pub(super) struct SingleFlight<K, V> {
    live: Mutex<HashMap<K, Arc<Slot<V>>>>,
}

impl<K: Clone + Eq + Hash, V: Clone> SingleFlight<K, V> {
    pub(super) fn new() -> SingleFlight<K, V> {
        SingleFlight {
            live: Mutex::new(HashMap::new()),
        }
    }

    /// The value for `key`, minting it with `mint` if this is the first live
    /// use of that key.
    ///
    /// The shared map lock is held only for O(1) slot lookups, never across
    /// `mint`, so a hit on one key and a mint on another do not block each
    /// other. Callers racing for the *same* absent key serialize on that key's
    /// gate and exactly one of them runs `mint`.
    ///
    /// A failed mint leaves nothing behind: nothing else removes an empty
    /// slot, so a caller whose mints keep failing would grow the map without
    /// bound.
    pub(super) fn get_or_try_init(
        &self,
        key: &K,
        mint: impl FnOnce() -> crate::Result<V>,
    ) -> crate::Result<V> {
        // `mint` runs at most once, but the slot we mint on may be evicted
        // out from under us before we reach it (see the re-check below), so
        // hold it in an `Option` and retry onto the map's current slot.
        let mut mint = Some(mint);
        loop {
            let slot = {
                let mut live = self.live.lock().map_err(|_| Errno::EIO)?;
                live.entry(key.clone())
                    .or_insert_with(|| Arc::new(Slot::empty()))
                    .clone()
            };
            // Fast path: already minted - no gate, no mint.
            if let Some(v) = slot.cell.with(V::clone) {
                return Ok(v);
            }
            // Re-check under the gate: a racing caller may have filled the
            // cell while we waited, and re-minting is a second registration.
            let _mint = slot.gate.lock().map_err(|_| Errno::EIO)?;
            if let Some(v) = slot.cell.with(V::clone) {
                return Ok(v);
            }
            // Confirm the map still holds *this* slot before minting on it. A
            // failed mint evicts its slot, and a caller arriving after that
            // installs a fresh one - so a slot cloned before the eviction is
            // now orphaned, and minting on it would let the map's current
            // slot mint the key a second time. Restart onto the current slot
            // instead; its fast path or gate then joins that mint rather than
            // duplicating it.
            {
                let live = self.live.lock().map_err(|_| Errno::EIO)?;
                if !live.get(key).is_some_and(|s| Arc::ptr_eq(s, &slot)) {
                    continue;
                }
            }
            let value = match (mint.take().expect("mint runs at most once"))() {
                Ok(v) => v,
                Err(e) => {
                    // Only if the map still holds *this* slot - a concurrent
                    // `invalidate` may have replaced it, and that one is not
                    // ours to drop.
                    if let Ok(mut live) = self.live.lock()
                        && live.get(key).is_some_and(|s| Arc::ptr_eq(s, &slot))
                    {
                        live.remove(key);
                    }
                    return Err(e);
                }
            };
            // Cannot fail: the gate is held and the re-check found it empty.
            slot.cell.set(value.clone());
            // Confirmed above to be the map's slot, and the gate we hold keeps
            // eviction-on-failure of it out, so this re-affirms rather than
            // races a replacement. `or_insert_with` so a newer slot still wins
            // if an `invalidate` replaced it during the mint.
            if let Ok(mut live) = self.live.lock() {
                live.entry(key.clone()).or_insert_with(|| slot.clone());
            }
            return Ok(value);
        }
    }

    /// Forget `key`, so the next [`get_or_try_init`](Self::get_or_try_init)
    /// mints again. A value already handed out is unaffected.
    pub(super) fn invalidate(&self, key: &K) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(key);
        }
    }

    /// Forget every key.
    pub(super) fn clear(&self) {
        if let Ok(mut live) = self.live.lock() {
            live.clear();
        }
    }

    /// How many keys are minted and cached. A mint still in flight does not
    /// count; one that failed left nothing to count.
    pub(super) fn len(&self) -> usize {
        self.live
            .lock()
            .map(|m| m.values().filter(|s| s.cell.is_set()).count())
            .unwrap_or(0)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn sf() -> SingleFlight<u32, u32> {
        SingleFlight::new()
    }

    #[test]
    fn a_hit_does_not_mint_again() {
        let s = sf();
        assert_eq!(s.get_or_try_init(&1, || Ok(10)).unwrap(), 10);
        assert_eq!(
            s.get_or_try_init(&1, || panic!("minted twice")).unwrap(),
            10
        );
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn a_failed_mint_leaves_nothing_behind() {
        let s = sf();
        for _ in 0..3 {
            assert!(s.get_or_try_init(&1, || Err(Errno::EIO.into())).is_err());
            assert_eq!(s.len(), 0, "a failed mint kept its slot");
        }
        // And the key is still mintable afterwards.
        assert_eq!(s.get_or_try_init(&1, || Ok(7)).unwrap(), 7);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn invalidate_forces_the_next_mint() {
        let s = sf();
        assert_eq!(s.get_or_try_init(&1, || Ok(10)).unwrap(), 10);
        s.invalidate(&1);
        assert_eq!(s.len(), 0);
        assert_eq!(s.get_or_try_init(&1, || Ok(11)).unwrap(), 11);
        s.clear();
        assert_eq!(s.len(), 0);
    }
}

#[cfg(loom)]
mod loom_tests {
    use super::*;
    use crate::sync::thread;

    /// Two threads, three with main - loom caps a model at 5. The preemption
    /// bound makes these bounded rather than exhaustive.
    fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(f);
    }

    /// A counter for how many times a mint closure actually ran.
    fn counter() -> Arc<Mutex<u32>> {
        Arc::new(Mutex::new(0))
    }

    fn bump(c: &Arc<Mutex<u32>>) {
        *c.lock().unwrap() += 1;
    }

    fn count(c: &Arc<Mutex<u32>>) -> u32 {
        *c.lock().unwrap()
    }

    /// However two callers for one absent key interleave, it is minted once
    /// and both see that value.
    ///
    /// Negative control: delete the re-check under the gate.
    #[test]
    fn loom_single_flight_mints_once() {
        bounded_model(|| {
            let s: Arc<SingleFlight<u32, u32>> = Arc::new(SingleFlight::new());
            let mints = counter();

            let (s1, c1) = (s.clone(), mints.clone());
            let t1 = thread::spawn(move || {
                s1.get_or_try_init(&1, || {
                    bump(&c1);
                    Ok(42)
                })
            });
            let (s2, c2) = (s.clone(), mints.clone());
            let t2 = thread::spawn(move || {
                s2.get_or_try_init(&1, || {
                    bump(&c2);
                    Ok(42)
                })
            });

            assert_eq!(t1.join().unwrap().unwrap(), 42);
            assert_eq!(t2.join().unwrap().unwrap(), 42);
            assert_eq!(count(&mints), 1, "one key minted more than once");
            assert_eq!(s.len(), 1);
        });
    }

    /// A failing mint must not evict a slot a concurrent mint is about to
    /// fill. Checked from the far side: once both callers are done, a third
    /// lookup is a hit.
    ///
    /// Negative control: delete the re-install in `get_or_try_init`.
    #[test]
    fn loom_a_failed_mint_does_not_orphan_a_successful_one() {
        bounded_model(|| {
            let s: Arc<SingleFlight<u32, u32>> = Arc::new(SingleFlight::new());
            let mints = counter();

            let s1 = s.clone();
            let t1 = thread::spawn(move || {
                let _ = s1.get_or_try_init(&1, || Err(Errno::EIO.into()));
            });
            let (s2, c2) = (s.clone(), mints.clone());
            let t2 = thread::spawn(move || {
                s2.get_or_try_init(&1, || {
                    bump(&c2);
                    Ok(42)
                })
            });

            t1.join().unwrap();
            let got = t2.join().unwrap().unwrap();
            assert_eq!(got, 42);

            // A different value, so a miss shows in the value as well as
            // the count.
            let again = s
                .get_or_try_init(&1, || {
                    bump(&mints);
                    Ok(99)
                })
                .unwrap();
            assert_eq!(again, 42, "a live value was orphaned by a failed mint");
            assert_eq!(count(&mints), 1, "one key minted more than once");
        });
    }

    /// The double-mint a two-thread model cannot reach: a failing mint evicts
    /// its slot, a second caller is still queued on it, and a third arrives
    /// after the eviction and installs a fresh slot. Even then the key is
    /// minted at most once, and one live value remains.
    ///
    /// Negative control: delete the slot-identity re-check under the gate.
    #[test]
    fn loom_a_failed_mint_cannot_double_mint() {
        bounded_model(|| {
            let s: Arc<SingleFlight<u32, u32>> = Arc::new(SingleFlight::new());
            let mints = counter();

            let s1 = s.clone();
            let a = thread::spawn(move || {
                let _ = s1.get_or_try_init(&1, || Err(Errno::EIO.into()));
            });
            let (s2, c2) = (s.clone(), mints.clone());
            let b = thread::spawn(move || {
                let _ = s2.get_or_try_init(&1, || {
                    bump(&c2);
                    Ok(42)
                });
            });
            let (s3, c3) = (s.clone(), mints.clone());
            let c = thread::spawn(move || {
                let _ = s3.get_or_try_init(&1, || {
                    bump(&c3);
                    Ok(42)
                });
            });

            a.join().unwrap();
            b.join().unwrap();
            c.join().unwrap();
            assert!(count(&mints) <= 1, "key minted {} times", count(&mints));
            assert_eq!(s.len(), 1, "the minted value must remain live");
        });
    }
}
