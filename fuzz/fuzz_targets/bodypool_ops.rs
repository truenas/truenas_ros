#![no_main]

//! Fuzz the body pool's byte law under an arbitrary sequence of claims
//! and gives. After every operation the pool re-derives its figures
//! from its lists and asserts they agree, nothing is retained past the
//! target or the target past the budget, and every buffer handed out is
//! empty and at least the size asked.

use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use truenas_ros::net::server::fuzz::BodyPool;
use truenas_ros::net::server::{FIXED_RECORD, Fixed};

#[derive(Debug)]
enum Op {
    /// A consumer claim, windowed licence.
    Claim(u8),
    /// A consumer give of the `n`th held Vec.
    Give(u8),
    /// A reactor claim, held licence.
    ClaimHeld(u8),
    /// The `n`th held reactor Vec goes home with its licence.
    GiveHeld(u8),
    /// The `n`th held reactor Vec is delivered: its licence moves to the
    /// pot and the Vec leaves through the consumer's recycle (or not).
    Deliver(u8, bool),
    /// A give of storage the pool never issued: unlicensed.
    GiveFresh(u8),
    /// A record.
    ClaimFixed,
    /// The `n`th fixed buffer is dropped, on this thread.
    DropFixed(u8),
    /// The `n`th fixed buffer is dropped on another thread.
    DropFixedElsewhere(u8),
    Drain,
    Tick,
}

// By hand: the derive needs `arbitrary`'s `derive` feature.
impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Op> {
        Ok(match u8::arbitrary(u)? % 11 {
            0 => Op::Claim(u8::arbitrary(u)?),
            1 => Op::Give(u8::arbitrary(u)?),
            2 => Op::ClaimHeld(u8::arbitrary(u)?),
            3 => Op::GiveHeld(u8::arbitrary(u)?),
            4 => Op::Deliver(u8::arbitrary(u)?, bool::arbitrary(u)?),
            5 => Op::GiveFresh(u8::arbitrary(u)?),
            6 => Op::ClaimFixed,
            7 => Op::DropFixed(u8::arbitrary(u)?),
            8 => Op::DropFixedElsewhere(u8::arbitrary(u)?),
            9 => Op::Drain,
            _ => Op::Tick,
        })
    }
}

/// Claim sizes in 16 KiB steps up to 4 MiB.
fn size(k: u8) -> usize {
    (usize::from(k) + 1) * 16 * 1024
}

fn take<T>(v: &mut Vec<T>, n: u8) -> Option<T> {
    if v.is_empty() {
        return None;
    }
    Some(v.swap_remove(usize::from(n) % v.len()))
}

fuzz_target!(|input: (u8, Vec<Op>)| {
    let (budget, ops) = input;
    // 1 MiB .. 16 MiB.
    let budget = (usize::from(budget) % 16 + 1) << 20;
    let mut p = BodyPool::new(budget);
    let mut consumer: Vec<Vec<u8>> = Vec::new();
    let mut reactor: Vec<(Vec<u8>, usize)> = Vec::new();
    let mut fixed: Vec<Fixed> = Vec::new();
    for op in ops.into_iter().take(256) {
        match op {
            Op::Claim(k) => {
                let want = size(k);
                let v = p.claim(want);
                assert!(v.is_empty() && v.capacity() >= want);
                if consumer.len() < 32 {
                    consumer.push(v);
                }
            }
            Op::Give(n) => {
                if let Some(v) = take(&mut consumer, n) {
                    p.give(v);
                }
            }
            Op::ClaimHeld(k) => {
                let want = size(k);
                let (v, licence) = p.claim_held(want);
                assert!(v.is_empty() && v.capacity() >= want);
                assert!(
                    licence == 0 || licence == want,
                    "a licence is the ask or nothing"
                );
                if reactor.len() < 32 {
                    reactor.push((v, licence));
                }
            }
            Op::GiveHeld(n) => {
                if let Some((v, licence)) = take(&mut reactor, n) {
                    p.give_held(v, licence);
                }
            }
            Op::Deliver(n, recycled) => {
                if let Some((v, licence)) = take(&mut reactor, n) {
                    p.receipt_done(licence);
                    if recycled {
                        p.give(v);
                    }
                }
            }
            Op::GiveFresh(k) => {
                let mut v = Vec::new();
                v.reserve_exact(size(k));
                p.give(v);
            }
            Op::ClaimFixed => {
                let f = p.claim_fixed().expect("the allocator serves a test");
                assert!(f.is_empty() && f.slot().is_none());
                assert_eq!(f.capacity(), FIXED_RECORD);
                if fixed.len() < 16 {
                    fixed.push(f);
                }
            }
            Op::DropFixed(n) => drop(take(&mut fixed, n)),
            Op::DropFixedElsewhere(n) => {
                if let Some(f) = take(&mut fixed, n) {
                    std::thread::spawn(move || drop(f)).join().expect("joins");
                }
            }
            Op::Drain => p.drain_returns(),
            Op::Tick => p.rebalance(),
        }
        p.check();
        assert!(p.retained() <= budget);
    }
    // Everything comes home.
    for v in consumer.drain(..) {
        p.give(v);
    }
    for (v, licence) in reactor.drain(..) {
        p.give_held(v, licence);
    }
    fixed.clear();
    p.drain_returns();
    p.check();
    for _ in 0..8 {
        p.rebalance();
        p.check();
    }
});
