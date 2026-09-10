//! The deferred, tick-batched submission queue.
//!
//! [`queue_bulk`](crate::ApiClient::queue_bulk) appends one call's
//! arguments here and returns at once; nothing touches the wire until the
//! next tick, when every method with queued items goes out as a single
//! `core.bulk` call. That is the anti-overload path: background work that
//! would otherwise be a request per item becomes one request per method
//! per tick, and `core.bulk` runs the items server-side under the calling
//! session's own credentials.
//!
//! This module is the sans-io storage and the chunk builder for **one
//! session**: `core.bulk` runs its items under the calling session's own
//! credentials, so the driver holds one of these per session and flushes
//! each on the session it belongs to. The tick clock, the flush, and the
//! per-item result fan-out live in the driver.

use crate::error::ApiError;
use crate::{__json, BulkTicket};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::collections::VecDeque;

/// One queued item: its ticket and its already-encoded argument array
/// (`["tank@snap1"]`), which becomes one element of the `core.bulk`
/// parameter list.
struct Item {
    ticket: BulkTicket,
    args: Box<RawValue>,
}

/// The per-method deferred queues.
#[derive(Default)]
pub(crate) struct BulkQueue {
    /// Grouped by method because one `core.bulk` call carries exactly one
    /// method. `BTreeMap` for a deterministic flush order.
    by_method: BTreeMap<String, VecDeque<Item>>,
    total: usize,
    /// Encoded-params bytes currently held; see [`BulkQueue::bytes`].
    bytes: usize,
}

/// One flush chunk: the `core.bulk` JSON-RPC params it should be sent
/// with, and the tickets it covers, in the order their per-item results
/// will come back.
pub(crate) struct Chunk {
    pub params: Box<RawValue>,
    pub tickets: Vec<BulkTicket>,
}

impl BulkQueue {
    /// Queue `args` (an encoded argument array) for `method` under
    /// `ticket`. Refuses at `max_items`.
    pub(crate) fn enqueue(
        &mut self,
        ticket: BulkTicket,
        method: &str,
        args: Box<RawValue>,
        max_items: usize,
    ) -> Result<(), ApiError> {
        if self.total >= max_items {
            return Err(ApiError::QueueFull {
                queue: "the deferred bulk queue, in items",
                cap: max_items,
            });
        }
        let len = args.get().len();
        self.by_method
            .entry(method.to_owned())
            .or_default()
            .push_back(Item { ticket, args });
        self.total += 1;
        self.bytes += len;
        Ok(())
    }

    /// Whether anything is queued.
    pub(crate) fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// How many bytes of encoded params are queued.
    ///
    /// Kept rather than summed, for the reason the call backlog keeps
    /// its own: `queue_bulk` asks before every enqueue and this queue is
    /// ten thousand items deep by default, so a traversal here makes
    /// filling it quadratic - measured at 30 ms for a thousand items and
    /// 320 ms for four thousand before this was a counter.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// How many items are queued.
    pub(crate) fn len(&self) -> usize {
        self.total
    }

    /// The methods that currently have queued items, in flush order.
    pub(crate) fn methods(&self) -> Vec<String> {
        self.by_method.keys().cloned().collect()
    }

    /// Take one `core.bulk` chunk for `method`: as many queued items as
    /// fit under `max_frame` (the session's outbound cap), packed into the
    /// params `["<method>", [<args>...]]`. A single item too large to fit
    /// even alone fails its ticket with [`ApiError::TooLarge`] and is
    /// dropped (returned in `oversized`), so the queue cannot wedge on one
    /// unsendable item.
    ///
    /// Returns `None` when the method's queue is empty. `oversized`
    /// carries `(ticket, len)` for any item skipped as too large.
    pub(crate) fn take_chunk(
        &mut self,
        method: &str,
        max_frame: usize,
        oversized: &mut Vec<(BulkTicket, usize)>,
    ) -> Option<Chunk> {
        let queue = self.by_method.get_mut(method)?;

        // Build the params body incrementally so the size check is exact:
        // `["<method>",[` then comma-separated item args then `]]`. The
        // JSON-RPC envelope (`{"jsonrpc":...,"method":"core.bulk",...}`)
        // adds a fixed ~60 bytes the request builder will wrap this in, so
        // budget for it by reserving margin below the cap.
        const ENVELOPE_MARGIN: usize = 128;
        let budget = max_frame.saturating_sub(ENVELOPE_MARGIN);

        let method_json =
            __json::to_string(method).expect("a string always encodes");
        let mut body = format!("[{method_json},[");
        let base_len = body.len() + 2; // the closing "]]"

        let mut tickets = Vec::new();
        while let Some(front) = queue.front() {
            let item_len = front.args.get().len();
            // The single-item-too-large case: even alone it cannot fit.
            if base_len + item_len > budget && tickets.is_empty() {
                let item = queue.pop_front().expect("front just checked");
                self.total -= 1;
                self.bytes = self.bytes.saturating_sub(item_len);
                oversized.push((item.ticket, item_len));
                continue;
            }
            // Would this item (plus a comma if not the first) overflow?
            let sep = usize::from(!tickets.is_empty());
            if body.len() + sep + item_len + 2 > budget {
                break;
            }
            let item = queue.pop_front().expect("front just checked");
            self.total -= 1;
            self.bytes = self.bytes.saturating_sub(item_len);
            if !tickets.is_empty() {
                body.push(',');
            }
            body.push_str(item.args.get());
            tickets.push(item.ticket);
        }

        if queue.is_empty() {
            self.by_method.remove(method);
        }
        if tickets.is_empty() {
            // Everything queued for this method was oversized (or the
            // queue was already empty); nothing to send.
            return None;
        }
        body.push_str("]]");
        let params =
            RawValue::from_string(body).expect("assembled JSON is valid");
        Some(Chunk { params, tickets })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(n: u64, args: &str) -> (BulkTicket, Box<RawValue>) {
        (
            BulkTicket(n),
            RawValue::from_string(args.to_owned()).expect("valid"),
        )
    }

    /// A generous frame takes every queued item into one chunk, in order,
    /// as `[method, [args...]]`.
    #[test]
    fn one_chunk_holds_everything_that_fits() {
        let mut q = BulkQueue::default();
        for (t, a) in [item(1, "[1]"), item(2, "[2]"), item(3, "[3]")] {
            q.enqueue(t, "m", a, 100).unwrap();
        }
        let mut over = Vec::new();
        let chunk = q.take_chunk("m", 4096, &mut over).expect("a chunk");
        assert!(over.is_empty());
        assert_eq!(
            chunk.tickets,
            vec![BulkTicket(1), BulkTicket(2), BulkTicket(3)]
        );
        assert_eq!(chunk.params.get(), r#"["m",[[1],[2],[3]]]"#);
        assert!(q.is_empty(), "the queue drained");
    }

    /// When the cap admits only some items, the rest stay for the next
    /// chunk - and every item eventually goes, in order.
    #[test]
    fn a_tight_cap_splits_into_chunks() {
        let mut q = BulkQueue::default();
        // Each arg is ~1 KiB; a 2500-byte cap (minus the 128 margin) fits
        // about two per chunk.
        let big = format!("[{:?}]", "z".repeat(1000));
        for n in 1..=5 {
            q.enqueue(
                BulkTicket(n),
                "m",
                RawValue::from_string(big.clone()).unwrap(),
                100,
            )
            .unwrap();
        }
        let mut seen = Vec::new();
        let mut over = Vec::new();
        while let Some(chunk) = q.take_chunk("m", 2500, &mut over) {
            assert!(chunk.tickets.len() < 5, "the cap forced a split");
            seen.extend(chunk.tickets);
        }
        assert!(over.is_empty());
        assert_eq!(
            seen,
            (1..=5).map(BulkTicket).collect::<Vec<_>>(),
            "every item flushed, in order"
        );
    }

    /// A single item too large for any frame fails to `oversized` and does
    /// not block a following item that fits.
    #[test]
    fn a_single_oversized_item_is_skipped() {
        let mut q = BulkQueue::default();
        let huge = format!("[{:?}]", "q".repeat(4000));
        q.enqueue(
            BulkTicket(1),
            "m",
            RawValue::from_string(huge).unwrap(),
            100,
        )
        .unwrap();
        q.enqueue(
            BulkTicket(2),
            "m",
            RawValue::from_string("[2]".into()).unwrap(),
            100,
        )
        .unwrap();
        let mut over = Vec::new();
        let chunk = q.take_chunk("m", 2000, &mut over).expect("the small one");
        assert_eq!(over.len(), 1, "the huge item was reported oversized");
        assert_eq!(over[0].0, BulkTicket(1));
        assert_eq!(chunk.tickets, vec![BulkTicket(2)]);
    }

    /// The queue refuses past its cap.
    /// The byte counter tracks the queue exactly, in and out. It is a
    /// counter and not a traversal because `queue_bulk` asks before
    /// every enqueue: summing made filling the default 10,000-item
    /// queue quadratic.
    #[test]
    fn the_byte_counter_matches_the_queue() {
        let mut q = BulkQueue::default();
        let walk = |q: &BulkQueue| -> usize {
            q.by_method
                .values()
                .flat_map(|d| d.iter())
                .map(|i| i.args.get().len())
                .sum()
        };
        assert_eq!(q.bytes(), 0);
        for i in 0..6u64 {
            let args = RawValue::from_string(format!(
                "[\"{}\"]",
                "x".repeat(if i == 5 { 400 } else { 20 })
            ))
            .unwrap();
            q.enqueue(BulkTicket(i), "m", args, usize::MAX).unwrap();
            assert_eq!(q.bytes(), walk(&q), "after enqueue {i}");
        }
        // Drain in chunks small enough to force several passes, and one
        // oversized item out through the other removal site.
        // `take_chunk` reserves 128 bytes of envelope margin, so the
        // usable budget is `max_frame - 128`. 160 leaves 32: room for one
        // small item per chunk, so the ordinary removal runs several
        // times, while the 400-byte item cannot fit even alone and takes
        // the oversized removal. Both decrement the counter.
        let mut oversized = Vec::new();
        let mut passes = 0;
        while q.take_chunk("m", 160, &mut oversized).is_some() {
            passes += 1;
            assert_eq!(q.bytes(), walk(&q), "after a chunk");
        }
        assert_eq!(q.bytes(), walk(&q), "after the last chunk");
        assert!(passes >= 2, "the ordinary removal must run: {passes}");
        assert!(
            !oversized.is_empty(),
            "and the oversized removal must run too"
        );
        assert_eq!(q.bytes(), 0, "a drained queue charges nothing");
    }

    #[test]
    fn enqueue_refuses_at_the_cap() {
        let mut q = BulkQueue::default();
        q.enqueue(
            BulkTicket(1),
            "m",
            RawValue::from_string("[1]".into()).unwrap(),
            1,
        )
        .unwrap();
        assert!(matches!(
            q.enqueue(
                BulkTicket(2),
                "m",
                RawValue::from_string("[2]".into()).unwrap(),
                1
            ),
            Err(ApiError::QueueFull {
                queue: "the deferred bulk queue, in items",
                cap: 1,
            })
        ));
    }
}
