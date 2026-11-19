//! Per-connection state of zero-copy sends. The kernel reads a zero-copy send's pages until the send's notification,
//! and notifications can come out of send order (`io_link_skb`, `io_notif_tw_complete`, `io_uring/notif.c`). So each
//! send has a sequence number, and a sent item is held until every send that carried its bytes is notified.

use super::SendItem;
use std::collections::VecDeque;

/// The most zero-copy sends one connection may have waiting for a completion, one bit of `owed` each.
pub(crate) const ZC_WINDOW: u32 = 64;

pub(crate) struct ZcLedger {
    /// Send with a copy from now on.
    pub(crate) off: bool,
    next: u32,
    /// Bit `seq % ZC_WINDOW` is set while send `seq` waits for a completion.
    owed: u64,
    /// The bytes each send moved, taken off the ring's pinned count at its notification.
    moved: [usize; ZC_WINDOW as usize],
    /// The newest send that carried part of the front item.
    front: Option<u32>,
    /// Sent items with the newest send that carried them, in send order.
    held: VecDeque<(u32, SendItem)>,
    /// The teardown holds its `CLOSE` until nothing is owed.
    pub(crate) close_held: bool,
    /// The `TCP_USER_TIMEOUT` setsockopt is in flight, and the held `CLOSE` must come after it.
    pub(crate) linger_inflight: bool,
    pub(crate) linger_set: bool,
    /// The setsockopt's value. The kernel reads it from here at issue.
    pub(crate) linger_ms: u32,
}

impl ZcLedger {
    pub(crate) fn new(linger_ms: u32) -> ZcLedger {
        ZcLedger {
            off: false,
            next: 0,
            owed: 0,
            moved: [0; ZC_WINDOW as usize],
            front: None,
            held: VecDeque::new(),
            close_held: false,
            linger_inflight: false,
            linger_set: false,
            linger_ms,
        }
    }

    /// The sequence for the next zero-copy send, or `None` to copy because zero-copy is off or the window is full.
    pub(crate) fn admit(&self) -> Option<u32> {
        if self.off || self.owed & bit(self.next) != 0 {
            return None;
        }
        Some(self.next)
    }

    pub(crate) fn staged(&mut self, seq: u32) {
        debug_assert_eq!(seq, self.next, "staged out of turn");
        self.owed |= bit(seq);
        self.moved[index(seq)] = 0;
        self.next = seq.wrapping_add(1);
    }

    /// Records the result of send `seq` and returns the bytes it pinned. Without `IORING_CQE_F_MORE` no notification
    /// follows (`io_sendrecv_fail`, `io_uring/net.c`).
    pub(crate) fn result(&mut self, seq: u32, res: i32, more: bool) -> usize {
        if !more {
            self.owed &= !bit(seq);
            self.release();
            return 0;
        }
        let moved = usize::try_from(res).unwrap_or(0);
        self.moved[index(seq)] = moved;
        moved
    }

    /// Records the notification of send `seq` and releases what no other send still carries. A copy report turns
    /// zero-copy off, but only after a send that moved bytes, since one that moved none reports a copy too. Returns
    /// whether `seq` was owed, the bytes it pinned, and whether zero-copy turned off.
    pub(crate) fn notified(&mut self, seq: u32, copied: bool) -> (bool, usize, bool) {
        if self.owed & bit(seq) == 0 {
            return (false, 0, false);
        }
        self.owed &= !bit(seq);
        let moved = std::mem::take(&mut self.moved[index(seq)]);
        let turned_off = copied && moved > 0 && !self.off;
        self.off |= turned_off;
        self.release();
        (true, moved, turned_off)
    }

    pub(crate) fn owes(&self) -> bool {
        self.owed != 0
    }

    /// A sent item leaves the send queue after send `carrier`, `None` for a plain send. `was_front` says it is the
    /// partly sent front item. The item is held while a send that carried it is owed.
    pub(super) fn retire(&mut self, item: SendItem, carrier: Option<u32>, was_front: bool) {
        let front = if was_front { self.front.take() } else { None };
        match newest(carrier, front) {
            Some(seq) => self.held.push_back((seq, item)),
            None => drop(item),
        }
    }

    /// Send `seq` carried part of the front item, which is not sent in full yet.
    pub(crate) fn carried_front(&mut self, seq: u32) {
        self.front = newest(Some(seq), self.front);
    }

    /// Drops the held items whose carriers are all notified, which runs a `Lent` callback or sends storage home.
    pub(crate) fn release(&mut self) {
        let oldest = self.oldest_owed();
        while let Some(&(seq, _)) = self.held.front() {
            if oldest.is_some_and(|o| !before(seq, o)) {
                break;
            }
            self.held.pop_front();
        }
        if self.front.is_some_and(|f| oldest.is_none_or(|o| before(f, o))) {
            self.front = None;
        }
    }

    /// The oldest owed send. Owed sends are among the last `ZC_WINDOW` staged, so after the map is rotated by `next`,
    /// bit `k` is send `next - ZC_WINDOW + k`.
    fn oldest_owed(&self) -> Option<u32> {
        if self.owed == 0 {
            return None;
        }
        let rotated = self.owed.rotate_right(self.next % ZC_WINDOW);
        Some(self.next.wrapping_sub(ZC_WINDOW).wrapping_add(rotated.trailing_zeros()))
    }

    #[cfg(test)]
    pub(crate) fn held_len(&self) -> usize {
        self.held.len()
    }
}

fn bit(seq: u32) -> u64 {
    1 << (seq % ZC_WINDOW)
}

fn index(seq: u32) -> usize {
    (seq % ZC_WINDOW) as usize
}

/// Whether send `a` came before send `b`, across wraparound.
fn before(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

fn newest(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if before(x, y) { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}
