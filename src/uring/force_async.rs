//! [`ForceAsync`]: which submitted operations carry `IOSQE_ASYNC`.

use crate::uring::sys::IOSQE_ASYNC;

tn_bitflags! {
    /// Which operation classes are submitted with `IOSQE_ASYNC`, skipping the inline issue attempt and going straight
    /// to an io-wq worker.
    ///
    /// Empty, the default, is the unflagged submission. No class changes what an operation does, only which thread does
    /// the work and when the kernel commits the resources it names, so measure one class at a time.
    ///
    /// # A socket and a regular file take the flag differently
    ///
    /// The kernel decides by pollability, not by opcode. `io_wq_submit_work` restores `IO_URING_F_NONBLOCK` when the
    /// opcode polls *and* the file polls, and arms poll on `-EAGAIN` (`io_uring/io_uring.c:1997-2003`).
    ///
    /// * **Sockets** poll, so the worker issues non-blocking and hands itself back. The flag buys moving the copy off
    ///   the reactor thread for one io-wq round trip, not a blocking `sendmsg` (see [`Self::SEND`]).
    /// * **Regular files** never poll (`io_file_can_poll`, `io_uring/io_uring.h`), so the worker issues blocking. On
    ///   ZFS, which sets no `FMODE_NOWAIT` (`zpl_file.c`), every read and write is punted anyway, and the flag only
    ///   removes the inline attempt that would answer `-EAGAIN`.
    ///
    /// The flag marks the work concurrent (`IO_WQ_WORK_CONCURRENT`, `io_prep_async_work`), and io-wq starts another
    /// worker for concurrent work (`io_wq_enqueue`, `io_uring/io-wq.c`), so [`Self::READ`] lets reads of one file run
    /// on several workers at once. A regular file's writes still run one at a time per inode (`WRITEV` is
    /// `.hash_reg_file`, `io_uring/opdef.c`), so [`Self::WRITE`] changes where a write starts, never how many run.
    pub struct ForceAsync: u8 {
        /// `SEND` and `SENDMSG` on a connection's socket.
        ///
        /// Over kTLS this does **not** make the send blocking, so it does not close the flush gap at teardown. io_uring
        /// adds `MSG_DONTWAIT` whenever it issues with `IO_URING_F_NONBLOCK` (`io_uring/net.c`), which io-wq restores
        /// for a pollable opcode on a pollable file.
        SEND = 0x01;
        /// `RECV` and `RECVMSG` on a connection's socket.
        ///
        /// **This one changes when a pooled receive buffer is committed.** An io-wq issue arrives unlocked, and
        /// `io_should_commit` (`io_uring/kbuf.c:171-189`) consumes the selected buffer there and then. So a
        /// forced-async read holds a buffer from its first issue, and a read cancelled after that completes carrying
        /// `IORING_CQE_F_BUFFER`. The reactor adopts the buffer on every completion and teardown forfeits the claim, so
        /// the accounting holds, but an outstanding read no longer costs the pool nothing.
        RECV = 0x02;
        /// `READV` and `READ` - the file-body pump read, and a consumer's own reads through the fs reactor, into the
        /// length of its buffers or the room past it.
        READ = 0x04;
        /// `WRITEV` - a leased upload window and a consumer's own writes through the fs reactor.
        WRITE = 0x08;
    }
}

impl ForceAsync {
    /// The `sqe.flags` bit one class contributes, `IOSQE_ASYNC` when `class` is set here and `0` otherwise.
    pub(crate) fn sqe_bit(self, class: ForceAsync) -> u8 {
        if self.contains(class) { IOSQE_ASYNC } else { 0 }
    }
}
