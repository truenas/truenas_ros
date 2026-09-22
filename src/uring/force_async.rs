//! [`ForceAsync`]: which submitted operations carry `IOSQE_ASYNC`.
//!
//! The type lives in the engine because the flag is an SQE property and
//! more than one domain stamps it: the net reactor on a connection's
//! socket operations, and the fs reactor on the file reads and writes the
//! net server submits on a connection's behalf.

use crate::uring::sys::IOSQE_ASYNC;

tn_bitflags! {
    /// Which operation classes are submitted with `IOSQE_ASYNC`, skipping
    /// the inline issue attempt and going straight to an io-wq worker.
    ///
    /// Empty - the default - is the unflagged submission every operation
    /// used to get, and nothing here changes what an operation *does*: the
    /// same bytes move, the same completion arrives. What moves is which
    /// thread does the work and when the kernel commits the resources the
    /// operation names, and both of those differ by class, so measure one
    /// class at a time rather than setting the whole set.
    ///
    /// # A socket and a regular file take the flag differently
    ///
    /// The kernel decides by pollability, not by opcode.
    /// `io_wq_submit_work` restores `IO_URING_F_NONBLOCK` when the opcode
    /// polls *and* the file polls, and arms poll on `-EAGAIN`
    /// (`io_uring/io_uring.c:1997-2003`):
    ///
    /// * **Sockets** - `SEND`, `SENDMSG`, `RECV` and `RECVMSG` are all
    ///   `.pollin`/`.pollout` (`io_uring/opdef.c`) and a socket polls, so
    ///   the worker issues non-blocking and hands itself back. The flag
    ///   buys one io-wq round trip in exchange for moving the copy off the
    ///   reactor thread; it does not buy a blocking `sendmsg`, and
    ///   [`Self::SEND`] says why that matters over kTLS.
    /// * **Regular files** - never pollable (`io_file_can_poll`,
    ///   `io_uring/io_uring.h`), so the worker issues blocking. On ZFS,
    ///   which sets no `FMODE_NOWAIT` (`zpl_file.c`), every read and write
    ///   is punted anyway: the flag removes the inline attempt that was
    ///   going to answer `-EAGAIN`, and nothing else.
    ///
    /// Depth does not come with it. io-wq runs a regular file's writes one
    /// at a time per inode - `WRITEV` is `.hash_reg_file`
    /// (`io_uring/opdef.c`), hashed in `io_prep_async_work` - so
    /// [`Self::WRITE`] changes where a write starts, never how many run.
    pub struct ForceAsync: u8 {
        /// `SEND` and `SENDMSG` on a connection's socket.
        ///
        /// Over kTLS this does **not** make the send blocking, so it does
        /// not close the flush gap at teardown: io_uring adds
        /// `MSG_DONTWAIT` whenever it issues with `IO_URING_F_NONBLOCK`
        /// (`io_uring/net.c`), and the block cited above restores
        /// `IO_URING_F_NONBLOCK` itself for a pollable opcode on a
        /// pollable file - so the send stays non-blocking either way.
        SEND = 0x01;
        /// `RECV` and `RECVMSG` on a connection's socket.
        ///
        /// **This one changes when a pooled receive buffer is committed.**
        /// An io-wq issue arrives unlocked, and `io_should_commit`
        /// (`io_uring/kbuf.c:171-189`) consumes the selected buffer there
        /// and then rather than at the transfer, because nothing else
        /// stops another operation taking it. So a forced-async read holds
        /// a buffer from its first issue - not from its completion - and a
        /// read cancelled after that point completes carrying
        /// `IORING_CQE_F_BUFFER` where an unflagged one carries nothing.
        /// The reactor adopts the buffer on every completion before it
        /// looks at the result, and teardown forfeits the claim, so the
        /// accounting holds either way - and it cannot arrive on a
        /// connection already holding one, because a selecting read is
        /// armed only where `recv_needs_buffer` holds and that wants an
        /// empty claim. What does not hold is the expectation that an
        /// outstanding read costs the pool nothing.
        RECV = 0x02;
        /// `READV` - the file-body pump read, and a consumer's own reads
        /// through the fs reactor.
        READ = 0x04;
        /// `WRITEV` - a leased upload window and a consumer's own writes
        /// through the fs reactor.
        WRITE = 0x08;
    }
}

impl ForceAsync {
    /// The `sqe.flags` bit one class contributes: `IOSQE_ASYNC` when
    /// `class` is set here, `0` otherwise. Written this way so a submit
    /// site ORs a value into the flags it already builds rather than
    /// branching around the whole fill.
    pub(crate) fn sqe_bit(self, class: ForceAsync) -> u8 {
        if self.contains(class) { IOSQE_ASYNC } else { 0 }
    }
}
