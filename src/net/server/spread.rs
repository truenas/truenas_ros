//! A spread: the servers of one port, a ring each, sharing a count of the
//! connections each ring holds, so that a ring which accepts a connection
//! while another holds fewer sends it there.
//!
//! The kernel offers no balance of its own. A `SO_REUSEPORT` group picks a
//! listener by a hash of the connection's addresses
//! (`reuseport_select_sock_by_hash`, `net/core/sock_reuseport.c`), and a
//! listener with `SO_INCOMING_CPU` is preferred only when its CPU took the
//! SYN. Neither sees how many connections a ring already holds, and a
//! connection never leaves the ring that took it, so one ring can run at
//! half the load of its neighbours for as long as its clients stay.
//!
//! The move is `IORING_OP_MSG_RING` with `IORING_MSG_SEND_FD`, before the
//! accepting ring has fetched the peer's address or run the accept handler,
//! so everything a connection has lives on the ring that serves it. The
//! kernel installs the file in a free slot of the target's table and posts
//! the target a completion naming that slot (`io_msg_install_complete`,
//! `io_uring/msg_ring.c`), which the target takes as it takes its own
//! accepts. Only a send that worked closes the sender's slot: a failed one,
//! such as a target whose table is full, leaves the connection where it was
//! accepted, to be served there.
//!
//! Nothing here orders one thread against another. Each ring writes its
//! own count and others read it with no ordering, so a stale count places a
//! connection one above the fewest, and never loses it. A place whose
//! descriptor is not set yet is passed over.

use crate::errno::Errno;
use crate::net::core::protocol::ServerAddr;
use crate::sync::atomic::{AtomicU32, Ordering};
use crate::sync::{Arc, Mutex, OnceCell};
use std::collections::HashSet;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// What a place reads while no ring serves there: not yet joined, or a
/// ring that began draining. It is never fewer than any count, so no ring
/// sends to it.
const CLOSED: u32 = u32::MAX;

/// The rings serving one port, for [`Server::join_spread`].
///
/// Built with one place per ring, cloned to each ring's thread, and joined
/// there once the ring's server exists. Clones share one set.
///
/// [`Server::join_spread`]: super::Server::join_spread
#[derive(Clone)]
pub struct Spread(Arc<Places>);

struct Places {
    places: Box<[Place]>,
    /// The addresses every member listens on, in order. The first to join
    /// sets them and the rest must match, since a hand-off names its
    /// listener by index on the ring that receives it.
    addrs: Mutex<Option<Vec<ServerAddr>>>,
}

/// One ring's place, on cache lines of its own (two, for the adjacent-line
/// prefetcher): only its ring writes the count, and every other ring reads
/// it when it accepts.
#[repr(align(128))]
struct Place {
    taken: AtomicU32,
    /// The ring's own descriptor, duplicated, so the number another ring
    /// sends to names this ring for as long as the set lives, whatever
    /// becomes of the ring's own copy.
    ring: OnceCell<OwnedFd>,
}

impl Spread {
    /// A set of `rings` places, every one closed until a server joins it.
    pub fn new(rings: usize) -> Spread {
        let places = (0..rings)
            .map(|_| Place {
                taken: AtomicU32::new(CLOSED),
                ring: OnceCell::new(),
            })
            .collect();
        Spread(Arc::new(Places {
            places,
            addrs: Mutex::new(None),
        }))
    }

    /// The number of places.
    pub fn len(&self) -> usize {
        self.0.places.len()
    }

    /// Whether the set has no places.
    pub fn is_empty(&self) -> bool {
        self.0.places.is_empty()
    }

    /// Take `place` for the ring `ring`, which listens on `addrs` and holds
    /// `taken` connections already.
    pub(crate) fn join(
        &self,
        place: usize,
        ring: RawFd,
        addrs: Vec<ServerAddr>,
        taken: u32,
    ) -> crate::Result<()> {
        let Some(at) = self.0.places.get(place) else {
            return Err(crate::Error::Validation(format!(
                "place {place} of a spread of {}",
                self.len()
            )));
        };
        {
            let mut first =
                self.0.addrs.lock().unwrap_or_else(|e| e.into_inner());
            match first.as_ref() {
                Some(theirs) if *theirs != addrs => {
                    return Err(crate::Error::Validation(format!(
                        "a spread's servers listen on {theirs:?}, not \
                         {addrs:?}"
                    )));
                }
                Some(_) => {}
                None => *first = Some(addrs),
            }
        }
        // SAFETY: `ring` is the joining server's open ring descriptor, which
        // it holds across this call; F_DUPFD_CLOEXEC returns a new one or -1.
        let raw = Errno::result(unsafe {
            libc::fcntl(ring, libc::F_DUPFD_CLOEXEC, 0)
        })?;
        // SAFETY: a descriptor `fcntl` just created, owned by nothing else.
        let own = unsafe { crate::fd::owned_from_raw(raw) };
        if !at.ring.set(own) {
            return Err(crate::Error::Validation(format!(
                "place {place} of the spread is taken"
            )));
        }
        at.taken.store(taken, Ordering::Relaxed);
        Ok(())
    }

    /// The ring with the fewest connections, when it holds fewer than the
    /// one at `me`. Ties stay, so an even spread moves nothing.
    pub(crate) fn fewer_than(&self, me: usize) -> Option<RawFd> {
        let places = &self.0.places;
        let mine = places.get(me)?.taken.load(Ordering::Relaxed);
        let mut best: Option<(u32, usize)> = None;
        for (i, at) in places.iter().enumerate() {
            let n = at.taken.load(Ordering::Relaxed);
            if i != me && n < mine && best.is_none_or(|(b, _)| n < b) {
                best = Some((n, i));
            }
        }
        let (_, i) = best?;
        places[i].ring.with(|fd| fd.as_raw_fd())
    }

    fn publish(&self, place: usize, taken: u32) {
        if let Some(at) = self.0.places.get(place) {
            at.taken.store(taken, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for Spread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let taken: Vec<u32> = self
            .0
            .places
            .iter()
            .map(|at| at.taken.load(Ordering::Relaxed))
            .collect();
        f.debug_struct("Spread").field("taken", &taken).finish()
    }
}

/// A server's place in a spread, and the count it publishes there: every
/// slot it holds a connection in, from the accept it kept to the slot's
/// release.
pub(crate) struct Joined {
    set: Spread,
    place: usize,
    taken: u32,
    closed: bool,
}

impl Joined {
    pub(crate) fn new(set: Spread, place: usize, taken: u32) -> Joined {
        Joined {
            set,
            place,
            taken,
            closed: false,
        }
    }

    /// Where a connection this ring accepted should go instead, if
    /// anywhere.
    pub(crate) fn target(&self) -> Option<RawFd> {
        if self.closed {
            return None;
        }
        self.set.fewer_than(self.place)
    }

    /// This ring kept a connection.
    pub(crate) fn took(&mut self) {
        self.taken = self.taken.saturating_add(1);
        self.publish();
    }

    /// A slot this ring kept a connection in was released.
    pub(crate) fn gave(&mut self) {
        self.taken = self.taken.saturating_sub(1);
        self.publish();
    }

    /// This ring takes no more connections: no ring sends it any from here
    /// on, beyond one already chosen, which it sheds.
    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.publish();
    }

    fn publish(&self) {
        let n = if self.closed { CLOSED } else { self.taken };
        self.set.publish(self.place, n);
    }
}

/// The physical cores among the CPUs this thread may run on, each core
/// once however many hardware threads it has.
///
/// A sizing for rings: a second ring on a core's other hardware thread
/// shares that core's caches and pipeline, and adds far less than a ring
/// on a core of its own. Reads the affinity mask, so a cpuset or a
/// service's `CPUAffinity` narrows it, and each CPU's
/// `topology/core_cpus_list` in sysfs. A CPU whose topology cannot be read
/// counts as a core of its own. At least 1.
pub fn physical_cores() -> std::io::Result<usize> {
    // SAFETY: `cpu_set_t` is a plain bitmask, valid when zeroed.
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `mask` is a live `cpu_set_t` of the size passed.
    let r = unsafe {
        libc::sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut mask,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let allowed = (0..libc::CPU_SETSIZE as usize)
        // SAFETY: `cpu` is below CPU_SETSIZE, inside `mask`.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &mask) });
    Ok(count_cores(allowed, |cpu| {
        std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/core_cpus_list"
        ))
        .ok()
    }))
}

/// Count the distinct cores of `cpus`, each named by the list of CPUs it
/// shares a core with.
fn count_cores(
    cpus: impl Iterator<Item = usize>,
    siblings: impl Fn(usize) -> Option<String>,
) -> usize {
    let cores: HashSet<String> = cpus
        .map(|cpu| {
            siblings(cpu)
                .map_or_else(|| format!("cpu{cpu}"), |s| s.trim().to_owned())
        })
        .collect();
    cores.len().max(1)
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn null() -> OwnedFd {
        std::fs::File::open("/dev/null").expect("/dev/null").into()
    }

    fn addrs() -> Vec<ServerAddr> {
        vec![ServerAddr::Tcp("127.0.0.1:2049".parse().unwrap())]
    }

    #[test]
    fn a_connection_goes_to_the_ring_with_the_fewest() {
        let set = Spread::new(3);
        let fds: Vec<OwnedFd> = (0..3).map(|_| null()).collect();
        for (i, taken) in [5, 3, 2].into_iter().enumerate() {
            set.join(i, fds[i].as_raw_fd(), addrs(), taken).unwrap();
        }
        assert!(set.fewer_than(0).is_some());
        let to = set.fewer_than(0).unwrap();
        let two = set.0.places[2].ring.with(|fd| fd.as_raw_fd()).unwrap();
        assert_eq!(to, two, "the ring with 2, not the one with 3");
        assert_eq!(set.fewer_than(2), None, "the fewest keeps its own");
    }

    #[test]
    fn a_tie_stays_where_it_was_accepted() {
        let set = Spread::new(2);
        let fds: Vec<OwnedFd> = (0..2).map(|_| null()).collect();
        for (i, fd) in fds.iter().enumerate() {
            set.join(i, fd.as_raw_fd(), addrs(), 4).unwrap();
        }
        assert_eq!(set.fewer_than(0), None);
        assert_eq!(set.fewer_than(1), None);
    }

    #[test]
    fn a_place_no_ring_serves_is_never_chosen() {
        let set = Spread::new(3);
        let fd = null();
        set.join(0, fd.as_raw_fd(), addrs(), 7).unwrap();
        assert_eq!(set.fewer_than(0), None, "places 1 and 2 never joined");
        let other = null();
        set.join(1, other.as_raw_fd(), addrs(), 0).unwrap();
        let mut one = Joined::new(set.clone(), 1, 0);
        assert!(set.fewer_than(0).is_some());
        one.close();
        assert_eq!(set.fewer_than(0), None, "place 1 began draining");
        one.took();
        assert_eq!(set.fewer_than(0), None, "and stays closed");
    }

    #[test]
    fn a_released_slot_comes_off_the_count() {
        let set = Spread::new(2);
        let fds: Vec<OwnedFd> = (0..2).map(|_| null()).collect();
        for (i, fd) in fds.iter().enumerate() {
            set.join(i, fd.as_raw_fd(), addrs(), 0).unwrap();
        }
        let mut zero = Joined::new(set.clone(), 0, 0);
        zero.took();
        zero.took();
        assert!(zero.target().is_some());
        zero.gave();
        zero.gave();
        assert_eq!(zero.target(), None);
    }

    #[test]
    fn a_server_on_other_addresses_or_a_taken_place_is_refused() {
        let set = Spread::new(2);
        let fd = null();
        set.join(0, fd.as_raw_fd(), addrs(), 0).unwrap();
        let other = vec![ServerAddr::Tcp("127.0.0.1:2050".parse().unwrap())];
        assert!(set.join(1, fd.as_raw_fd(), other, 0).is_err());
        assert!(set.join(0, fd.as_raw_fd(), addrs(), 0).is_err());
        assert!(set.join(2, fd.as_raw_fd(), addrs(), 0).is_err());
    }

    #[test]
    fn hyperthreads_of_one_core_count_once() {
        // Four CPUs on two cores, as the kernel lists their siblings.
        let siblings = |cpu: usize| {
            Some(
                if cpu.is_multiple_of(2) {
                    "0,2\n"
                } else {
                    "1,3\n"
                }
                .to_owned(),
            )
        };
        assert_eq!(count_cores(0..4, siblings), 2);
        assert_eq!(count_cores([0, 2].into_iter(), siblings), 1);
        assert_eq!(count_cores([0, 1].into_iter(), siblings), 2);
        // A CPU with no topology to read is a core of its own.
        assert_eq!(count_cores(0..3, |_| None), 3);
        assert_eq!(count_cores(std::iter::empty(), siblings), 1);
    }

    #[test]
    fn a_completion_another_ring_posts_is_not_counted_in_flight() {
        use crate::net::core::conn::{Op, pack};
        use crate::uring::engine::counted;
        use crate::uring::sys::{IORING_CQE_F_MORE, IoUringCqe};
        let cqe = |user_data, flags| IoUringCqe {
            user_data,
            res: 0,
            flags,
        };
        assert!(!counted(&cqe(pack(Op::Handed, 1, 0), 0)));
        assert!(counted(&cqe(pack(Op::Handoff, 1, 0), 0)));
        assert!(!counted(&cqe(pack(Op::Accept, 0, 0), IORING_CQE_F_MORE)));
        assert!(counted(&cqe(pack(Op::Accept, 0, 0), 0)));
    }

    /// A send the kernel refuses leaves the connection on the ring that
    /// accepted it, and it is served there. The other place holds a
    /// descriptor that is no ring, so every send to it answers `EBADFD`
    /// (`io_msg_ring`, `io_uring/msg_ring.c`).
    #[test]
    fn a_refused_hand_off_is_served_where_it_was_accepted() {
        use crate::net::core::protocol::{ClientAddr, Endian, PrefixWidth};
        use crate::net::server::{Server, ServerConfig, length_prefixed};
        use std::io::{Read, Write};
        use std::time::Duration;
        let cfg = ServerConfig {
            reuse_port: true,
            ..ServerConfig::default()
        };
        let echo = |_h: &[u8], body: &[u8], _p: &ClientAddr| {
            let mut pdu = (body.len() as u32).to_be_bytes().to_vec();
            pdu.extend_from_slice(body);
            Some(pdu)
        };
        let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse().unwrap());
        let mut server = match Server::with_config([addr], cfg, proto) {
            Ok(s) => s,
            Err(crate::Error::Errno(e))
                if crate::uring::setup_unavailable(e) =>
            {
                return;
            }
            Err(e) => panic!("Server::with_config: {e}"),
        };
        let set = Spread::new(2);
        server.join_spread(&set, 0).expect("join place 0");
        let not_a_ring = null();
        set.join(1, not_a_ring.as_raw_fd(), server.local_addrs(), 0)
            .expect("place 1");
        let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
            panic!("a TCP listener");
        };
        let stop = server.shutdown_handle();
        let stats = server.stats_handle();
        // The server stops however the client ends, so a connection that
        // is dropped fails the test rather than hanging it.
        let client = std::thread::spawn(move || {
            let served = (|| -> std::io::Result<Vec<[u8; 5]>> {
                let mut held = Vec::new();
                let mut replies = Vec::new();
                for i in 0..4u8 {
                    let mut s = std::net::TcpStream::connect(v4)?;
                    s.set_read_timeout(Some(Duration::from_secs(10)))?;
                    s.write_all(&[0, 0, 0, 1, i])?;
                    let mut reply = [0u8; 5];
                    s.read_exact(&mut reply)?;
                    replies.push(reply);
                    held.push(s);
                }
                Ok(replies)
            })();
            stop.shutdown();
            served
        });
        server.serve_forever().expect("serve_forever");
        let replies = client
            .join()
            .expect("client")
            .expect("served where it was accepted");
        for (i, reply) in replies.iter().enumerate() {
            assert_eq!(*reply, [0, 0, 0, 1, i as u8]);
        }
        let s = stats.snapshot();
        assert_eq!((s.accepted, s.handed_off), (4, 0));
    }

    #[test]
    fn this_host_has_at_least_one_core_and_no_more_than_its_cpus() {
        let cores = physical_cores().expect("sched_getaffinity");
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        assert!((1..=cpus).contains(&cores), "{cores} cores of {cpus}");
    }
}
