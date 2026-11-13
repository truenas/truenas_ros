use super::*;

#[test]
fn wake_drain_fires_every_completion() {
    let (mut eng, mut fs, _me) = setup();
    let count: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    let c2 = count.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..8 {
                let c3 = c2.clone();
                c.offload(
                    || (),
                    move |r, _c| {
                        r.expect("a unit job never panics");
                        *c3.borrow_mut() += 1;
                    },
                );
            }
        },
        || *count.borrow() == 8,
    );
    assert_eq!(*count.borrow(), 8);
}

#[test]
fn a_failed_readdir_is_an_error_not_end_of_directory() {
    // Point the DIR*'s fd at a non-directory with `dup2`, keeping the fd number valid. The next `readdir` fails
    // `ENOTDIR`, which must arrive as an error, not an empty batch that reads as a complete listing of nothing.
    let (mut eng, mut fs, me) = setup();
    let dir = fixture(3);
    let anchor = Anchor::open(dir.path()).unwrap();
    struct S {
        walk: Option<DirWalk>,
        result: Option<crate::Result<NameBatch>>,
    }
    let st: Rc<RefCell<S>> = Rc::new(RefCell::new(S {
        walk: None,
        result: None,
    }));
    let st2 = st.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_dir(me, &anchor, move |res, conn| {
                let walk = res.expect("open_dir");
                // SAFETY: `dp` is the live DIR* just handed back; redirect its fd to /dev/null so the next readdir
                // sees a non-dir.
                let dirfd = unsafe { libc::dirfd(walk.inner.borrow().dp) };
                assert!(dirfd >= 0);
                let null = unsafe { libc::open(c"/dev/null".as_ptr(), 0) };
                assert!(null >= 0, "open /dev/null");
                assert_eq!(unsafe { libc::dup2(null, dirfd) }, dirfd, "dup2 onto dirfd");
                unsafe { libc::close(null) };
                st2.borrow_mut().walk = Some(walk);
                let st3 = st2.clone();
                let b = st2.borrow();
                conn.next_batch(b.walk.as_ref().unwrap(), move |res, _c| {
                    st3.borrow_mut().result = Some(res);
                });
            });
        },
        || st.borrow().result.is_some(),
    );
    let s = st.borrow();
    assert!(
        matches!(s.result.as_ref().unwrap(), Err(crate::Error::Errno(Errno::ENOTDIR))),
        "readdir failure delivered as Err(ENOTDIR), got {:?}",
        s.result.as_ref().unwrap()
    );
}

#[test]
fn dirwalk_drop_closes_the_dir() {
    let (mut eng, mut fs, me) = setup();
    let dir = fixture(3);
    let anchor = Anchor::open(dir.path()).unwrap();
    let captured: Rc<RefCell<Option<Rc<RefCell<DirWalkInner>>>>> = Rc::new(RefCell::new(None));
    let cap2 = captured.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_dir(me, &anchor, move |res, _c| {
                let walk = res.expect("open_dir");
                // Snapshot the inner, then drop `walk` at the end of this closure (no batch in flight -> Drop
                // closes the DIR* now).
                *cap2.borrow_mut() = Some(walk.inner.clone());
            });
        },
        || captured.borrow().is_some(),
    );
    let inner = captured.borrow().as_ref().unwrap().clone();
    assert!(inner.borrow().dropped, "walk Drop ran");
    assert!(inner.borrow().dp.is_null(), "DIR* closed on drop, not leaked");
}

struct ListState {
    me: Personality,
    anchor: Anchor,
    walk: Option<DirWalk>,
    pending: VecDeque<Vec<u8>>,
    eod: bool,
    seen: usize,
    sum: u64,
    finished: bool,
}
type ListRef = Rc<RefCell<ListState>>;

/// Pull the next batch of names for `st`'s walk (one job at a time).
fn request_batch(st: &ListRef, conn: &mut FsConn<'_>) {
    let st2 = st.clone();
    let b = st.borrow();
    let walk = b.walk.as_ref().expect("walk");
    conn.next_batch(walk, move |res, conn| {
        let batch = res.expect("batch");
        {
            let mut s = st2.borrow_mut();
            s.pending.extend(batch.names);
            s.eod = batch.eod;
        }
        enrich_next(&st2, conn);
    });
}

/// Enrich the next pending name on-loop (open + fgetxattr), <= 1 op in flight; pull the next batch when the current
/// one drains, finish at eod.
fn enrich_next(st: &ListRef, conn: &mut FsConn<'_>) {
    let name = st.borrow_mut().pending.pop_front();
    let Some(name) = name else {
        let eod = st.borrow().eod;
        if eod {
            st.borrow_mut().finished = true;
        } else {
            request_batch(st, conn);
        }
        return;
    };
    let (me, anchor) = {
        let b = st.borrow();
        (b.me, b.anchor.clone())
    };
    let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW);
    let cname = CString::new(name).unwrap();
    let st2 = st.clone();
    conn.open(me, &anchor, &cname, how, move |done, conn| {
        let Some(f) = done.file() else {
            return enrich_next(&st2, conn);
        };
        let me = st2.borrow().me;
        let st3 = st2.clone();
        conn.fgetxattr(me, f, c"user.bench", vec![0u8; 64], move |done, conn| {
            if let Ok(nb) = done.result() {
                let nb = nb as usize;
                let bufs = done.into_bufs();
                let mut s = st3.borrow_mut();
                s.seen += 1;
                if let Some(v) = bufs.first() {
                    for &x in &v[..nb.min(v.len())] {
                        s.sum += x as u64;
                    }
                }
            }
            enrich_next(&st3, conn);
        });
    });
}

#[test]
fn hybrid_listing_enriches_every_entry() {
    let (mut eng, mut fs, me) = setup();
    let n = 40usize;
    let dir = fixture(n);
    let anchor = Anchor::open(dir.path()).unwrap();
    const CLIENTS: usize = 3;
    let states: Vec<ListRef> = (0..CLIENTS)
        .map(|_| {
            Rc::new(RefCell::new(ListState {
                me,
                anchor: anchor.clone(),
                walk: None,
                pending: VecDeque::new(),
                eod: false,
                seen: 0,
                sum: 0,
                finished: false,
            }))
        })
        .collect();
    let kick = states.clone();
    let check = states.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for st in &kick {
                let st2 = st.clone();
                let (me, anchor) = {
                    let b = st.borrow();
                    (b.me, b.anchor.clone())
                };
                c.open_dir(me, &anchor, move |res, c| {
                    st2.borrow_mut().walk = Some(res.expect("open_dir"));
                    request_batch(&st2, c);
                });
            }
        },
        move || check.iter().all(|s| s.borrow().finished),
    );
    for s in &states {
        let b = s.borrow();
        assert_eq!(b.seen, n, "every entry enriched");
        assert_eq!(b.sum, xsum(n), "xattr values correct");
    }
}
