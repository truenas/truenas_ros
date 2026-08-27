//! Lossy conversion between the NFS4 and POSIX1E models.
//!
//! A port of the kernel's nfsd shim (`fs/nfsd/nfs4acl.c`), which is the only
//! implementation that has to satisfy both models against a live filesystem -
//! so it is also what a client comparing our answer against an NFS export has
//! already seen. The mapping is a bijection in neither direction, which is
//! what the names say.
//!
//! **NFS4 -> POSIX1E drops every right POSIX cannot name.**
//! `low_mode_from_nfs4` keeps `r` for `READ_DATA`, `w` only when
//! `WRITE_DATA`, `APPEND_DATA` and - on a directory - `DELETE_CHILD` are
//! *all* granted, and `x` for `EXECUTE`. `DELETE`, `WRITE_OWNER`,
//! `WRITE_ACL`, `WRITE_ATTRIBUTES` and the named-attribute bits have no POSIX
//! spelling and are lost. The rounding is deliberately downward: a partial
//! NFS4 write grant becomes no POSIX write at all, because the result decides
//! access and rounding up would grant what the source did not.
//!
//! **POSIX1E -> NFS4 collapses the group-class mask.** A POSIX entry's
//! effective rights are `perm & mask` and NFS4 has no second stage, so each
//! entry is emitted already masked. Convert back and the mask reappears as
//! the union of what survived: `u:1000:rwx` under `mask::r-x` becomes
//! `u:1000:r-x` under `mask::r-x`, and the stored `rwx` is gone.
//!
//! **Ordering carries what NFS4 has no mask for.** POSIX picks one class and
//! stops; NFS4 accumulates over every ACE whose principal matches, and
//! `OWNER@`, `GROUP@` and `EVERYONE@` all match the owner. An ACL granting
//! some class more than the owner therefore needs an explicit DENY on
//! `OWNER@` ahead of the allows, or the trailing `ALLOW EVERYONE@` hands the
//! owner what POSIX withheld. [`PosixAcl::to_nfs4_lossy`] says what that
//! costs.
//!
//! Three things depart from nfsd, all in the NFS4 -> POSIX1E direction and
//! all because the input here is a ZFS ACL rather than an NFSv4 protocol ACL:
//!
//! * **`INHERITED` and `NO_PROPAGATE_INHERIT` are accepted rather than
//!   refused.** Both are outside `NFS4_SUPPORTED_FLAGS` and nfsd answers
//!   `-EINVAL` for either, but ZFS sets `INHERITED` on every ACE a child
//!   inherits, so refusing it would fail on ordinary directories.
//!   `NO_PROPAGATE_INHERIT` has no POSIX spelling - a default ACL is
//!   inherited by every descendant - so it is dropped, and the result grants
//!   at depth 2 what the source stopped at depth 1.
//! * **AUDIT and ALARM ACEs are skipped rather than refused.** nfsd rejects
//!   the whole ACL; they settle no access and POSIX1E has no auditing, so
//!   dropping them cannot widen the result. ZFS will not store one anyway
//!   (`nfsace4i_to_acep`, `module/os/linux/zfs/zpl_xattr.c`).
//! * **An `INHERIT_ONLY` ACE with neither inherit bit governs nothing.**
//!   nfsd tests `flag & (FILE_INHERIT|DIRECTORY_INHERIT)`, finds neither and
//!   feeds the ACE to the *effective* ACL - granting rights the ACE says do
//!   not apply to this object. It is skipped here.

use super::nfs4::{
    Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who,
};
use super::posix::{PosixAce, PosixAcl, PosixPerm, PosixTag};
use crate::error::Result;

// The mode-bit translations, verbatim from `fs/nfsd/nfs4acl.c`.

/// `NFS4_READ_MODE`.
const READ_MODE: Nfs4Perm = Nfs4Perm::READ_DATA;
/// `NFS4_WRITE_MODE`.
const WRITE_MODE: Nfs4Perm = Nfs4Perm::WRITE_DATA.union(Nfs4Perm::APPEND_DATA);
/// `NFS4_EXECUTE_MODE`.
const EXECUTE_MODE: Nfs4Perm = Nfs4Perm::EXECUTE;
/// `NFS4_ANYONE_MODE`: handed to every principal an ALLOW names. POSIX cannot
/// withhold them - anyone who can look a file up can stat it and read its
/// ACL - so leaving them out would make the NFS4 form stricter than the POSIX
/// one it came from.
const ANYONE_MODE: Nfs4Perm = Nfs4Perm::READ_ATTRIBUTES
    .union(Nfs4Perm::READ_ACL)
    .union(Nfs4Perm::SYNCHRONIZE);
/// `NFS4_OWNER_MODE`: what an owner holds in POSIX whatever the ACL says.
const OWNER_MODE: Nfs4Perm =
    Nfs4Perm::WRITE_ATTRIBUTES.union(Nfs4Perm::WRITE_ACL);
/// `NFS4_INHERITANCE_FLAGS`: the two bits that make an ACE a child's, and so
/// the two that stand in for a POSIX default ACL.
const INHERITABLE: Nfs4Flag =
    Nfs4Flag::FILE_INHERIT.union(Nfs4Flag::DIRECTORY_INHERIT);

/// `deny_mask_from_posix` (`fs/nfsd/nfs4acl.c`): the NFS4 bits that
/// stand for POSIX `perm`, and nothing else. A DENY carries only these -
/// denying `READ_ATTRIBUTES` or `SYNCHRONIZE` would withhold what POSIX never
/// withholds.
fn deny_mask_from_posix(perm: PosixPerm, is_dir: bool) -> Nfs4Perm {
    let mut mask = Nfs4Perm::empty();
    if perm.contains(PosixPerm::READ) {
        mask |= READ_MODE;
    }
    if perm.contains(PosixPerm::WRITE) {
        mask |= WRITE_MODE;
        // POSIX `w` on a directory is the right to unlink its children;
        // NFS4 spells that separately.
        if is_dir {
            mask |= Nfs4Perm::DELETE_CHILD;
        }
    }
    if perm.contains(PosixPerm::EXECUTE) {
        mask |= EXECUTE_MODE;
    }
    mask
}

/// `mask_from_posix` (`fs/nfsd/nfs4acl.c`): the mask an ALLOW carries,
/// which is the DENY translation plus the rights POSIX grants unconditionally.
fn mask_from_posix(perm: PosixPerm, is_dir: bool, is_owner: bool) -> Nfs4Perm {
    let mut mask = ANYONE_MODE | deny_mask_from_posix(perm, is_dir);
    if is_owner {
        mask |= OWNER_MODE;
    }
    mask
}

/// `low_mode_from_nfs4` (`fs/nfsd/nfs4acl.c`): the POSIX rights an
/// allowed NFS4 mask amounts to.
///
/// A POSIX bit is set only when *every* NFS4 bit it stands for is allowed, so
/// a caller holding `WRITE_DATA` but not `APPEND_DATA` gets no `w`. That is
/// the pessimism the whole conversion rests on: DENY entries have already
/// been folded into the allow sets by then, and a bit rounded up here would
/// grant access the NFS4 ACL refused.
fn low_mode_from_nfs4(perm: Nfs4Perm, is_dir: bool) -> PosixPerm {
    let write_mode = if is_dir {
        WRITE_MODE | Nfs4Perm::DELETE_CHILD
    } else {
        WRITE_MODE
    };
    let mut mode = PosixPerm::empty();
    if perm.contains(READ_MODE) {
        mode |= PosixPerm::READ;
    }
    if perm.contains(write_mode) {
        mode |= PosixPerm::WRITE;
    }
    if perm.contains(EXECUTE_MODE) {
        mode |= PosixPerm::EXECUTE;
    }
    mode
}

// ── POSIX1E -> NFS4 ─────────────────────────────────────────────────────────

/// `struct posix_acl_summary` (`fs/nfsd/nfs4acl.c`): the class-wide
/// rights a per-entry DENY has to account for, reduced to what the mask
/// leaves effective.
struct PosixSummary {
    owner: PosixPerm,
    users: PosixPerm,
    group: PosixPerm,
    groups: PosixPerm,
    other: PosixPerm,
    mask: PosixPerm,
}

/// `summarize_posix_acl` (`fs/nfsd/nfs4acl.c`).
///
/// Only `users` and `groups` accumulate; the rest are written by the single
/// entry of their tag, which `validate` proved is present. An absent one
/// reading as empty is unreachable, and nfsd leans on the same guarantee.
fn summarize(aces: &[PosixAce]) -> PosixSummary {
    let mut s = PosixSummary {
        owner: PosixPerm::empty(),
        users: PosixPerm::empty(),
        group: PosixPerm::empty(),
        groups: PosixPerm::empty(),
        other: PosixPerm::empty(),
        // No MASK entry means nothing is masked.
        mask: PosixPerm::all(),
    };
    for a in aces {
        match a.tag {
            PosixTag::UserObj => s.owner = a.perms,
            PosixTag::User => s.users |= a.perms,
            PosixTag::GroupObj => s.group = a.perms,
            PosixTag::Group => s.groups |= a.perms,
            PosixTag::Mask => s.mask = a.perms,
            PosixTag::Other => s.other = a.perms,
        }
    }
    // The mask may be written after the entries it limits, so apply it once
    // the whole list has been read.
    s.users &= s.mask;
    s.group &= s.mask;
    s.groups &= s.mask;
    s
}

/// `_posix_to_nfsv4_one` (`fs/nfsd/nfs4acl.c`): append the ACEs for
/// one POSIX list - the access half, or the default half marked inherit-only.
fn translate_one(
    out: &mut Vec<Nfs4Ace>,
    aces: &[PosixAce],
    is_dir: bool,
    inherit_only: bool,
) {
    use Nfs4AceType::{Allow, Deny};
    use Nfs4Who::{Everyone, Group, Named, Owner};

    let pas = summarize(aces);
    let eflag = if inherit_only {
        INHERITABLE | Nfs4Flag::INHERIT_ONLY
    } else {
        Nfs4Flag::empty()
    };
    let gflag = eflag | Nfs4Flag::IDENTIFIER_GROUP;

    // What the owner is not granted but a later ACE would grant them anyway:
    // `OWNER@` is matched by `GROUP@` and `EVERYONE@` too, so the withholding
    // has to be explicit and has to come first. Denying everything outside
    // the owner's own rights would say the same thing in a longer ACL.
    let deny = !pas.owner & (pas.users | pas.group | pas.groups | pas.other);
    if !deny.is_empty() {
        let mask = deny_mask_from_posix(deny, is_dir);
        out.push(Nfs4Ace::new(Deny, eflag, mask, Owner, -1));
    }
    let mask = mask_from_posix(pas.owner, is_dir, true);
    out.push(Nfs4Ace::new(Allow, eflag, mask, Owner, -1));

    for a in aces.iter().filter(|a| a.tag == PosixTag::User) {
        let eff = a.perms & pas.mask;
        let deny = !eff & (pas.groups | pas.group | pas.other);
        if !deny.is_empty() {
            let mask = deny_mask_from_posix(deny, is_dir);
            out.push(Nfs4Ace::new(Deny, eflag, mask, Named, a.id));
        }
        let mask = mask_from_posix(eff, is_dir, false);
        out.push(Nfs4Ace::new(Allow, eflag, mask, Named, a.id));
    }

    // Every group is allowed before any group is denied, because a caller can
    // be in more than one: a DENY placed ahead of a sibling group's ALLOW
    // settles the bit for a member of both, and POSIX grants such a caller
    // the union of the two.
    let mask = mask_from_posix(pas.group, is_dir, false);
    out.push(Nfs4Ace::new(Allow, eflag, mask, Group, -1));
    for a in aces.iter().filter(|a| a.tag == PosixTag::Group) {
        let mask = mask_from_posix(a.perms & pas.mask, is_dir, false);
        out.push(Nfs4Ace::new(Allow, gflag, mask, Named, a.id));
    }

    let deny = !pas.group & pas.other;
    if !deny.is_empty() {
        let mask = deny_mask_from_posix(deny, is_dir);
        out.push(Nfs4Ace::new(Deny, eflag, mask, Group, -1));
    }
    for a in aces.iter().filter(|a| a.tag == PosixTag::Group) {
        let deny = !(a.perms & pas.mask) & pas.other;
        if !deny.is_empty() {
            let mask = deny_mask_from_posix(deny, is_dir);
            out.push(Nfs4Ace::new(Deny, gflag, mask, Named, a.id));
        }
    }

    let mask = mask_from_posix(pas.other, is_dir, false);
    out.push(Nfs4Ace::new(Allow, eflag, mask, Everyone, -1));
}

impl PosixAcl {
    /// Convert to the NFS4 ACL granting the closest access.
    ///
    /// A port of nfsd's shim (`fs/nfsd/nfs4acl.c`). What it loses is the
    /// group-class mask: a POSIX entry's effective rights are `perm & mask`,
    /// NFS4 has no second stage, so every entry goes out already reduced.
    /// `u:1000:rwx` under `mask::r-x` is emitted as `r-x`, and the stored
    /// `rwx` is not recoverable from the result.
    ///
    /// `is_dir` picks the directory reading of the rights - `w` also means
    /// `DELETE_CHILD` - and decides whether a default ACL may be present at
    /// all. The ACL is validated against it first, because the translation
    /// reads exactly one `USER_OBJ`, `GROUP_OBJ` and `OTHER` entry per list;
    /// nfsd asserts that shape rather than checking it
    /// (`BUG_ON(pacl->a_count < 3)`).
    ///
    /// The default ACL becomes a second run of ACEs carrying
    /// `FILE_INHERIT | DIRECTORY_INHERIT | INHERIT_ONLY`, which is how nfsd
    /// simulates one (`NFS4_INHERITANCE_FLAGS`, `fs/nfsd/nfs4acl.c`).
    /// Nothing here produces `NO_PROPAGATE_INHERIT`, because a POSIX default
    /// ACL has no way to say it: the result is inherited by every descendant.
    ///
    /// # The result is not always writable
    ///
    /// The validation [`fsetacl`] applies refuses DENY entries for
    /// `OWNER@`/`GROUP@`, and this emits them whenever the source grants some
    /// class more than the owner, or `other` more than the owning group.
    /// NFS4 accumulates over every ACE whose principal matches and
    /// `EVERYONE@` matches the owner too, so without a DENY ahead of them the
    /// trailing `ALLOW EVERYONE@` hands the owner what POSIX withheld;
    /// widening silently is the worse answer. A directory whose POSIX ACL has
    /// no default half meets the other rule the same way - a directory ACL
    /// has to carry something inheritable, and there is nothing to inherit.
    ///
    /// [`fsetacl`]: crate::sync_fs::acl::fsetacl
    pub fn to_nfs4_lossy(&self, is_dir: bool) -> Result<Nfs4Acl> {
        self.validate(is_dir)?;
        let mut aces = Vec::new();
        translate_one(&mut aces, &self.access, is_dir, false);
        // `validate` refused a default ACL on anything but a directory, so
        // this run only ever describes a directory's children.
        if let Some(default) = &self.default {
            translate_one(&mut aces, default, is_dir, true);
        }
        Ok(Nfs4Acl {
            acl_flags: if is_dir {
                Nfs4AclFlag::ACL_IS_DIR
            } else {
                Nfs4AclFlag::empty()
            },
            aces,
        })
    }
}

// ── NFS4 -> POSIX1E ─────────────────────────────────────────────────────────

/// `struct posix_ace_state` (`fs/nfsd/nfs4acl.c`): the bits one
/// entity has been allowed and denied so far.
///
/// NFS4 settles each bit at the first ACE that names it, so a bit already in
/// one set can never enter the other.
#[derive(Clone, Copy)]
struct AceState {
    allow: Nfs4Perm,
    deny: Nfs4Perm,
}

impl AceState {
    const EMPTY: AceState = AceState {
        allow: Nfs4Perm::empty(),
        deny: Nfs4Perm::empty(),
    };

    /// `allow_bits`: allow everything in `mask` not already denied.
    fn allow_bits(&mut self, mask: Nfs4Perm) {
        self.allow |= mask.difference(self.deny);
    }

    /// `deny_bits`: deny everything in `mask` not already allowed.
    fn deny_bits(&mut self, mask: Nfs4Perm) {
        self.deny |= mask.difference(self.allow);
    }
}

fn allow_bits_all(list: &mut [(i64, AceState)], mask: Nfs4Perm) {
    for (_, p) in list {
        p.allow_bits(mask);
    }
}

fn deny_bits_all(list: &mut [(i64, AceState)], mask: Nfs4Perm) {
    for (_, p) in list {
        p.deny_bits(mask);
    }
}

/// `ace2type` (`fs/nfsd/nfs4acl.c`): the POSIX class an NFS4
/// principal belongs to. `EVERYONE@` becomes `OTHER`, which is the first
/// approximation this conversion makes - NFS4's `EVERYONE@` includes the
/// owner and the owning group, POSIX's `other` excludes both - and the reason
/// an `OTHER` ACE below feeds every entity rather than just `other`.
fn ace2tag(ace: &Nfs4Ace) -> PosixTag {
    match ace.who_type {
        Nfs4Who::Named => {
            if ace.ace_flags.contains(Nfs4Flag::IDENTIFIER_GROUP) {
                PosixTag::Group
            } else {
                PosixTag::User
            }
        }
        Nfs4Who::Owner => PosixTag::UserObj,
        Nfs4Who::Group => PosixTag::GroupObj,
        Nfs4Who::Everyone => PosixTag::Other,
    }
}

/// `struct posix_acl_state` (`fs/nfsd/nfs4acl.c`): one half - the
/// effective ACL or the inheritable one - of the POSIX ACL being built.
struct AclState {
    /// Bitset of the [`PosixTag`] values an ACE has landed on. The tag values
    /// are the kernel's `ACL_*` constants, so this is nfsd's `valid` field.
    valid: u16,
    owner: AceState,
    group: AceState,
    other: AceState,
    everyone: AceState,
    users: Vec<(i64, AceState)>,
    groups: Vec<(i64, AceState)>,
}

impl AclState {
    fn new() -> Self {
        AclState {
            valid: 0,
            owner: AceState::EMPTY,
            group: AceState::EMPTY,
            other: AceState::EMPTY,
            everyone: AceState::EMPTY,
            users: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn saw(&self, tag: PosixTag) -> bool {
        (self.valid & tag as u16) != 0
    }

    /// `find_uid`/`find_gid` (`fs/nfsd/nfs4acl.c`): the slot for
    /// `id`, created on first sight seeded from `EVERYONE@`.
    ///
    /// The seed is what makes a late named entry answer for the ACEs that
    /// preceded it: `EVERYONE@` matched this principal too, so whatever it
    /// has already settled is already true of them. Takes the list rather
    /// than `&mut self` so the seed can be read while the list is borrowed.
    fn slot(
        list: &mut Vec<(i64, AceState)>,
        everyone: AceState,
        id: i64,
    ) -> usize {
        if let Some(i) = list.iter().position(|(x, _)| *x == id) {
            return i;
        }
        list.push((id, everyone));
        list.len() - 1
    }

    /// `process_one_v4_ace` (`fs/nfsd/nfs4acl.c`).
    ///
    /// A denial reaches further than the entity it names, because POSIX picks
    /// exactly one entry per caller and this conversion does not know which:
    /// a named user may be the owner, whose access POSIX reads off `USER_OBJ`
    /// alone, and a group's members may be any of the rest. Erring towards
    /// the denial is the whole reason the mapping is one-way.
    fn process(&mut self, ace: &Nfs4Ace) {
        let mask = ace.access_mask;
        let is_allow = ace.ace_type == Nfs4AceType::Allow;
        let tag = ace2tag(ace);
        self.valid |= tag as u16;
        match tag {
            PosixTag::UserObj => {
                if is_allow {
                    self.owner.allow_bits(mask);
                } else {
                    self.owner.deny_bits(mask);
                }
            }
            PosixTag::User => {
                let i = Self::slot(&mut self.users, self.everyone, ace.who_id);
                if is_allow {
                    self.users[i].1.allow_bits(mask);
                } else {
                    self.users[i].1.deny_bits(mask);
                    // The named user may be the owner, and POSIX would then
                    // never consult this entry at all.
                    let denied = self.users[i].1.deny;
                    self.owner.deny_bits(denied);
                }
            }
            PosixTag::GroupObj => {
                if is_allow {
                    self.group.allow_bits(mask);
                } else {
                    self.group.deny_bits(mask);
                    // Anyone at all may be in the owning group.
                    let denied = self.group.deny;
                    self.owner.deny_bits(denied);
                    self.everyone.deny_bits(denied);
                    deny_bits_all(&mut self.users, denied);
                    deny_bits_all(&mut self.groups, denied);
                }
            }
            PosixTag::Group => {
                let i = Self::slot(&mut self.groups, self.everyone, ace.who_id);
                if is_allow {
                    self.groups[i].1.allow_bits(mask);
                } else {
                    self.groups[i].1.deny_bits(mask);
                    // ...and likewise in a named group.
                    let denied = self.groups[i].1.deny;
                    self.owner.deny_bits(denied);
                    self.group.deny_bits(denied);
                    self.everyone.deny_bits(denied);
                    deny_bits_all(&mut self.users, denied);
                    deny_bits_all(&mut self.groups, denied);
                }
            }
            PosixTag::Other => {
                // `EVERYONE@` names every caller, the owner and the owning
                // group included, so it moves every entity at once.
                if is_allow {
                    self.owner.allow_bits(mask);
                    self.group.allow_bits(mask);
                    self.other.allow_bits(mask);
                    self.everyone.allow_bits(mask);
                    allow_bits_all(&mut self.users, mask);
                    allow_bits_all(&mut self.groups, mask);
                } else {
                    self.owner.deny_bits(mask);
                    self.group.deny_bits(mask);
                    self.other.deny_bits(mask);
                    self.everyone.deny_bits(mask);
                    deny_bits_all(&mut self.users, mask);
                    deny_bits_all(&mut self.groups, mask);
                }
            }
            // `ace2tag` has no MASK to return: NFS4 has no analogue of the
            // group-class mask, which is why the one below is derived.
            PosixTag::Mask => {}
        }
    }
}

/// `posix_state_to_acl` (`fs/nfsd/nfs4acl.c`): the entries one state
/// yields. Only the allowed sets are read - the denials have done their work
/// by carving those down.
fn state_to_entries(
    state: &AclState,
    is_dir: bool,
    default: bool,
) -> Vec<PosixAce> {
    let entry = |tag, perm, id| PosixAce {
        tag,
        perms: low_mode_from_nfs4(perm, is_dir),
        id,
        default,
    };
    let named = state.users.len() + state.groups.len();
    let mut out = Vec::with_capacity(4 + named);
    out.push(entry(PosixTag::UserObj, state.owner.allow, -1));
    for (id, p) in &state.users {
        out.push(entry(PosixTag::User, p.allow, *id));
    }
    out.push(entry(PosixTag::GroupObj, state.group.allow, -1));
    for (id, p) in &state.groups {
        out.push(entry(PosixTag::Group, p.allow, *id));
    }
    // `add_to_mask`: the group class's ceiling is everything any of its
    // members was allowed. A list with no named entry has no mask, and POSIX
    // then reads the owning group's rights directly.
    if named > 0 {
        let m = state
            .users
            .iter()
            .chain(&state.groups)
            .fold(state.group.allow, |acc, (_, p)| acc | p.allow);
        out.push(entry(PosixTag::Mask, m, -1));
    }
    out.push(entry(PosixTag::Other, state.other.allow, -1));
    out
}

impl Nfs4Acl {
    /// Convert to the POSIX1E ACL granting the closest access.
    ///
    /// A port of nfsd's shim (`fs/nfsd/nfs4acl.c`). What it loses is every
    /// right POSIX cannot name: `r` survives `READ_DATA`, `w` only when
    /// `WRITE_DATA`, `APPEND_DATA` and - on a directory - `DELETE_CHILD` are
    /// *all* granted, and `x` survives `EXECUTE`. `DELETE`, `WRITE_OWNER`,
    /// `WRITE_ACL`, `WRITE_ATTRIBUTES` and the named-attribute bits are
    /// dropped. The rounding is downward on purpose: a partial NFS4 write
    /// grant becomes no POSIX write at all, because the result decides access
    /// and rounding up would grant what the source refused.
    ///
    /// ACEs are read in wire order, which is the order NFS4 evaluates them
    /// in - a DENY binds only the bits no earlier ACE allowed - and a denial
    /// is written into every entity that might turn out to be the one POSIX
    /// consults, since POSIX picks one entry per caller and this cannot know
    /// which.
    ///
    /// `is_dir` picks the directory reading of the rights and gates the
    /// default ACL, which only a directory can carry. Inheritable ACEs become
    /// that default ACL, and `NO_PROPAGATE_INHERIT` cannot survive the trip:
    /// a POSIX default ACL is inherited by every descendant, so the result
    /// reaches depths the source stopped short of. AUDIT and ALARM ACEs are
    /// skipped - they settle no access, and ZFS will not store one anyway.
    ///
    /// The input is deliberately **not** validated: the trivial ACL ZFS
    /// synthesises for a directory carries no inheritance flags and would
    /// fail that check, and it is the single most common thing to convert.
    /// What the result must satisfy is checked instead, so a named principal
    /// whose id POSIX cannot hold - `0xFFFFFFFF`, which the kernel reads back
    /// as "no id" - is refused rather than written out as an entry that would
    /// decode as something else.
    ///
    /// An ACL with no ACEs at all converts to one granting nothing, as nfsd
    /// does. The empty `system.nfs4_acl_xdr` blob decodes to exactly that
    /// (see [`Nfs4Acl::from_xattr`]), so a caller holding one wants the mode
    /// bits, not this.
    pub fn to_posix_lossy(&self, is_dir: bool) -> Result<PosixAcl> {
        let mut effective = AclState::new();
        let mut inheritable = AclState::new();
        for ace in &self.aces {
            // AUDIT and ALARM settle no access, so they are skipped rather
            // than refused; ZFS will not store one in any case.
            if !matches!(ace.ace_type, Nfs4AceType::Allow | Nfs4AceType::Deny) {
                continue;
            }
            if is_dir && ace.ace_flags.intersects(INHERITABLE) {
                inheritable.process(ace);
            }
            // `INHERIT_ONLY` hands the ACE to children only. With no inherit
            // bit beside it there are no children to hand it to, so it
            // governs nothing anywhere.
            if !ace.ace_flags.contains(Nfs4Flag::INHERIT_ONLY) {
                effective.process(ace);
            }
        }

        // setfacl's rule, which nfsd adopts: a default ACL missing one of the
        // three required entries takes the effective ACL's. Without it a
        // directory carrying a single inheritable ACE would hand its children
        // a default ACL denying everything else, which is not what naming one
        // principal was meant to say.
        if inheritable.valid != 0 {
            if !inheritable.saw(PosixTag::UserObj) {
                inheritable.owner = effective.owner;
            }
            if !inheritable.saw(PosixTag::GroupObj) {
                inheritable.group = effective.group;
            }
            if !inheritable.saw(PosixTag::Other) {
                inheritable.other = effective.other;
            }
        }

        let mut aces = state_to_entries(&effective, is_dir, false);
        if inheritable.valid != 0 {
            aces.extend(state_to_entries(&inheritable, is_dir, true));
        }
        // `from_aces` puts each list in canonical tag order and sorts the
        // named runs by id, which is nfsd's `sort_pacl`.
        let acl = PosixAcl::from_aces(aces);
        acl.validate(is_dir)?;
        Ok(acl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_fs::acl::posix::synthesize_from_mode;
    use Nfs4AceType::{Allow, Deny};
    use PosixTag::{
        Group as G, GroupObj as GO, Mask as M, Other as O, User as U,
        UserObj as UO,
    };

    /// The NFS4 bits POSIX `r`, `w` and `x` stand for. `w` differs by object
    /// type: on a directory it is also the right to unlink a child.
    const R: Nfs4Perm = Nfs4Perm::READ_DATA;
    const X: Nfs4Perm = Nfs4Perm::EXECUTE;
    const W_FILE: Nfs4Perm = Nfs4Perm::WRITE_DATA.union(Nfs4Perm::APPEND_DATA);
    const W_DIR: Nfs4Perm = W_FILE.union(Nfs4Perm::DELETE_CHILD);
    const NONE: Nfs4Flag = Nfs4Flag::empty();
    /// The flags a POSIX default ACL is spelled with.
    const INH: Nfs4Flag = INHERITABLE.union(Nfs4Flag::INHERIT_ONLY);

    /// A POSIX entry, permissions written as an octal digit.
    fn pe(tag: PosixTag, id: i64, perms: u16) -> PosixAce {
        PosixAce {
            tag,
            perms: PosixPerm::from_bits_retain(perms),
            id,
            default: false,
        }
    }

    /// The same, in the default (inheritable) list.
    fn de(tag: PosixTag, id: i64, perms: u16) -> PosixAce {
        PosixAce {
            default: true,
            ..pe(tag, id, perms)
        }
    }

    /// A POSIX list reduced to the triples an assertion cares about.
    fn shape(aces: &[PosixAce]) -> Vec<(PosixTag, i64, u16)> {
        aces.iter().map(|a| (a.tag, a.id, a.perms.bits())).collect()
    }

    fn ace(
        t: Nfs4AceType,
        f: Nfs4Flag,
        m: Nfs4Perm,
        w: Nfs4Who,
        id: i64,
    ) -> Nfs4Ace {
        Nfs4Ace::new(t, f, m, w, id)
    }

    fn nfs4(aces: Vec<Nfs4Ace>) -> Nfs4Acl {
        Nfs4Acl {
            acl_flags: Nfs4AclFlag::empty(),
            aces,
        }
    }

    /// The mode bits are the subset both models spell the same way, so every
    /// one of the 512 of them has to come back unchanged - for a file and for
    /// a directory, whose `w` costs an extra NFS4 bit in both directions.
    /// This is the property anything reading an ACL to decide access relies
    /// on; everything below is about what happens outside it.
    #[test]
    fn the_mode_bits_survive_a_round_trip_through_nfs4() {
        for mode in 0..=0o777u32 {
            for is_dir in [false, true] {
                let src = synthesize_from_mode(mode);
                let nfs4 = src.to_nfs4_lossy(is_dir).expect("mode converts");
                let back = nfs4.to_posix_lossy(is_dir).expect("and back");
                assert_eq!(
                    shape(&back.access),
                    shape(&src.access),
                    "mode {mode:o} (is_dir {is_dir}) did not round-trip"
                );
                assert!(
                    back.default.is_none(),
                    "mode {mode:o} grew a default ACL"
                );
            }
        }
    }

    /// Named entries survive too, as long as the mask hides nothing: it is
    /// the *withholding* that NFS4 cannot express, not the entries.
    #[test]
    fn a_fully_effective_acl_survives_the_round_trip() {
        // GROUP_OBJ holds a right neither named entry does, so the mask
        // coming back has to be drawn from the whole group class.
        let src = PosixAcl::from_aces([
            pe(UO, -1, 0o7),
            pe(U, 1000, 0o4),
            pe(GO, -1, 0o6),
            pe(G, 2000, 0o1),
            pe(M, -1, 0o7),
            pe(O, -1, 0o4),
        ]);
        let back = src
            .to_nfs4_lossy(false)
            .unwrap()
            .to_posix_lossy(false)
            .unwrap();
        assert_eq!(shape(&back.access), shape(&src.access));
    }

    /// ...and when it does hide something, that is where the loss is. NFS4
    /// has no second-stage mask, so each entry goes out already reduced and
    /// the mask comes back as the union of what survived - the stored `rwx`
    /// is not recoverable.
    #[test]
    fn the_group_class_mask_is_folded_into_the_entries_it_limits() {
        let src = PosixAcl::from_aces([
            pe(UO, -1, 0o7),
            pe(U, 1000, 0o7),
            pe(GO, -1, 0o7),
            pe(M, -1, 0o5),
            pe(O, -1, 0o0),
        ]);
        let back = src
            .to_nfs4_lossy(false)
            .unwrap()
            .to_posix_lossy(false)
            .unwrap();
        assert_eq!(
            shape(&back.access),
            [
                (UO, -1, 0o7),
                (U, 1000, 0o5),
                (GO, -1, 0o5),
                (M, -1, 0o5),
                (O, -1, 0o0),
            ]
        );
    }

    /// The rights POSIX has no spelling for are the other half of the loss.
    /// An ACL that grants only these grants nothing at all once converted.
    #[test]
    fn rights_posix_cannot_name_are_dropped() {
        let unspellable = Nfs4Perm::DELETE
            | Nfs4Perm::WRITE_OWNER
            | Nfs4Perm::WRITE_ACL
            | Nfs4Perm::WRITE_ATTRIBUTES
            | Nfs4Perm::READ_NAMED_ATTRS
            | Nfs4Perm::WRITE_NAMED_ATTRS;
        let acl = nfs4(vec![
            ace(Allow, NONE, unspellable, Nfs4Who::Owner, -1),
            ace(Allow, NONE, unspellable, Nfs4Who::Group, -1),
            ace(Allow, NONE, unspellable, Nfs4Who::Everyone, -1),
        ]);
        let posix = acl.to_posix_lossy(false).unwrap();
        assert_eq!(
            shape(&posix.access),
            [(UO, -1, 0), (GO, -1, 0), (O, -1, 0)]
        );
    }

    /// A POSIX bit stands for several NFS4 bits, and holding some of them is
    /// not holding the bit. Rounding up here would grant a write the ACL
    /// never gave.
    #[test]
    fn a_partial_write_grant_rounds_down() {
        let owner_gets = |m: Nfs4Perm, is_dir: bool| {
            let acl = nfs4(vec![
                ace(Allow, NONE, m, Nfs4Who::Owner, -1),
                ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Group, -1),
                ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Everyone, -1),
            ]);
            acl.to_posix_lossy(is_dir).unwrap().access[0].perms
        };
        assert_eq!(owner_gets(Nfs4Perm::WRITE_DATA, false), PosixPerm::empty());
        assert_eq!(owner_gets(W_FILE, false), PosixPerm::WRITE);
        // On a directory the same pair is short of `w`: POSIX `w` there is
        // also the right to unlink, which NFS4 spells separately.
        assert_eq!(owner_gets(W_FILE, true), PosixPerm::empty());
        assert_eq!(owner_gets(W_DIR, true), PosixPerm::WRITE);
    }

    /// NFS4 settles a bit at the first ACE that names it, so the wire order
    /// is the meaning. Reading the ACEs in any other order silently inverts
    /// an ACL of this shape.
    #[test]
    fn a_deny_binds_only_the_bits_no_earlier_ace_allowed() {
        let other = |aces: Vec<Nfs4Ace>| {
            let acl = nfs4(aces);
            let posix = acl.to_posix_lossy(false).unwrap();
            posix.access.last().unwrap().perms
        };
        let allow_first = vec![
            ace(Allow, NONE, R | X, Nfs4Who::Everyone, -1),
            ace(Deny, NONE, R | X, Nfs4Who::Everyone, -1),
        ];
        let deny_first = vec![
            ace(Deny, NONE, R | X, Nfs4Who::Everyone, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Everyone, -1),
        ];
        assert_eq!(other(allow_first), PosixPerm::READ | PosixPerm::EXECUTE);
        assert_eq!(other(deny_first), PosixPerm::empty());
    }

    /// A denial reaches past the entity it names. POSIX consults exactly one
    /// entry per caller and this conversion cannot know which: a named user
    /// may be the file's owner, whose access POSIX reads off `USER_OBJ`
    /// alone. Leaving `USER_OBJ` alone hands that caller the access the NFS4
    /// ACL refused them, and no round trip can see it - the ACL is one POSIX
    /// cannot express faithfully in the first place.
    #[test]
    fn a_named_denial_binds_the_owner_it_might_be() {
        let acl = nfs4(vec![
            ace(Deny, NONE, W_FILE, Nfs4Who::Named, 1000),
            ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Owner, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Named, 1000),
            ace(Allow, NONE, R | X, Nfs4Who::Group, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Everyone, -1),
        ]);
        assert_eq!(
            shape(&acl.to_posix_lossy(false).unwrap().access),
            [
                (UO, -1, 0o5),
                (U, 1000, 0o5),
                (GO, -1, 0o5),
                (M, -1, 0o5),
                (O, -1, 0o5),
            ]
        );
    }

    /// A group denial reaches further still - anyone at all may be in the
    /// owning group or in a named one - so it binds every entity the state
    /// holds, and `EVERYONE@` carries it forward to entities not yet seen.
    #[test]
    fn a_group_denial_binds_every_entity_it_might_contain() {
        // u:1000 exists before the denial and holds only part of it, so the
        // denial has to be written into its entry as well. u:3000 is first
        // seen afterwards and inherits the denial through EVERYONE@.
        let tail = |deny: Nfs4Ace| {
            nfs4(vec![
                ace(Allow, NONE, R | X, Nfs4Who::Named, 1000),
                deny,
                ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Owner, -1),
                ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Group, -1),
                ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Everyone, -1),
                ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Named, 3000),
            ])
        };

        let owning = tail(ace(Deny, NONE, W_FILE, Nfs4Who::Group, -1));
        assert_eq!(
            shape(&owning.to_posix_lossy(false).unwrap().access),
            [
                (UO, -1, 0o5),
                (U, 1000, 0o5),
                (U, 3000, 0o5),
                (GO, -1, 0o5),
                (M, -1, 0o5),
                (O, -1, 0o7),
            ]
        );

        let named = tail(ace(
            Deny,
            Nfs4Flag::IDENTIFIER_GROUP,
            W_FILE,
            Nfs4Who::Named,
            2000,
        ));
        assert_eq!(
            shape(&named.to_posix_lossy(false).unwrap().access),
            [
                (UO, -1, 0o5),
                (U, 1000, 0o5),
                (U, 3000, 0o5),
                (GO, -1, 0o5),
                (G, 2000, 0o5),
                (M, -1, 0o5),
                (O, -1, 0o7),
            ]
        );
    }

    /// The spill is bounded by what the denial actually settled. A DENY of a
    /// bit an earlier ACE already allowed settles nothing, so it must reach
    /// nobody - taking the ACE's mask instead would strip the owner of a
    /// right the ACL never took from anyone.
    #[test]
    fn a_denial_of_what_is_already_allowed_spills_nowhere() {
        let acl = nfs4(vec![
            ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Group, -1),
            ace(Deny, NONE, W_FILE, Nfs4Who::Group, -1),
            ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Owner, -1),
        ]);
        assert_eq!(
            shape(&acl.to_posix_lossy(false).unwrap().access),
            [(UO, -1, 0o7), (GO, -1, 0o7), (O, -1, 0o0)]
        );
    }

    /// `EVERYONE@` names the owner and the owning group as well, which
    /// `other` does not - so an `EVERYONE@` grant has to reach every entity,
    /// and a named entry first seen afterwards has to start from what it
    /// already settled.
    #[test]
    fn an_everyone_ace_reaches_the_owner_and_every_named_entry() {
        let expected = [
            (UO, -1, 0o1),
            (U, 1000, 0o5),
            (GO, -1, 0o1),
            (M, -1, 0o5),
            (O, -1, 0o1),
        ];
        let named_first = nfs4(vec![
            ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Owner, -1),
            ace(Allow, NONE, R, Nfs4Who::Named, 1000),
            ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Group, -1),
            ace(Allow, NONE, X, Nfs4Who::Everyone, -1),
        ]);
        let named_last = nfs4(vec![
            ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Owner, -1),
            ace(Allow, NONE, Nfs4Perm::empty(), Nfs4Who::Group, -1),
            ace(Allow, NONE, X, Nfs4Who::Everyone, -1),
            ace(Allow, NONE, R, Nfs4Who::Named, 1000),
        ]);
        for acl in [named_first, named_last] {
            let posix = acl.to_posix_lossy(false).unwrap();
            assert_eq!(shape(&posix.access), expected);
        }
    }

    /// The inheritable ACEs are the default ACL and only the default ACL:
    /// an `INHERIT_ONLY` ACE is absent from the access half.
    #[test]
    fn inheritable_aces_become_the_default_acl() {
        let acl = nfs4(vec![
            ace(Allow, NONE, R | W_DIR | X, Nfs4Who::Owner, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Group, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Everyone, -1),
            ace(Allow, INH, R | W_DIR | X, Nfs4Who::Owner, -1),
            ace(Allow, INH, R, Nfs4Who::Group, -1),
            ace(Allow, INH, Nfs4Perm::empty(), Nfs4Who::Everyone, -1),
        ]);
        let posix = acl.to_posix_lossy(true).unwrap();
        assert_eq!(
            shape(&posix.access),
            [(UO, -1, 0o7), (GO, -1, 0o5), (O, -1, 0o5)]
        );
        let default = posix.default.expect("an inheritable half is a default");
        assert_eq!(
            shape(&default),
            [(UO, -1, 0o7), (GO, -1, 0o4), (O, -1, 0o0)]
        );
    }

    /// setfacl's rule, which nfsd adopts: one inheritable ACE naming one
    /// principal must not hand children a default ACL that denies every
    /// class it did not mention.
    #[test]
    fn the_default_acl_borrows_missing_classes_from_the_access_acl() {
        let acl = nfs4(vec![
            ace(Allow, NONE, R | W_DIR | X, Nfs4Who::Owner, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Group, -1),
            ace(Allow, NONE, R | X, Nfs4Who::Everyone, -1),
            ace(Allow, INH, R | X, Nfs4Who::Named, 1000),
        ]);
        let default = acl.to_posix_lossy(true).unwrap().default.unwrap();
        assert_eq!(
            shape(&default),
            [
                (UO, -1, 0o7),
                (U, 1000, 0o5),
                (GO, -1, 0o5),
                (M, -1, 0o5),
                (O, -1, 0o5),
            ]
        );
    }

    /// nfsd hands an `INHERIT_ONLY` ACE carrying neither inherit bit to the
    /// *effective* ACL, granting what the ACE says does not apply here. A
    /// file has nothing to inherit to either, so both halves drop it.
    #[test]
    fn an_inherit_only_ace_governs_nothing_where_nothing_inherits() {
        let acl = nfs4(vec![
            ace(
                Allow,
                Nfs4Flag::INHERIT_ONLY,
                R | W_FILE | X,
                Nfs4Who::Owner,
                -1,
            ),
            ace(Allow, INH, R | W_FILE | X, Nfs4Who::Group, -1),
        ]);
        let posix = acl.to_posix_lossy(false).unwrap();
        assert_eq!(
            shape(&posix.access),
            [(UO, -1, 0), (GO, -1, 0), (O, -1, 0)]
        );
        assert!(posix.default.is_none(), "a file inherits to nothing");
    }

    /// AUDIT and ALARM settle no access, so they are skipped rather than
    /// rejected the way nfsd rejects them. Ordered so that processing one
    /// would be visible: neither is an ALLOW, so it would read as a denial
    /// of everything the ALLOWs behind it grant.
    #[test]
    fn audit_and_alarm_aces_are_skipped() {
        for t in [Nfs4AceType::Audit, Nfs4AceType::Alarm] {
            let acl = nfs4(vec![
                ace(t, NONE, R | W_FILE | X, Nfs4Who::Everyone, -1),
                ace(Allow, NONE, R | W_FILE | X, Nfs4Who::Owner, -1),
                ace(Allow, NONE, R, Nfs4Who::Group, -1),
                ace(Allow, NONE, R, Nfs4Who::Everyone, -1),
            ]);
            let posix = acl.to_posix_lossy(false).unwrap();
            assert_eq!(
                shape(&posix.access),
                [(UO, -1, 0o7), (GO, -1, 0o4), (O, -1, 0o4)],
                "{t:?} was not skipped"
            );
        }
    }

    /// A POSIX ACL granting a class more than the owner needs a DENY on
    /// `OWNER@` to keep its meaning, and that is exactly what
    /// [`Nfs4Acl::validate`] will not write. The conversion emits it anyway:
    /// a writable ACL that grants the owner a write POSIX withheld is the
    /// worse answer.
    #[test]
    fn an_inverted_acl_needs_a_deny_validate_refuses() {
        // Owner may read; group and other may read and write.
        let src = synthesize_from_mode(0o466);
        let acl = src.to_nfs4_lossy(false).unwrap();
        assert_eq!(acl.aces[0].ace_type, Deny);
        assert_eq!(acl.aces[0].who_type, Nfs4Who::Owner);
        assert_eq!(acl.aces[0].access_mask, W_FILE);
        let e = acl.validate(false).unwrap_err().to_string();
        assert!(e.contains("DENY entries are not permitted"), "{e}");
        // The meaning survives even though the write does not.
        let back = acl.to_posix_lossy(false).unwrap();
        assert_eq!(shape(&back.access), shape(&src.access));
        // An ordinary mode needs no such entry and stays writable.
        let plain = synthesize_from_mode(0o644).to_nfs4_lossy(false).unwrap();
        assert!(plain.validate(false).is_ok());
    }

    /// A directory's default ACL is what makes the converted ACL satisfy
    /// `validate`'s inheritance rule; without one there is nothing
    /// inheritable to find.
    #[test]
    fn a_directory_default_acl_is_what_makes_the_result_writable() {
        // The halves differ, so an inheritable ACE reaching the access ACL
        // - which is what INHERIT_ONLY is there to prevent - shows up.
        let src = PosixAcl::from_aces([
            pe(UO, -1, 0o7),
            pe(GO, -1, 0o0),
            pe(O, -1, 0o0),
            de(UO, -1, 0o7),
            de(GO, -1, 0o5),
            de(O, -1, 0o5),
        ]);
        let acl = src.to_nfs4_lossy(true).unwrap();
        assert_eq!(acl.acl_flags, Nfs4AclFlag::ACL_IS_DIR);
        acl.validate(true).expect("a default ACL is inheritable");
        let back = acl.to_posix_lossy(true).unwrap();
        assert_eq!(shape(&back.access), shape(&src.access));
        assert_eq!(
            shape(&back.default.unwrap()),
            shape(src.default.as_deref().unwrap())
        );

        let bare = PosixAcl::from_aces([
            pe(UO, -1, 0o7),
            pe(GO, -1, 0o0),
            pe(O, -1, 0o0),
        ]);
        let acl = bare.to_nfs4_lossy(true).unwrap();
        let e = acl.validate(true).unwrap_err().to_string();
        assert!(e.contains("FILE_INHERIT"), "{e}");
    }

    /// The rights POSIX cannot withhold ride every ALLOW and no DENY, and
    /// they survive no round trip - `low_mode_from_nfs4` cannot see them, so
    /// nothing above would notice their absence. A converted ACL missing them
    /// refuses a stat, or an ACL read, that POSIX permits.
    #[test]
    fn allows_carry_what_posix_never_withholds_and_denies_do_not() {
        // Every class is granted something the owner is not, so each of the
        // four DENY shapes is emitted alongside the ALLOWs.
        let src = PosixAcl::from_aces([
            pe(UO, -1, 0o4),
            pe(U, 1000, 0o1),
            pe(GO, -1, 0o6),
            pe(G, 2000, 0o2),
            pe(M, -1, 0o7),
            pe(O, -1, 0o5),
            de(UO, -1, 0o4),
            de(GO, -1, 0o6),
            de(O, -1, 0o5),
        ]);
        let acl = src.to_nfs4_lossy(true).unwrap();
        let mut denies = 0;
        let mut owner_allows = 0;
        for a in &acl.aces {
            match a.ace_type {
                Allow => {
                    assert!(a.access_mask.contains(ANYONE_MODE), "{a:?}");
                    if a.access_mask.intersects(OWNER_MODE) {
                        assert_eq!(a.who_type, Nfs4Who::Owner, "{a:?}");
                        assert!(a.access_mask.contains(OWNER_MODE), "{a:?}");
                        owner_allows += 1;
                    }
                }
                // Denying READ_ATTRIBUTES or WRITE_ACL would withhold what
                // POSIX withholds from nobody.
                other => {
                    assert_eq!(other, Deny);
                    assert!(!a.access_mask.intersects(ANYONE_MODE), "{a:?}");
                    assert!(!a.access_mask.intersects(OWNER_MODE), "{a:?}");
                    denies += 1;
                }
            }
        }
        // Four in the access half - one per class that outranks the owner -
        // and two in the default half, which names no principal.
        assert_eq!(denies, 6, "{acl:?}");
        assert_eq!(owner_allows, 2, "one OWNER@ ALLOW per half");
    }

    /// The whole 32-bit range is a valid ZFS id, but the kernel reads
    /// `0xFFFFFFFF` back out of a POSIX entry as "no id". Refusing beats
    /// emitting an entry that decodes as something else.
    #[test]
    fn a_named_id_posix_cannot_hold_is_refused() {
        let with = |id: i64| {
            nfs4(vec![
                ace(Allow, NONE, R, Nfs4Who::Owner, -1),
                ace(Allow, NONE, R, Nfs4Who::Named, id),
                ace(Allow, NONE, R, Nfs4Who::Group, -1),
                ace(Allow, NONE, R, Nfs4Who::Everyone, -1),
            ])
            .to_posix_lossy(false)
        };
        let e = with(u32::MAX as i64).unwrap_err().to_string();
        assert!(e.contains("not a valid uid"), "{e}");
        assert!(with(u32::MAX as i64 - 1).is_ok());
    }

    /// The translation reads exactly one `USER_OBJ`, `GROUP_OBJ` and `OTHER`
    /// per list; nfsd asserts that shape rather than checking it, so the
    /// check has to happen before the walk.
    #[test]
    fn a_posix_acl_the_walk_cannot_read_is_refused() {
        let acl = PosixAcl::from_aces([pe(UO, -1, 0o7), pe(O, -1, 0o5)]);
        let e = acl.to_nfs4_lossy(false).unwrap_err().to_string();
        assert!(e.contains("GROUP_OBJ"), "{e}");
    }
}
