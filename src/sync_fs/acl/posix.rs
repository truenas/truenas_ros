//! POSIX1E ACLs (`system.posix_acl_access` / `_default`) - little-endian.

use crate::error::{Error, Result};

pub(crate) const POSIX_ACCESS_XATTR: &str = "system.posix_acl_access";
pub(crate) const POSIX_DEFAULT_XATTR: &str = "system.posix_acl_default";

const HDR_SZ: usize = 4;
const ACE_SZ: usize = 8;
const VERSION: u32 = 2;
const SPECIAL_ID: u32 = 0xFFFF_FFFF;

tn_enum! {
    /// The kind of a POSIX1E ACL entry.
    pub enum PosixTag: u16 {
        /// The file owner's permissions.
        UserObj = 0x01,
        /// A named user's permissions.
        User = 0x02,
        /// The owning group's permissions.
        GroupObj = 0x04,
        /// A named group's permissions.
        Group = 0x08,
        /// The mask limiting group-class permissions.
        Mask = 0x10,
        /// Everyone else's permissions.
        Other = 0x20,
    }
}

impl PosixTag {
    /// True for the tags whose `id` is always the special sentinel.
    fn is_special(self) -> bool {
        matches!(
            self,
            PosixTag::UserObj
                | PosixTag::GroupObj
                | PosixTag::Mask
                | PosixTag::Other
        )
    }
}

tn_bitflags! {
    /// POSIX1E permission bits.
    pub struct PosixPerm: u16 {
        /// Execute (or search, for directories).
        EXECUTE = 0x1;
        /// Write.
        WRITE = 0x2;
        /// Read.
        READ = 0x4;
    }
}

/// The kernel's `posix_acl_create_masq` (`fs/posix_acl.c`), transcribed.
///
/// It intersects a freshly-inherited access ACL with the create mode and
/// narrows the mode by what survives, returning the narrowed mode. Both
/// directions matter: the ACL is what the child ends up with, and the mode
/// is what `getattr` reports.
///
/// ```text
/// case ACL_USER_OBJ:
///         pa->e_perm &= (mode >> 6) | ~S_IRWXO;
///         mode &= (pa->e_perm << 6) | ~S_IRWXU;
/// case ACL_USER: case ACL_GROUP:  not_equiv = 1;
/// case ACL_GROUP_OBJ:             group_obj = pa;
/// case ACL_OTHER:
///         pa->e_perm &= mode | ~S_IRWXO;
///         mode &= pa->e_perm | ~S_IRWXO;
/// case ACL_MASK:                  mask_obj = pa; not_equiv = 1;
/// ...
/// if (mask_obj) {
///         mask_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
///         mode &= (mask_obj->e_perm << 3) | ~S_IRWXG;
/// } else {
///         group_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
///         mode &= (group_obj->e_perm << 3) | ~S_IRWXG;
/// }
/// ```
///
/// `~S_IRWXO` is the identity on a three-bit permission field, so each
/// `&= x | ~S_IRWXO` is `&= x & 7` here. The `MASK`/`GROUP_OBJ` step runs
/// *after* the loop and reads the mode the loop already narrowed, which is
/// why it cannot be folded into it.
///
/// `ACL_MASK` and `ACL_GROUP_OBJ` are an either/or in the C and so here: a
/// `Mask` entry supersedes `GroupObj` for the group class. An ACL with
/// neither is malformed - the C answers `-EIO` - and so is one this crate
/// would refuse in [`validate`](PosixAcl::validate).
fn create_masq(access: &mut [PosixAce], mode: u32) -> Result<u32> {
    const RWX: u16 = 0o7;
    let mut m = mode;
    let mut group_obj: Option<usize> = None;
    let mut mask_obj: Option<usize> = None;
    for (i, a) in access.iter_mut().enumerate() {
        match a.tag {
            PosixTag::UserObj => {
                a.perms &=
                    PosixPerm::from_bits_truncate(((m >> 6) as u16) & RWX);
                m &= ((a.perms.bits() as u32) << 6) | !0o700;
            }
            PosixTag::Other => {
                a.perms &= PosixPerm::from_bits_truncate((m as u16) & RWX);
                m &= u32::from(a.perms.bits()) | !0o007;
            }
            PosixTag::GroupObj => group_obj = Some(i),
            PosixTag::Mask => mask_obj = Some(i),
            // The C answers `-EIO` for any other tag; this enum has none,
            // so there is no arm to write rather than one left off.
            PosixTag::User | PosixTag::Group => {}
        }
    }
    let group_class = mask_obj.or(group_obj).ok_or_else(|| {
        Error::Validation("ACL has neither a MASK nor a GROUP_OBJ entry".into())
    })?;
    let a = &mut access[group_class];
    a.perms &= PosixPerm::from_bits_truncate(((m >> 3) as u16) & RWX);
    m &= (u32::from(a.perms.bits()) << 3) | !0o070;
    Ok((mode & !0o777) | (m & 0o777))
}

/// A single POSIX1E ACL entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosixAce {
    /// The entry kind.
    pub tag: PosixTag,
    /// The permissions granted.
    pub perms: PosixPerm,
    /// The uid/gid for `User`/`Group` entries; `-1` for special entries.
    pub id: i64,
    /// True if this entry belongs to the default (inheritable) ACL.
    pub default: bool,
}

/// A POSIX1E ACL: an access list plus an optional default (inheritable) list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosixAcl {
    /// The access ACL entries.
    pub access: Vec<PosixAce>,
    /// The default ACL entries (`None` if there is no default ACL xattr).
    pub default: Option<Vec<PosixAce>>,
    // True when `access` was synthesised from mode bits (no access xattr).
    synthesized: bool,
}

#[inline]
fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
#[inline]
fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

fn parse_aces(data: &[u8], is_default: bool) -> Result<Vec<PosixAce>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() < HDR_SZ {
        return Err(Error::Parse("POSIX ACL too short".into()));
    }
    if le32(data, 0) != VERSION {
        return Err(Error::Parse("unsupported POSIX ACL version".into()));
    }
    if !(data.len() - HDR_SZ).is_multiple_of(ACE_SZ) {
        return Err(Error::Parse("POSIX ACL has a partial entry".into()));
    }
    let naces = (data.len() - HDR_SZ) / ACE_SZ;
    let mut out = Vec::with_capacity(naces);
    for i in 0..naces {
        let p = HDR_SZ + i * ACE_SZ;
        let tag = PosixTag::try_from(le16(data, p))
            .map_err(|_| Error::Parse("unknown POSIX ACL tag".into()))?;
        let perms = PosixPerm::from_bits_retain(le16(data, p + 2));
        let xid = le32(data, p + 4);
        // Read `e_id` exactly as the kernel does (`fs/posix_acl.c`): a special
        // tag's id field is written as `ACL_UNDEFINED_ID` and ignored on the
        // way back in (`posix_acl_from_xattr` does not even load it), so it
        // carries no id whatever the wire says. A *named* tag holding the
        // sentinel is malformed - `encode_aces` cannot write it back, so
        // accepting it would decode a blob we can never re-emit.
        let id = if tag.is_special() {
            -1
        } else if xid == SPECIAL_ID {
            return Err(Error::Parse(
                "POSIX ACL named entry carries the undefined-id sentinel"
                    .into(),
            ));
        } else {
            xid as i64
        };
        out.push(PosixAce {
            tag,
            perms,
            id,
            default: is_default,
        });
    }
    Ok(out)
}

fn encode_aces(aces: &[PosixAce]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HDR_SZ + aces.len() * ACE_SZ);
    out.extend_from_slice(&VERSION.to_le_bytes());
    for a in aces {
        let xid = if a.tag.is_special() {
            SPECIAL_ID
        } else {
            match u32::try_from(a.id) {
                Ok(xid) if xid != SPECIAL_ID => xid,
                _ => {
                    return Err(Error::Validation(format!(
                        "POSIX ACL entry id {} is not a valid uid/gid",
                        a.id
                    )));
                }
            }
        };
        out.extend_from_slice(&(a.tag as u16).to_le_bytes());
        out.extend_from_slice(&a.perms.bits().to_le_bytes());
        out.extend_from_slice(&xid.to_le_bytes());
    }
    Ok(out)
}

impl PosixAcl {
    /// Decode from the raw little-endian access (and optional default) xattr
    /// bytes.
    pub fn from_xattr(access: &[u8], default: Option<&[u8]>) -> Result<Self> {
        let access = parse_aces(access, false)?;
        let default = match default {
            Some(d) => Some(parse_aces(d, true)?),
            None => None,
        };
        Ok(PosixAcl {
            access,
            default,
            synthesized: false,
        })
    }

    /// Build an ACL from entries, splitting on [`PosixAce::default`] and
    /// sorting each list by `(tag, id)` (stable), matching the C `from_aces`.
    /// An empty default list yields `None`.
    pub fn from_aces<I>(aces: I) -> Self
    where
        I: IntoIterator<Item = PosixAce>,
    {
        let mut access = Vec::new();
        let mut default = Vec::new();
        for a in aces {
            if a.default {
                default.push(a);
            } else {
                access.push(a);
            }
        }
        let key = |a: &PosixAce| (a.tag as u16, a.id);
        access.sort_by_key(key);
        default.sort_by_key(key);
        PosixAcl {
            access,
            default: (!default.is_empty()).then_some(default),
            synthesized: false,
        }
    }

    /// Raw bytes for `system.posix_acl_access`. Errors if a named entry's id
    /// is not a valid uid/gid.
    pub fn access_bytes(&self) -> Result<Vec<u8>> {
        encode_aces(&self.access)
    }

    /// Raw bytes for `system.posix_acl_default`, or `None` if there is no
    /// default ACL. Errors if a named entry's id is not a valid uid/gid.
    pub fn default_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.default.as_deref().map(encode_aces).transpose()
    }

    /// True if the access ACL was synthesised from mode bits and there is no
    /// default ACL. An ACL you construct yourself is never trivial.
    pub fn trivial(&self) -> bool {
        self.synthesized && self.default.is_none()
    }

    /// Produce the ACL a new child object inherits from this directory's
    /// default ACL, and the mode it is created with.
    ///
    /// Errors if this ACL is trivial or has no default ACL.
    ///
    /// `mode` is the **requested** creation mode, unmasked. A raw mode word
    /// rather than `sync_fs::Mode`, because this module compiles under the
    /// `acl` feature alone and that type is `sync-fs`'s. The umask is
    /// deliberately not applied: `posix_acl_create`
    /// (`fs/posix_acl.c`) applies `current_umask()` only on the branch where
    /// the parent has **no** default ACL, and takes this one instead when it
    /// has - the intersection below does the narrowing in its place.
    ///
    /// # The mode is not a formality
    ///
    /// The default ACL is not copied down verbatim.
    /// `posix_acl_create_masq` intersects it with the create mode, and the
    /// intersection runs both ways: the entries are narrowed by the mode and
    /// the mode is narrowed by what survives. Predicting without it says
    /// group and other have access they do not have. Measured against the
    /// kernel, parent default `rwx` on all four entries:
    ///
    /// ```text
    /// verbatim copy (what this used to answer):
    ///     USER_OBJ:7 GROUP_OBJ:7 MASK:7 OTHER:7
    /// kernel, child dir created 0o700:
    ///     USER_OBJ:7 GROUP_OBJ:7 MASK:0 OTHER:0
    /// kernel, child file created 0o600:
    ///     USER_OBJ:6 GROUP_OBJ:7 MASK:0 OTHER:0
    /// ```
    ///
    /// # When the child gets no access ACL at all
    ///
    /// `posix_acl_create` releases the masq'd ACL when it comes out
    /// *equivalent to the mode* - no `User`, `Group` or `Mask` entry - and
    /// stores only the mode. The returned ACL is still the right answer
    /// about effective permissions there, since that is what equivalence
    /// means, but it is not what `getxattr` would find:
    /// [`equivalent_to_mode`](PosixAcl::equivalent_to_mode) is the same
    /// question this makes the kernel ask.
    pub fn generate_inherited_acl(
        &self,
        is_dir: bool,
        mode: u32,
    ) -> Result<(Self, u32)> {
        if self.access.is_empty() && self.default.is_none() {
            return Err(Error::Validation(
                "cannot generate inherited ACL from trivial ACL".into(),
            ));
        }
        let default = self.default.as_ref().ok_or_else(|| {
            Error::Validation(
                "cannot generate inherited ACL: no default ACL".into(),
            )
        })?;
        let mut access: Vec<PosixAce> = default
            .iter()
            .map(|a| PosixAce {
                default: false,
                ..a.clone()
            })
            .collect();
        let new_mode = create_masq(&mut access, mode)?;
        let new_default = is_dir.then(|| {
            default
                .iter()
                .map(|a| PosixAce {
                    default: true,
                    ..a.clone()
                })
                .collect()
        });
        Ok((
            PosixAcl {
                access,
                default: new_default,
                synthesized: false,
            },
            new_mode,
        ))
    }

    /// Whether this ACL's access entries say no more than the mode bits do -
    /// no `User`, `Group` or `Mask` entry.
    ///
    /// The kernel's `not_equiv` (`posix_acl_create_masq`, `fs/posix_acl.c`),
    /// and it decides whether a created child carries an access ACL at all:
    /// `posix_acl_create` releases the ACL and keeps only the mode when this
    /// is true.
    pub fn equivalent_to_mode(&self) -> bool {
        !self.access.iter().any(|a| {
            matches!(a.tag, PosixTag::User | PosixTag::Group | PosixTag::Mask)
        })
    }

    /// Structural validation: the C `posixacl_valid` tag rules plus the
    /// checks the kernel makes in `posix_acl_valid` (permission bits confined
    /// to rwx, entries in canonical tag order).
    pub(crate) fn validate(&self, is_dir: bool) -> Result<()> {
        validate_entries(&self.access, "access")?;
        if let Some(default) = &self.default {
            if !is_dir {
                return Err(Error::Validation(
                    "default ACL is only valid on directories".into(),
                ));
            }
            validate_entries(default, "default")?;
        }
        Ok(())
    }

    /// Decode and attach a default ACL from raw xattr bytes.
    pub(crate) fn set_default_from_xattr(&mut self, data: &[u8]) -> Result<()> {
        self.default = Some(parse_aces(data, true)?);
        Ok(())
    }
}

/// A synthetic 3-entry access ACL derived from mode bits, used when
/// `system.posix_acl_access` is absent (matching `getfacl(1)`).
pub(crate) fn synthesize_from_mode(mode: u32) -> PosixAcl {
    let mk = |tag, three: u32| PosixAce {
        tag,
        perms: PosixPerm::from_bits_retain((three & 7) as u16),
        id: -1,
        default: false,
    };
    PosixAcl {
        access: vec![
            mk(PosixTag::UserObj, mode >> 6),
            mk(PosixTag::GroupObj, mode >> 3),
            mk(PosixTag::Other, mode),
        ],
        default: None,
        synthesized: true,
    }
}

/// Check that a named USER/GROUP entry carries an id the wire format can hold:
/// a 32-bit value other than the sentinel the kernel reads back as "no id"
/// (`uid_valid`, `include/linux/uidgid.h`).
fn validate_named_id(
    id: i64,
    label: &str,
    tag: &str,
    kind: &str,
) -> Result<()> {
    if id < 0 {
        return Err(Error::Validation(format!(
            "{label} ACL: named {tag} entry has no {kind}"
        )));
    }
    if u32::try_from(id).is_err() || id == SPECIAL_ID as i64 {
        return Err(Error::Validation(format!(
            "{label} ACL: named {tag} entry {kind} {id} is not a valid {kind}"
        )));
    }
    Ok(())
}

fn validate_entries(aces: &[PosixAce], label: &str) -> Result<()> {
    let (mut user_obj, mut group_obj, mut other, mut mask, mut named) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    // The tag values ascend in the canonical entry order (USER_OBJ, USER,
    // GROUP_OBJ, GROUP, MASK, OTHER), so - given the tag counts checked
    // below - a non-decreasing tag value is exactly the sequence the
    // kernel's state machine accepts (`fs/posix_acl.c:posix_acl_valid`).
    let mut prev_tag = 0u16;
    for a in aces {
        if !PosixPerm::all().contains(a.perms) {
            return Err(Error::Validation(format!(
                "{label} ACL: entry has permission bits outside rwx"
            )));
        }
        if (a.tag as u16) < prev_tag {
            return Err(Error::Validation(format!(
                "{label} ACL entries are not in canonical tag order"
            )));
        }
        prev_tag = a.tag as u16;
        match a.tag {
            PosixTag::UserObj => user_obj += 1,
            PosixTag::GroupObj => group_obj += 1,
            PosixTag::Other => other += 1,
            PosixTag::Mask => mask += 1,
            PosixTag::User => {
                validate_named_id(a.id, label, "USER", "uid")?;
                named += 1;
            }
            PosixTag::Group => {
                validate_named_id(a.id, label, "GROUP", "gid")?;
                named += 1;
            }
        }
    }
    if user_obj != 1 {
        return Err(Error::Validation(format!(
            "{label} ACL must have exactly one USER_OBJ entry"
        )));
    }
    if group_obj != 1 {
        return Err(Error::Validation(format!(
            "{label} ACL must have exactly one GROUP_OBJ entry"
        )));
    }
    if other != 1 {
        return Err(Error::Validation(format!(
            "{label} ACL must have exactly one OTHER entry"
        )));
    }
    if named > 0 && mask != 1 {
        return Err(Error::Validation(format!(
            "{label} ACL must have exactly one MASK entry when named USER \
             or GROUP entries are present"
        )));
    }
    if mask > 1 {
        return Err(Error::Validation(format!(
            "{label} ACL has more than one MASK entry"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(tag: PosixTag, id: i64) -> PosixAce {
        PosixAce {
            tag,
            perms: PosixPerm::READ,
            id,
            default: false,
        }
    }

    /// A 4-byte version-2 header followed by one raw entry.
    fn blob(tag: u16, xid: u32) -> Vec<u8> {
        let mut b = VERSION.to_le_bytes().to_vec();
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&PosixPerm::READ.bits().to_le_bytes());
        b.extend_from_slice(&xid.to_le_bytes());
        b
    }

    /// `e_id` is read exactly as `fs/posix_acl.c` reads it: ignored for a
    /// special tag, and never the undefined sentinel on a named one. Both
    /// halves keep decode and encode symmetric - without them `from_xattr`
    /// accepts blobs `access_bytes` either refuses or re-emits differently.
    #[test]
    fn entry_ids_decode_the_way_the_kernel_writes_them() {
        // A named entry holding ACL_UNDEFINED_ID has no id to encode back.
        let named = blob(PosixTag::User as u16, SPECIAL_ID);
        assert!(PosixAcl::from_xattr(&named, None).is_err());

        // A special entry's id field is ignored, so a stray value normalizes
        // to -1 and re-encodes as the sentinel rather than round-tripping.
        let stray = blob(PosixTag::Mask as u16, 5);
        let acl = PosixAcl::from_xattr(&stray, None).expect("mask decodes");
        assert_eq!(acl.access[0].id, -1);
        let out = acl.access_bytes().expect("decoded ACL re-encodes");
        assert_eq!(out, blob(PosixTag::Mask as u16, SPECIAL_ID));
        // ...and normalization is a fixed point from there.
        assert_eq!(
            PosixAcl::from_xattr(&out, None)
                .unwrap()
                .access_bytes()
                .unwrap(),
            out
        );
    }

    #[test]
    fn decode_rejects_bad_version_and_partial_entry() {
        // Wrong version word in the 4-byte header.
        assert!(PosixAcl::from_xattr(&[9, 0, 0, 0], None).is_err());
        // Version 2, then a 5-byte trailing partial entry (entries are 8).
        let mut blob = vec![2u8, 0, 0, 0];
        blob.extend_from_slice(&[1, 0, 0, 0, 0]);
        assert!(PosixAcl::from_xattr(&blob, None).is_err());
    }

    /// A minimal valid access ACL whose named USER entry carries `id`.
    fn named_user(id: i64) -> PosixAcl {
        PosixAcl::from_aces([
            ace(PosixTag::UserObj, -1),
            ace(PosixTag::User, id),
            ace(PosixTag::GroupObj, -1),
            ace(PosixTag::Mask, -1),
            ace(PosixTag::Other, -1),
        ])
    }

    #[test]
    fn validate_rejects_unrepresentable_named_ids() {
        assert!(named_user(1000).validate(false).is_ok());
        assert!(named_user(u32::MAX as i64 - 1).validate(false).is_ok());
        // The sentinel the kernel reads back as "no id".
        assert!(named_user(SPECIAL_ID as i64).validate(false).is_err());
        // Wider than the 32-bit wire field.
        assert!(named_user(u32::MAX as i64 + 1).validate(false).is_err());
        assert!(named_user(-1).validate(false).is_err());
    }

    #[test]
    fn encoding_an_unrepresentable_named_id_errors() {
        assert!(named_user(1000).access_bytes().is_ok());
        assert!(named_user(SPECIAL_ID as i64).access_bytes().is_err());
        assert!(named_user(u32::MAX as i64 + 1).access_bytes().is_err());
        // A special entry's `id` is never encoded.
        assert!(
            PosixAcl::from_aces([ace(PosixTag::UserObj, i64::MAX)])
                .access_bytes()
                .is_ok()
        );
        // The default list is encoded by the same rules.
        let mut acl = named_user(1000);
        acl.default = Some(vec![PosixAce {
            default: true,
            ..ace(PosixTag::Group, u32::MAX as i64 + 1)
        }]);
        assert!(acl.default_bytes().is_err());
    }

    #[test]
    fn validate_rejects_what_the_kernel_rejects() {
        let mut acl = named_user(1000);
        acl.access.reverse();
        let e = acl.validate(false).unwrap_err().to_string();
        assert!(e.contains("canonical tag order"), "{e}");
        // A default list the kernel would refuse is rejected by validate.
        let mut acl = named_user(1000);
        acl.default = Some(
            [PosixTag::Other, PosixTag::UserObj, PosixTag::GroupObj]
                .map(|tag| PosixAce {
                    default: true,
                    ..ace(tag, -1)
                })
                .to_vec(),
        );
        let e = acl.validate(true).unwrap_err().to_string();
        assert!(e.contains("default ACL entries are not"), "{e}");
        // Permission bits outside rwx.
        let mut acl = named_user(1000);
        acl.access[0].perms = PosixPerm::from_bits_retain(0x8);
        let e = acl.validate(false).unwrap_err().to_string();
        assert!(e.contains("outside rwx"), "{e}");
    }

    #[test]
    fn synthesize_from_mode_matches_getfacl() {
        let acl = synthesize_from_mode(0o644);
        assert!(acl.trivial());
        assert_eq!(acl.access.len(), 3);
        assert_eq!(acl.access[0].tag, PosixTag::UserObj);
        assert_eq!(acl.access[0].perms, PosixPerm::READ | PosixPerm::WRITE);
        assert_eq!(acl.access[1].tag, PosixTag::GroupObj);
        assert_eq!(acl.access[1].perms, PosixPerm::READ);
        assert_eq!(acl.access[2].tag, PosixTag::Other);
        assert_eq!(acl.access[2].perms, PosixPerm::READ);
        // 4-byte version header + 3 * 8-byte entries.
        assert_eq!(acl.access_bytes().unwrap().len(), 28);
    }

    #[test]
    fn trivial_only_when_synthesized_and_no_default() {
        assert!(
            !PosixAcl::from_aces([PosixAce {
                tag: PosixTag::UserObj,
                perms: PosixPerm::READ,
                id: -1,
                default: false,
            }])
            .trivial()
        );
        assert!(synthesize_from_mode(0o600).trivial());
    }

    /// The prediction is the kernel's, so the kernel is the oracle.
    ///
    /// A parent directory carrying a default ACL, a child created under it,
    /// and the crate's answer compared against what `getxattr` finds - not
    /// against a transcription of the arithmetic, which would pass on a
    /// transcription that is wrong in both places.
    ///
    /// Copied verbatim, as this did before, a default of `rwx` on all four
    /// entries predicts `MASK:rwx OTHER:rwx` for a child made `0o700`,
    /// where the kernel gives `MASK:--- OTHER:---`: group and other told
    /// they have full access when they have none.
    ///
    /// Skips where the filesystem has no POSIX ACLs; held to
    /// `TRUENAS_ROS_REQUIRE_POSIX_ACL` where CI arms it, because a silent
    /// skip here is a test that asserts nothing about the one thing it is
    /// for.
    #[test]
    fn the_inherited_acl_matches_what_the_kernel_creates() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::tempdir().expect("tempdir");
        let cpath = |p: &std::path::Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes()).expect("path")
        };

        // Two parent default ACLs, because one of them cannot fail.
        //
        // `rwx` everywhere is *wider* than either create mode below, so the
        // mode survives the intersection unchanged and the predicted mode is
        // the requested mode - an assertion that reads as checking the
        // arithmetic and restates its input. `r-x` on `USER_OBJ` is
        // narrower, and there the mode comes back `0o500`/`0o400`: that row
        // is what makes the mode assertion an assertion.
        //
        // A named user in both, so the result is not mode-equivalent and the
        // kernel really stores an access ACL on the child.
        for (shape, owner) in [
            ("wide", PosixPerm::all()),
            ("narrow", PosixPerm::READ | PosixPerm::EXECUTE),
        ] {
            let parent = dir.path().join(format!("p_{shape}"));
            std::fs::create_dir(&parent).expect("parent");
            let entries = [
                (PosixTag::UserObj, -1i64),
                (PosixTag::User, 1000),
                (PosixTag::GroupObj, -1),
                (PosixTag::Mask, -1),
                (PosixTag::Other, -1),
            ];
            let default: Vec<PosixAce> = entries
                .iter()
                .map(|&(tag, id)| PosixAce {
                    tag,
                    perms: if tag == PosixTag::UserObj {
                        owner
                    } else {
                        PosixPerm::all()
                    },
                    id,
                    default: true,
                })
                .collect();
            let blob = encode_aces(&default).expect("encode");
            let cp = cpath(&parent);
            // SAFETY: valid NUL-terminated path and a sized buffer.
            let rc = unsafe {
                libc::setxattr(
                    cp.as_ptr(),
                    c"system.posix_acl_default".as_ptr(),
                    blob.as_ptr().cast(),
                    blob.len(),
                    0,
                )
            };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
                    "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but the fixture \
                 filesystem refuses a default ACL: {e}"
                );
                return;
            }

            let parent_acl = PosixAcl::from_xattr(&[], Some(&blob))
                .expect("the default reads back");

            for (name, mode, is_dir) in
                [("cd", 0o700u32, true), ("cf", 0o600, false)]
            {
                let child = parent.join(name);
                // The umask must not narrow this: `posix_acl_create` applies it
                // only on the branch where the parent has NO default ACL.
                let old = unsafe { libc::umask(0) };
                if is_dir {
                    // `mkdir` WITH the mode, not `create_dir` then `chmod`. A
                    // chmod is not a second spelling of the create: it sets
                    // `USER_OBJ`/`MASK`/`OTHER` from the mode it is given
                    // (`posix_acl_chmod`), so it overwrites both halves of what
                    // inheritance produced and this compares the prediction
                    // against the chmod's arithmetic instead of the kernel's
                    // `posix_acl_create`. Measured on a `posixacl` dataset, with
                    // the narrow default above and a `0o700` child: `mkdir`
                    // gives `mode 0500, user::r-x`, create-then-chmod gives
                    // `mode 0700, user::rwx`. The two agree only for a default
                    // wider than the mode, which is the one shape this used to
                    // build.
                    let cc = cpath(&child);
                    // SAFETY: valid NUL-terminated path and an explicit mode.
                    let rc = unsafe {
                        libc::mkdir(cc.as_ptr(), mode as libc::mode_t)
                    };
                    assert_eq!(
                        rc,
                        0,
                        "child dir: {}",
                        std::io::Error::last_os_error()
                    );
                } else {
                    let cc = cpath(&child);
                    // SAFETY: valid path; O_CREAT with an explicit mode.
                    let fd = unsafe {
                        libc::open(
                            cc.as_ptr(),
                            libc::O_CREAT | libc::O_RDWR,
                            mode as libc::c_uint,
                        )
                    };
                    assert!(fd >= 0, "child file");
                    // SAFETY: a descriptor this call just opened.
                    unsafe { libc::close(fd) };
                }
                unsafe { libc::umask(old) };

                let mut buf = [0u8; 512];
                let cc = cpath(&child);
                // SAFETY: valid path and a sized destination.
                let n = unsafe {
                    libc::getxattr(
                        cc.as_ptr(),
                        c"system.posix_acl_access".as_ptr(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                };
                assert!(n > 0, "the kernel stored no access ACL on {name}");
                let actual = PosixAcl::from_xattr(&buf[..n as usize], None)
                    .expect("the kernel's ACL decodes");

                let (predicted, predicted_mode) = parent_acl
                    .generate_inherited_acl(is_dir, mode)
                    .expect("a default ACL is present");
                assert_eq!(
                    predicted.access, actual.access,
                    "{shape}/{name}: predicted vs the kernel's own"
                );
                // The other half of the same intersection, and the one `getattr`
                // reports: `posix_acl_create_masq` narrows the entries by the
                // mode AND the mode by what survives. Checking only the entries
                // leaves the second return value of `generate_inherited_acl`
                // with no oracle at all.
                let actual_mode = std::fs::symlink_metadata(&child)
                    .expect("stat the child")
                    .permissions()
                    .mode()
                    & 0o7777;
                assert_eq!(
                    predicted_mode & 0o7777,
                    actual_mode,
                    "{shape}/{name}: predicted create mode vs the kernel's own"
                );
            }
        }
    }

    #[test]
    fn generate_inherited_needs_a_default_acl() {
        assert!(
            synthesize_from_mode(0o755)
                .generate_inherited_acl(true, 0o755)
                .is_err()
        );
    }
}
