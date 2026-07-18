//! POSIX1E ACLs (`system.posix_acl_access` / `_default`) — little-endian.

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
    let naces = (data.len() - HDR_SZ) / ACE_SZ;
    let mut out = Vec::with_capacity(naces);
    for i in 0..naces {
        let p = HDR_SZ + i * ACE_SZ;
        let tag = PosixTag::try_from(le16(data, p))
            .map_err(|_| Error::Parse("unknown POSIX ACL tag".into()))?;
        let perms = PosixPerm::from_bits_retain(le16(data, p + 2));
        let xid = le32(data, p + 4);
        let id = if xid == SPECIAL_ID { -1 } else { xid as i64 };
        out.push(PosixAce {
            tag,
            perms,
            id,
            default: is_default,
        });
    }
    Ok(out)
}

fn encode_aces(aces: &[PosixAce]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_SZ + aces.len() * ACE_SZ);
    out.extend_from_slice(&VERSION.to_le_bytes());
    for a in aces {
        let xid = if a.tag.is_special() {
            SPECIAL_ID
        } else {
            a.id as u32
        };
        out.extend_from_slice(&(a.tag as u16).to_le_bytes());
        out.extend_from_slice(&a.perms.bits().to_le_bytes());
        out.extend_from_slice(&xid.to_le_bytes());
    }
    out
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

    /// Raw bytes for `system.posix_acl_access`.
    pub fn access_bytes(&self) -> Vec<u8> {
        encode_aces(&self.access)
    }

    /// Raw bytes for `system.posix_acl_default`, or `None` if there is no
    /// default ACL.
    pub fn default_bytes(&self) -> Option<Vec<u8>> {
        self.default.as_deref().map(encode_aces)
    }

    /// True if the access ACL was synthesised from mode bits and there is no
    /// default ACL. An ACL you construct yourself is never trivial.
    pub fn trivial(&self) -> bool {
        self.synthesized && self.default.is_none()
    }

    /// Produce the ACL a new child object inherits from this directory's
    /// default ACL. Errors if this ACL is trivial or has no default ACL.
    pub fn generate_inherited_acl(&self, is_dir: bool) -> Result<Self> {
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
        let access = default
            .iter()
            .map(|a| PosixAce {
                default: false,
                ..a.clone()
            })
            .collect();
        let new_default = is_dir.then(|| {
            default
                .iter()
                .map(|a| PosixAce {
                    default: true,
                    ..a.clone()
                })
                .collect()
        });
        Ok(PosixAcl {
            access,
            default: new_default,
            synthesized: false,
        })
    }

    /// Structural validation (matching the C `posixacl_valid`).
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

fn validate_entries(aces: &[PosixAce], label: &str) -> Result<()> {
    let (mut user_obj, mut group_obj, mut other, mut mask, mut named) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    for a in aces {
        match a.tag {
            PosixTag::UserObj => user_obj += 1,
            PosixTag::GroupObj => group_obj += 1,
            PosixTag::Other => other += 1,
            PosixTag::Mask => mask += 1,
            PosixTag::User => {
                if a.id < 0 {
                    return Err(Error::Validation(format!(
                        "{label} ACL: named USER entry has no uid"
                    )));
                }
                named += 1;
            }
            PosixTag::Group => {
                if a.id < 0 {
                    return Err(Error::Validation(format!(
                        "{label} ACL: named GROUP entry has no gid"
                    )));
                }
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
        assert_eq!(acl.access_bytes().len(), 28);
    }

    #[test]
    fn trivial_only_when_synthesized_and_no_default() {
        assert!(!PosixAcl::from_aces([PosixAce {
            tag: PosixTag::UserObj,
            perms: PosixPerm::READ,
            id: -1,
            default: false,
        }])
        .trivial());
        assert!(synthesize_from_mode(0o600).trivial());
    }

    #[test]
    fn generate_inherited_needs_a_default_acl() {
        assert!(synthesize_from_mode(0o755)
            .generate_inherited_acl(true)
            .is_err());
    }
}
