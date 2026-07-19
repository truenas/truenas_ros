//! NFS4 ACLs (`system.nfs4_acl_xdr`) — big-endian XDR wire format.

use crate::error::{Error, Result};

/// The xattr name holding an NFS4 ACL.
pub(crate) const NFS4_ACL_XATTR: &str = "system.nfs4_acl_xdr";

const HDR_SZ: usize = 8;
const ACE_SZ: usize = 20;

tn_enum! {
    /// The type of an NFS4 ACE.
    pub enum Nfs4AceType: u32 {
        /// Grant the access in `access_mask`.
        Allow = 0,
        /// Deny the access in `access_mask`.
        Deny = 1,
        /// Audit attempts to use the access.
        Audit = 2,
        /// Alarm on attempts to use the access.
        Alarm = 3,
    }
}

tn_enum! {
    /// The principal an NFS4 ACE applies to.
    ///
    /// `Named` corresponds to a numeric uid/gid (`iflag == 0` on the wire); the
    /// others are the special principals (`iflag == 1`).
    pub enum Nfs4Who: u32 {
        /// A named uid/gid (see [`Nfs4Ace::who_id`]).
        Named = 0,
        /// The file owner (`OWNER@`).
        Owner = 1,
        /// The owning group (`GROUP@`).
        Group = 2,
        /// Everyone (`EVERYONE@`).
        Everyone = 3,
    }
}

tn_bitflags! {
    /// NFS4 access-mask permission bits.
    pub struct Nfs4Perm: u32 {
        /// Read file data / list a directory.
        READ_DATA = 0x0000_0001;
        /// Write file data / create a file in a directory.
        WRITE_DATA = 0x0000_0002;
        /// Append to a file / create a subdirectory.
        APPEND_DATA = 0x0000_0004;
        /// Read named attributes.
        READ_NAMED_ATTRS = 0x0000_0008;
        /// Write named attributes.
        WRITE_NAMED_ATTRS = 0x0000_0010;
        /// Execute a file / traverse a directory.
        EXECUTE = 0x0000_0020;
        /// Delete a child within a directory.
        DELETE_CHILD = 0x0000_0040;
        /// Read basic attributes.
        READ_ATTRIBUTES = 0x0000_0080;
        /// Write basic attributes (e.g. timestamps).
        WRITE_ATTRIBUTES = 0x0000_0100;
        /// Delete the object.
        DELETE = 0x0001_0000;
        /// Read the ACL.
        READ_ACL = 0x0002_0000;
        /// Write the ACL.
        WRITE_ACL = 0x0004_0000;
        /// Change the owner or owning group.
        WRITE_OWNER = 0x0008_0000;
        /// Synchronise access.
        SYNCHRONIZE = 0x0010_0000;
    }
}

tn_bitflags! {
    /// NFS4 ACE flags (inheritance and audit/alarm control).
    pub struct Nfs4Flag: u32 {
        /// Inherited by new files created in this directory.
        FILE_INHERIT = 0x0000_0001;
        /// Inherited by new subdirectories created in this directory.
        DIRECTORY_INHERIT = 0x0000_0002;
        /// Do not propagate inheritance beyond one level.
        NO_PROPAGATE_INHERIT = 0x0000_0004;
        /// Applies to children only, not to this object.
        INHERIT_ONLY = 0x0000_0008;
        /// Audit/alarm on successful access.
        SUCCESSFUL_ACCESS = 0x0000_0010;
        /// Audit/alarm on failed access.
        FAILED_ACCESS = 0x0000_0020;
        /// The principal is a group.
        IDENTIFIER_GROUP = 0x0000_0040;
        /// This ACE was inherited from a parent.
        INHERITED = 0x0000_0080;
    }
}

impl Nfs4Flag {
    /// All four inheritance bits (`FILE|DIRECTORY|NO_PROPAGATE|INHERIT_ONLY`).
    const INHERIT_MASK: Nfs4Flag = Nfs4Flag::FILE_INHERIT
        .union(Nfs4Flag::DIRECTORY_INHERIT)
        .union(Nfs4Flag::NO_PROPAGATE_INHERIT)
        .union(Nfs4Flag::INHERIT_ONLY);
    /// The two "inheritable to a child" bits.
    const INHERITABLE: Nfs4Flag =
        Nfs4Flag::FILE_INHERIT.union(Nfs4Flag::DIRECTORY_INHERIT);
}

tn_bitflags! {
    /// ACL-level flags (the 4-byte XDR header). `ACL_IS_TRIVIAL`/`ACL_IS_DIR`
    /// are ZFS on-disk extensions.
    pub struct Nfs4AclFlag: u32 {
        /// Automatic inheritance is enabled.
        AUTO_INHERIT = 0x0000_0001;
        /// The ACL is protected from inheritance.
        PROTECTED = 0x0000_0002;
        /// The ACL was set by default rather than explicitly.
        DEFAULTED = 0x0000_0004;
        /// (ZFS) The ACL is equivalent to the file's mode bits.
        ACL_IS_TRIVIAL = 0x0001_0000;
        /// (ZFS) The ACL belongs to a directory.
        ACL_IS_DIR = 0x0002_0000;
    }
}

/// A single NFS4 access-control entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nfs4Ace {
    /// Whether this entry allows, denies, audits, or alarms.
    pub ace_type: Nfs4AceType,
    /// Inheritance / audit flags.
    pub ace_flags: Nfs4Flag,
    /// The permissions this entry governs.
    pub access_mask: Nfs4Perm,
    /// The kind of principal (`Named` or a special principal).
    pub who_type: Nfs4Who,
    /// The uid/gid for a `Named` principal; `-1` for special principals.
    pub who_id: i64,
}

impl Nfs4Ace {
    /// Construct an ACE. `who_id` is ignored (stored as `-1`) unless
    /// `who_type` is [`Nfs4Who::Named`].
    pub fn new(
        ace_type: Nfs4AceType,
        ace_flags: Nfs4Flag,
        access_mask: Nfs4Perm,
        who_type: Nfs4Who,
        who_id: i64,
    ) -> Self {
        let who_id = if who_type == Nfs4Who::Named {
            who_id
        } else {
            -1
        };
        Nfs4Ace {
            ace_type,
            ace_flags,
            access_mask,
            who_type,
            who_id,
        }
    }
}

/// An NFS4 ACL: a header flag word plus an ordered list of ACEs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nfs4Acl {
    /// ACL-level flags from the XDR header.
    pub acl_flags: Nfs4AclFlag,
    /// The access-control entries, in stored (wire) order.
    pub aces: Vec<Nfs4Ace>,
}

#[inline]
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

impl Nfs4Acl {
    /// Decode from the raw big-endian XDR bytes of `system.nfs4_acl_xdr`.
    ///
    /// A buffer shorter than the 8-byte header is treated as an empty,
    /// trivial ACL (the "present but empty" sentinel from `fgetacl`).
    pub fn from_xattr(data: &[u8]) -> Result<Self> {
        if data.len() < HDR_SZ {
            return Ok(Nfs4Acl {
                acl_flags: Nfs4AclFlag::ACL_IS_TRIVIAL,
                aces: Vec::new(),
            });
        }
        let acl_flags = Nfs4AclFlag::from_bits_retain(be32(data, 0));
        let naces = be32(data, 4) as usize;
        // `naces` is attacker-controlled (from the xattr blob); compute the
        // required length with checked arithmetic so a huge count cannot wrap
        // `usize` and slip past the truncation guard (a 32-bit-target hazard).
        let need = naces
            .checked_mul(ACE_SZ)
            .and_then(|n| n.checked_add(HDR_SZ));
        if need.map_or(true, |need| data.len() < need) {
            return Err(Error::Parse(format!(
                "NFS4 ACL truncated: {} bytes for {naces} ACEs",
                data.len()
            )));
        }
        let mut aces = Vec::with_capacity(naces);
        for i in 0..naces {
            let p = HDR_SZ + i * ACE_SZ;
            let ace_type = Nfs4AceType::try_from(be32(data, p))
                .map_err(|_| Error::Parse("invalid NFS4 ACE type".into()))?;
            let ace_flags = Nfs4Flag::from_bits_retain(be32(data, p + 4));
            let iflag = be32(data, p + 8);
            let access_mask = Nfs4Perm::from_bits_retain(be32(data, p + 12));
            let who_raw = be32(data, p + 16);
            let (who_type, who_id) = if iflag != 0 {
                let w = Nfs4Who::try_from(who_raw).map_err(|_| {
                    Error::Parse("invalid NFS4 special principal".into())
                })?;
                (w, -1)
            } else {
                (Nfs4Who::Named, who_raw as i64)
            };
            aces.push(Nfs4Ace {
                ace_type,
                ace_flags,
                access_mask,
                who_type,
                who_id,
            });
        }
        Ok(Nfs4Acl { acl_flags, aces })
    }

    /// Build an ACL from ACEs, re-sorting them into Windows-canonical order
    /// (explicit-deny, explicit-allow, inherited-deny, inherited-allow) with a
    /// stable sort, matching the C `from_aces`.
    pub fn from_aces<I>(aces: I, acl_flags: Nfs4AclFlag) -> Self
    where
        I: IntoIterator<Item = Nfs4Ace>,
    {
        let mut aces: Vec<Nfs4Ace> = aces.into_iter().collect();
        aces.sort_by_key(bucket_key);
        Nfs4Acl { acl_flags, aces }
    }

    /// Encode to the raw big-endian XDR bytes (ACEs in stored order, no sort).
    pub fn to_xattr(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HDR_SZ + self.aces.len() * ACE_SZ);
        out.extend_from_slice(&self.acl_flags.bits().to_be_bytes());
        out.extend_from_slice(&(self.aces.len() as u32).to_be_bytes());
        for a in &self.aces {
            let (iflag, who) = if a.who_type == Nfs4Who::Named {
                (0u32, a.who_id as u32)
            } else {
                (1u32, a.who_type as u32)
            };
            out.extend_from_slice(&(a.ace_type as u32).to_be_bytes());
            out.extend_from_slice(&a.ace_flags.bits().to_be_bytes());
            out.extend_from_slice(&iflag.to_be_bytes());
            out.extend_from_slice(&a.access_mask.bits().to_be_bytes());
            out.extend_from_slice(&who.to_be_bytes());
        }
        out
    }

    /// True if the on-disk `ACL_IS_TRIVIAL` bit is set (the ACL is equivalent
    /// to the mode bits).
    pub fn trivial(&self) -> bool {
        self.acl_flags.contains(Nfs4AclFlag::ACL_IS_TRIVIAL)
    }

    /// Produce the ACL a new child object would inherit from this one.
    ///
    /// Errors if no ACE is inheritable for the given child type.
    pub fn generate_inherited_acl(&self, is_dir: bool) -> Result<Self> {
        let aces: Vec<Nfs4Ace> = self
            .aces
            .iter()
            .filter(|a| ace_is_inheritable(a.ace_flags, is_dir))
            .map(|a| Nfs4Ace {
                ace_flags: inherited_flags(a.ace_flags, is_dir),
                ..a.clone()
            })
            .collect();
        if aces.is_empty() {
            return Err(Error::Validation(
                "parent ACL has no inheritable ACEs for this object type"
                    .into(),
            ));
        }
        let acl_flags = if is_dir {
            Nfs4AclFlag::ACL_IS_DIR
        } else {
            Nfs4AclFlag::empty()
        };
        Ok(Nfs4Acl { acl_flags, aces })
    }

    /// Structural validation (matching the C `nfs4acl_valid`).
    pub(crate) fn validate(&self, is_dir: bool) -> Result<()> {
        let mut has_propagate = false;
        let mut has_inheritable = false;
        for a in &self.aces {
            let special = a.who_type != Nfs4Who::Named;
            if a.ace_type == Nfs4AceType::Deny && special {
                return Err(Error::Validation(
                    "DENY entries are not permitted for special principals \
                     (OWNER@, GROUP@, EVERYONE@)"
                        .into(),
                ));
            }
            if is_dir
                && a.ace_flags.contains(Nfs4Flag::INHERIT_ONLY)
                && !a.ace_flags.intersects(Nfs4Flag::INHERITABLE)
            {
                return Err(Error::Validation(
                    "INHERIT_ONLY requires FILE_INHERIT or DIRECTORY_INHERIT \
                     to also be set"
                        .into(),
                ));
            }
            if is_dir
                && a.ace_flags.contains(Nfs4Flag::NO_PROPAGATE_INHERIT)
                && !a.ace_flags.intersects(Nfs4Flag::INHERITABLE)
            {
                return Err(Error::Validation(
                    "NO_PROPAGATE_INHERIT requires FILE_INHERIT or \
                     DIRECTORY_INHERIT to also be set"
                        .into(),
                ));
            }
            if a.ace_flags.intersects(Nfs4Flag::INHERIT_MASK) {
                has_propagate = true;
            }
            if a.ace_flags.intersects(Nfs4Flag::INHERITABLE) {
                has_inheritable = true;
            }
        }
        if has_propagate && !is_dir {
            return Err(Error::Validation(
                "FILE_INHERIT/DIRECTORY_INHERIT/NO_PROPAGATE_INHERIT/\
                 INHERIT_ONLY flags are only valid on directories"
                    .into(),
            ));
        }
        if is_dir && !has_inheritable {
            return Err(Error::Validation(
                "directory ACL must contain at least one ACE with \
                 FILE_INHERIT or DIRECTORY_INHERIT"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Windows-canonical sort key: `2*inherited + is_allow`.
fn bucket_key(a: &Nfs4Ace) -> u8 {
    let inherited = a.ace_flags.contains(Nfs4Flag::INHERITED) as u8;
    let is_allow = (a.ace_type == Nfs4AceType::Allow) as u8;
    inherited * 2 + is_allow
}

fn ace_is_inheritable(flags: Nfs4Flag, is_dir: bool) -> bool {
    if is_dir {
        flags.intersects(Nfs4Flag::INHERITABLE)
    } else {
        flags.contains(Nfs4Flag::FILE_INHERIT)
    }
}

/// Rewrite an ACE's flags for a newly-created child (port of the C logic).
fn inherited_flags(f: Nfs4Flag, is_dir: bool) -> Nfs4Flag {
    use Nfs4Flag as F;
    if is_dir && !f.contains(F::NO_PROPAGATE_INHERIT) {
        if f.contains(F::DIRECTORY_INHERIT) {
            (f - F::INHERIT_ONLY) | F::INHERITED
        } else {
            (f | F::INHERIT_ONLY) | F::INHERITED
        }
    } else if is_dir {
        if f.contains(F::INHERIT_ONLY) && f.contains(F::FILE_INHERIT) {
            (f - F::INHERIT_ONLY) | F::INHERITED
        } else {
            (f - F::INHERIT_MASK) | F::INHERITED
        }
    } else {
        (f - F::INHERIT_MASK) | F::INHERITED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_is_trivial() {
        let acl = Nfs4Acl::from_xattr(&[]).unwrap();
        assert!(acl.trivial());
        assert!(acl.aces.is_empty());
    }

    #[test]
    fn file_child_strips_inherit_bits() {
        let ace = Nfs4Ace::new(
            Nfs4AceType::Allow,
            Nfs4Flag::FILE_INHERIT | Nfs4Flag::INHERIT_ONLY,
            Nfs4Perm::READ_DATA,
            Nfs4Who::Owner,
            -1,
        );
        let acl = Nfs4Acl {
            acl_flags: Nfs4AclFlag::ACL_IS_DIR,
            aces: vec![ace],
        };
        let child = acl.generate_inherited_acl(false).unwrap();
        let f = child.aces[0].ace_flags;
        assert!(!f.intersects(Nfs4Flag::INHERIT_MASK));
        assert!(f.contains(Nfs4Flag::INHERITED));
        assert_eq!(child.acl_flags, Nfs4AclFlag::empty());
    }

    #[test]
    fn validate_rejects_deny_for_special_principal() {
        let ace = Nfs4Ace::new(
            Nfs4AceType::Deny,
            Nfs4Flag::empty(),
            Nfs4Perm::WRITE_DATA,
            Nfs4Who::Owner,
            -1,
        );
        let acl = Nfs4Acl {
            acl_flags: Nfs4AclFlag::empty(),
            aces: vec![ace],
        };
        assert!(acl.validate(false).is_err());
    }
}
