//! Internal macros for defining flag and enum types from `libc` constants or
//! explicit kernel-header values.
//!
//! Beyond a plain `bitflags!` / enum definition, they add a `= <literal>`
//! form, because many constants we need (`STATMOUNT_*`, `LISTMOUNT_*`,
//! `FSCONFIG_*`, `OPEN_TREE_*`, `MOVE_MOUNT_*`, newer `STATX_*`, …) are not
//! exposed by the `libc` crate and must be hardcoded from the kernel uapi
//! headers.

/// Define a `bitflags`-based flag type.
///
/// Each flag is written as one of:
/// * `FLAG;` — value taken from `libc::FLAG`.
/// * `FLAG = 0x1;` — explicit kernel-header value (annotate with a
///   `// <header>:<line>` comment at the use site).
/// * `FLAG as u64;` — `libc::FLAG` cast to the container type (for libc type
///   mismatches).
#[allow(unused_macros)]
macro_rules! tn_bitflags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $Flag:ident $(= $value:literal)? $(as $cast:ty)? ;
            )+
        }
    ) => {
        ::bitflags::bitflags! {
            #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            #[repr(transparent)]
            $(#[$outer])*
            $vis struct $BitFlags: $T {
                $(
                    $(#[$inner $($args)*])*
                    const $Flag =
                        tn_bitflags!(@value $Flag $(= $value)? $(as $cast)?);
                )+
            }
        }
    };
    (@value $Flag:ident = $value:literal) => { $value };
    (@value $Flag:ident as $cast:ty) => { libc::$Flag as $cast };
    (@value $Flag:ident) => { libc::$Flag };
}

/// Define a closed `#[repr($repr)]` enum with explicit values and a
/// `TryFrom<$repr>` conversion that returns [`Errno::EINVAL`] for unknown
/// values.
///
/// [`Errno::EINVAL`]: crate::errno::Errno::EINVAL
#[allow(unused_macros)]
macro_rules! tn_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $Enum:ident: $repr:ty {
            $(
                $(#[$inner:meta])*
                $Variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr($repr)]
        $vis enum $Enum {
            $( $(#[$inner])* $Variant = $value ),+
        }

        impl ::core::convert::TryFrom<$repr> for $Enum {
            type Error = $crate::errno::Errno;
            fn try_from(
                value: $repr,
            ) -> ::core::result::Result<Self, Self::Error> {
                $(
                    if value == $Enum::$Variant as $repr {
                        return ::core::result::Result::Ok($Enum::$Variant);
                    }
                )+
                ::core::result::Result::Err($crate::errno::Errno::EINVAL)
            }
        }
    };
}
