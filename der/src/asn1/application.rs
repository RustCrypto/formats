//! Application field.

use crate::tag::CLASS_APPLICATION;

use super::custom_class::{
    CustomClassExplicit, CustomClassExplicitRef, CustomClassImplicit, CustomClassImplicitRef,
};

/// Application class, EXPLICIT
pub type ApplicationExplicit<const TAG: u16, T> = CustomClassExplicit<TAG, T, CLASS_APPLICATION>;

/// Application class, IMPLICIT
pub type ApplicationImplicit<const TAG: u16, T> = CustomClassImplicit<TAG, T, CLASS_APPLICATION>;

/// Application class, reference, EXPLICIT
pub type ApplicationExplicitRef<'a, const TAG: u16, T> =
    CustomClassExplicitRef<'a, TAG, T, CLASS_APPLICATION>;

/// Application class, reference, IMPLICIT
pub type ApplicationImplicitRef<'a, const TAG: u16, T> =
    CustomClassImplicitRef<'a, TAG, T, CLASS_APPLICATION>;
