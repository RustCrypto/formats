//! Name types as defined in [RFC 5280 Section 4.2.1.6].
//!
//! [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6

mod dirstr;
mod ediparty;
mod general;
mod other;

pub use dirstr::DirectoryString;
pub use ediparty::EdiPartyName;
pub use general::{GeneralName, GeneralNames};
pub use other::OtherName;
