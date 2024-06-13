pub(in crate::serde) use super::alloc::vec::Vec;

mod de;
mod error;
mod ser;

pub use de::{from_str, Deserializer};
pub use error::{Error, Result};
pub use ser::{to_bytes, Serializer};
