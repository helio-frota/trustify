use bytesize::ByteSize;
use serde::{Serialize, Serializer};
use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    ops::{Deref, DerefMut},
    str::FromStr,
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, Schema},
};

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    PartialOrd,
    Eq,
    Ord,
    Hash,
    Default,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct BinaryByteSize(#[schemars(with = "ByteSizeDef")] pub ByteSize);

impl ToSchema for BinaryByteSize {
    fn name() -> Cow<'static, str> {
        "BinaryByteSize".into()
    }
}

impl PartialSchema for BinaryByteSize {
    fn schema() -> RefOr<Schema> {
        String::schema()
    }
}

impl Serialize for BinaryByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// This is a copy of [`bytesize::ByteSize`] to generate a schema for it.
#[derive(schemars::JsonSchema, utoipa::ToSchema)]
#[schemars(remote = "ByteSize")]
pub struct ByteSizeDef(#[allow(unused)] pub String);

impl From<ByteSize> for BinaryByteSize {
    fn from(value: ByteSize) -> Self {
        Self(value)
    }
}

impl From<u64> for BinaryByteSize {
    fn from(value: u64) -> Self {
        Self(ByteSize(value))
    }
}

impl From<usize> for BinaryByteSize {
    fn from(value: usize) -> Self {
        Self(ByteSize(value as u64))
    }
}

impl From<BinaryByteSize> for usize {
    fn from(value: BinaryByteSize) -> Self {
        value.0.0 as usize
    }
}

impl Deref for BinaryByteSize {
    type Target = ByteSize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BinaryByteSize {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for BinaryByteSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FromStr for BinaryByteSize {
    type Err = <ByteSize as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ByteSize::from_str(s).map(BinaryByteSize)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_string() {
        assert_eq!("4.0 GiB", &BinaryByteSize(ByteSize::gib(4)).to_string());
    }
}
