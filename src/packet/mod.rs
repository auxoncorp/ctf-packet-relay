use crate::relayd::wire::Index;
use bytes::Bytes;
use std::fmt;

pub use codec::{CtfPacketCodec, DecoderError};
pub use magic::CtfPacketMagic;

pub(crate) mod codec;
pub(crate) mod magic;

pub struct CtfPacket {
    pub index: Index,
    pub packet: Bytes,
}

impl fmt::Display for CtfPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.index.fmt(f)
    }
}
