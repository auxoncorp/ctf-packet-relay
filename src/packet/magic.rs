pub struct CtfPacketMagic;

impl CtfPacketMagic {
    pub const MAGIC: &'static [u8] = &[0xC1, 0x1F, 0xFC, 0xC1];

    pub(crate) fn check_magic(input: &[u8]) -> bool {
        (input.len() >= Self::MAGIC.len()) && (&input[..4] == Self::MAGIC)
    }
}
