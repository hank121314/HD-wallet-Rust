#[repr(u32)]
pub enum Version {
    Private = 0x0488ADE4,
    Public = 0x0488B21E,
    TestnetPublic = 0x043587CF,
    TestnetPrivate = 0x04358394,
}

impl Version {
    pub fn to_be_bytes(&self) -> [u8; 4] {
        match self {
            Version::Private => (Version::Private as u32).to_be_bytes(),
            Version::Public => (Version::Public as u32).to_be_bytes(),
            Version::TestnetPublic => (Version::TestnetPublic as u32).to_be_bytes(),
            Version::TestnetPrivate => (Version::TestnetPrivate as u32).to_be_bytes(),
        }
    }
}