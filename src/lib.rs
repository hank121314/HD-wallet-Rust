pub mod bip32;
pub mod bip39;
pub mod child_number;
pub mod error;
pub mod keys;
pub mod path;
pub mod secp256k1;
pub mod version;

pub type Result<T, E = error::Error> = std::result::Result<T, E>;
pub type HmacSha512 = hmac::Hmac<sha2::Sha512>;
