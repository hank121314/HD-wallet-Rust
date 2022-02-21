use crate::child_number::ChildNumber;
use crate::keys::KeyFingerprint;
use crate::{
    keys::ExtendedKey,
    path::Path,
    secp256k1::{Curve, Point},
    HmacSha512, Result,
};
use hmac::{Mac, NewMac};
use num_bigint::{BigInt, Sign};
use ripemd160::{Digest, Ripemd160};
use sha2::Sha256;
use std::str::FromStr;

const MASTER_PATH: &str = "0'";
const KEY_SIZE: usize = 32;
const BIP39_DOMAIN_SEPARATOR: &str = "Bitcoin seed";
const HARDENED_FLAG: u32 = 1 << 31;

/*
Rust implementation for Bip32

p = (x^3 + 7)
point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
pub struct Bip32;

impl Bip32 {
    /*
    Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    Split I into two 32-byte sequences, IL and IR.
    Use parse256(IL) as master secret key, and IR as master chain code.
     */
    pub fn from_seed<S: Into<String>>(seed: S) -> Result<ExtendedKey> {
        let seed = hex::decode(seed.into()).unwrap();
        let mut hmac = HmacSha512::new_from_slice(BIP39_DOMAIN_SEPARATOR.as_bytes()).unwrap();
        hmac.update(seed.as_ref());
        let result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(KEY_SIZE);
        let master_path = Path::from_str(MASTER_PATH)?;

        Ok(ExtendedKey {
            private_key: secret_key.try_into().unwrap(),
            chain_code: chain_code.try_into().unwrap(),
            path: master_path,
            finger_print: KeyFingerprint::default(),
        })
    }

    pub fn derive(key: ExtendedKey, child_number: ChildNumber) -> ExtendedKey {
        let m_chain_code = key.chain_code.clone();
        let m_private_key = key.private_key.clone();
        let m_public_key = hex::decode(key.public_key(true)).unwrap();
        let (is_hardened, mut index) = (child_number.is_hardened, child_number.index);
        let mut hmac = HmacSha512::new_from_slice(m_chain_code.as_ref()).unwrap();
        match is_hardened {
            true => {
                hmac.update(&[0]);
                hmac.update(&m_private_key);
                index = index | HARDENED_FLAG;
            }
            false => {
                hmac.update(&m_public_key);
            }
        }

        hmac.update(&index.to_be_bytes());
        let result = hmac.finalize().into_bytes();

        let (secret_key, chain_code) = result.split_at(KEY_SIZE);

        let curve = Curve::secp256k1();

        // ki = parse256(IL) + kpar (mod n)
        let parse256 = BigInt::from_bytes_be(Sign::Plus, secret_key);
        let k_par = BigInt::from_bytes_be(Sign::Plus, &key.private_key);
        let ki = Point::modulo(parse256 + k_par, Some(curve.r)).to_bytes_be();

        let mut path = key.path.clone();
        path.depth += 1;
        path.child_numbers.push(child_number.clone());

        // Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the serialized ECDSA public key K.
        // The first 32 bits of the identifier are called the key fingerprint.
        let finger_print = Ripemd160::digest(&Sha256::digest(&m_public_key)).to_vec();

        ExtendedKey {
            private_key: ki.1.as_slice()[..32].try_into().unwrap(),
            chain_code: chain_code.try_into().unwrap(),
            path,
            finger_print: finger_print.as_slice()[..4].try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{bip32::Bip32, child_number::ChildNumber};
    use bip32::{ChildNumber as TargetChildNumber, Prefix, Seed, XPrv};
    use std::str::FromStr;
    use crate::version::Version;

    #[test]
    fn generate_master_private_key() {
        let seed = "37b92480d76e320f3a3227ab897c3680f7ec84dfc949220e1dec50d2abf64e918623e6ae7d1792a1de2fa0825ef804ed676056dc530a7bc96d8f86941fad27b5";
        let master = Bip32::from_seed(seed).unwrap();

        assert_eq!(
            "8ad8c49dd58ef9ebc4c48dfb0058140cd17095b13db93e28c1a655984a31b73a",
            hex::encode(master.chain_code)
        );
        assert_eq!(
            "edc386d2b86c3f176df81126cf0d399196c8c2b17b362fb8be9d634d8e6110e3",
            hex::encode(master.private_key)
        );
    }

    #[test]
    fn derive_0_hardened_key() {
        let seed = "5d6c43a28c7177a25c2b6812dec03d9ca5b1f5988b276f9504fd69f8e32f0797cacda47c9746f8c97a273a525de465e67b65b17d75bacdbc0d01e788b9646288";
        let master = Bip32::from_seed(seed).unwrap();
        let child_number = ChildNumber::from_str("0'").unwrap();
        let seed = hex::decode(seed).unwrap();
        let seed = Seed::new(<[u8; 64]>::try_from(seed).unwrap());
        let key = XPrv::new(seed).unwrap();
        let target_child_number = TargetChildNumber::from_str("0'").unwrap();
        let target = key.derive_child(target_child_number).unwrap();

        let next = Bip32::derive(master, child_number);

        assert_eq!(target.attrs().chain_code, next.chain_code);
    }

    #[test]
    fn derive_0_non_hardened_key() {
        let seed = "5d6c43a28c7177a25c2b6812dec03d9ca5b1f5988b276f9504fd69f8e32f0797cacda47c9746f8c97a273a525de465e67b65b17d75bacdbc0d01e788b9646288";
        let master = Bip32::from_seed(seed).unwrap();
        let child_number = ChildNumber::from_str("0").unwrap();
        let next = Bip32::derive(master, child_number);

        let seed = hex::decode(seed).unwrap();
        let seed = Seed::new(<[u8; 64]>::try_from(seed).unwrap());
        let key = XPrv::new(seed).unwrap();
        let target_child_number = TargetChildNumber::from_str("0").unwrap();
        let target = key.derive_child(target_child_number).unwrap();

        assert_eq!(target.attrs().chain_code, next.chain_code);
        assert_eq!(target.to_extended_key(Prefix::XPRV).to_string(), next.to_base58(Version::Private));

        let child_number = ChildNumber::from_str("1").unwrap();
        let next = Bip32::derive(next, child_number);

        let target_child_number = TargetChildNumber::from_str("1").unwrap();
        let target = target.derive_child(target_child_number).unwrap();

        assert_eq!(target.attrs().chain_code, next.chain_code);
        assert_eq!(target.to_extended_key(Prefix::XPRV).to_string(), next.to_base58(Version::Private))
    }
}
