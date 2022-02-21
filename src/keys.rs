use crate::{path::Path, secp256k1::Point, version::Version};
use num_bigint::{BigInt, Sign};
use num_traits::Zero;

pub type KeyFingerprint = [u8; 4];
pub type PrivateKey = [u8; 32];
pub type ChainCode = [u8; 32];

pub struct ExtendedKey {
    pub(crate) private_key: PrivateKey,
    pub(crate) chain_code: ChainCode,
    pub(crate) path: Path,
    pub(crate) finger_print: KeyFingerprint,
}

impl ExtendedKey {
    pub fn public_key(&self, is_compressed: bool) -> String {
        let key = BigInt::from_bytes_be(Sign::Plus, &self.private_key);
        // point(kpar)
        let point = Point::double_and_add(Point::secp256k1_base_point(), key);

        match is_compressed {
            true => {
                // serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
                let prefix = match &point.y & BigInt::from(1) != BigInt::zero() {
                    true => "03",
                    false => "02",
                };

                format!("{}{}", prefix, point.x.to_str_radix(16))
            }
            false => format!("04{}{}", point.x.to_str_radix(16), point.y.to_str_radix(16)),
        }
    }

    pub fn to_base58(&self, version: Version) -> String {
        let mut data: Vec<u8> = Vec::new();
        // version
        let version_data: [u8; 4] = version.to_be_bytes();
        data.append(&mut version_data.to_vec());

        // derive
        data.push(self.path.depth as u8);

        // fingerprint
        let finger_print = self.finger_print;
        data.append(&mut finger_print.to_vec());

        // child number
        let child_number = self.path.child_numbers.last().unwrap();
        let child_number: [u8; 4] = child_number.index.to_be_bytes();
        data.append(&mut child_number.to_vec());

        let chain_code = self.chain_code;
        data.append(&mut chain_code.to_vec());

        match version {
            Version::Private | Version::TestnetPrivate => {
                data.push(0x00);
                let private_key = self.private_key;
                data.append(&mut private_key.to_vec());
            }
            Version::Public | Version::TestnetPublic => {
                let public_key = self.public_key(true);
                let public_key = &public_key.as_bytes()[..33];
                data.append(&mut public_key.to_vec());
            }
        };

        bs58::encode(data).with_check().into_string()
    }
}
