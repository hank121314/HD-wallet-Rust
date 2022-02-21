use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};

/*
secp256k1 base point in affine coordinates:
x = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
y = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
*/
const G_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

const G_Y: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub struct Curve {
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
    pub r: BigInt,
}

impl Curve {
    /*
    For curve secp256k1 prime modulus is 2^256−2^32−977
    a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
     */
    pub fn secp256k1() -> Self {
        let p = BigInt::from(2).pow(256) - BigInt::from(2).pow(32) - BigInt::from(977);
        let a = BigInt::from(0);
        let b = BigInt::from(7);
        let r = BigInt::from_bytes_be(Sign::Plus, &CURVE_ORDER);
        Curve { p, a, b, r }
    }
}

/*
Rust secp256k1 implementations

Using double and add to multiply scalar.

Reference: https://paulmillr.com/posts/noble-secp256k1-fast-ecc/
 */
#[derive(Clone)]
pub struct Point {
    pub x: BigInt,
    pub y: BigInt,
}

impl Point {
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Self { x, y }
    }

    pub fn zero() -> Self {
        let x = BigInt::from(0);
        let y = BigInt::from(0);

        Self::new(x, y)
    }

    pub fn secp256k1_base_point() -> Self {
        let x = BigInt::from_bytes_be(Sign::Plus, &G_X);
        let y = BigInt::from_bytes_be(Sign::Plus, &G_Y);

        Self::new(x, y)
    }

    pub fn double_and_add(d: Point, n: BigInt) -> Self {
        let mut p = Point::zero();
        let mut n = n;
        let mut d = d;
        while n > BigInt::zero() {
            if n.clone() & BigInt::one() != BigInt::zero() {
                p = p.add(d.clone());
            }
            d = d.double();
            n >>= 1;
        }

        p
    }

    /*
    P + R = Q
    Point addition algorithm for ECC Curves:
        xR = (m ^ 2 - xP - xQ) mod p
        yR = (yP + m(xR - xP)) mod p
    If P == Q, we have:
        m = (3xP ^ 2 + a)(2yP) ^ -1 mod p
    If P != Q, the slope m assumes the form:
        m = (yP - yQ)(xP - xQ) ^ -1 mod p
     */
    pub fn add<A: AsRef<Self>>(&self, other: A) -> Self {
        let other = other.as_ref();
        let x1 = self.x.clone();
        let y1 = self.y.clone();
        let x2 = other.x.clone();
        let y2 = other.y.clone();
        if x1 == BigInt::zero() || y1 == BigInt::zero() {
            return other.to_owned();
        }
        if x2 == BigInt::zero() || y2 == BigInt::zero() {
            return self.to_owned();
        }
        if x1 == x2 && y1 == y2 {
            return self.double();
        }
        if x1 == x2 && y1 == -1 * &y2 {
            return Point::zero();
        }
        let m = (&y2 - &y1) * Self::invert(&x2 - &x1, None);
        let m = Self::modulo(m, None);
        let x3 = Self::modulo(&m * &m - &x1 - &x2, None);
        // We need to get negation of y3.
        let y3 = Self::modulo(&m * (&x1 - &x3) - &y1, None);

        Self { x: x3, y: y3 }
    }

    pub fn double(&self) -> Self {
        let curve = Curve::secp256k1();
        let x1 = self.x.clone();
        let y1 = self.y.clone();
        let m = (BigInt::from(3) * &x1 * &x1 + curve.a) * Self::invert(BigInt::from(2) * &y1, None);
        let m = Self::modulo(m, None);
        let x3 = Self::modulo(&m * &m - BigInt::from(2) * &x1, None);
        // We need to get negation of y3.
        let y3 = Self::modulo(&m * (&x1 - &x3) - &y1, None);

        Self { x: x3, y: y3 }
    }

    /*
    If you cannot understand modular arithmetic.
    Here is a useful tutorial from khan academy.
    https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/what-is-modular-arithmetic
     */
    pub fn modulo(number: BigInt, modulus: Option<BigInt>) -> BigInt {
        let modulus = modulus.unwrap_or(Curve::secp256k1().p);

        (number % modulus.clone() + modulus.clone()) % modulus
    }

    /*
    Using Extended Euclidean algorithms to find modular multiplicative inverse.
    a * x + b * y = gcd(a, b);
    FYI: https://brilliant.org/wiki/extended-euclidean-algorithm/

    ex. 1914a+899b = gcd(1914,899).
     */
    pub fn extended_euclid(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        match a == BigInt::zero() {
            true => (b, BigInt::zero(), BigInt::one()),
            false => {
                let (g, x, y) = Self::extended_euclid(&b % &a, a.clone());

                (g, y - (&b / &a) * &x, x)
            }
        }
    }

    pub fn invert(number: BigInt, modulus: Option<BigInt>) -> BigInt {
        let m = modulus.unwrap_or(Curve::secp256k1().p);
        let a = Self::modulo(number, Some(m.clone()));
        let b = m.clone();
        let (_, x, _) = Self::extended_euclid(a, b);

        Self::modulo(x, None)
    }
}

impl AsRef<Point> for Point {
    fn as_ref(&self) -> &Point {
        self
    }
}
