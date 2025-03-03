use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Read;

use bitvec::bits;
use bitvec::index::BitIdx;
use bitvec::order::Lsb0;
use bitvec::store::BitStore;
use chacha20::XChaChaCore;
use chacha20poly1305::ChaChaPoly1305;
use cipher::consts::{B0, B1};
use cipher::generic_array::GenericArray;
use cipher::typenum::{UInt, UTerm};
use cipher::StreamCipherCoreWrapper;
use password_hash::Salt;
use password_hash::{Ident, Output, PasswordHash, PasswordHashString};
use rand::CryptoRng;
use rand::SeedableRng;
use rand_core::OsRng;
use rand_core::{Error, RngCore};
use scrypt::{scrypt, Params};

use chacha20poly1305::{
    aead::{AeadCore, KeyInit},
    XChaCha20Poly1305,
};

const RECOMMENDED_LOG_N: u8 = 17;
const RECOMMENDED_R: u32 = 8;
const RECOMMENDED_P: u32 = 1;
const LEN: usize = 64;

pub const ALG_ID: Ident = Ident::new_unwrap("scrypt");

/* === SEEDER === */

const N: usize = 64;
type Idx = usize;

pub struct Seed(pub [u8; N]);
pub struct BstRng(Seed, Idx);

impl Default for Seed {
    fn default() -> Seed {
        Seed([0; N])
    }
}

impl Seed {
    // use first 64 bytes of hash
    fn from_hash(hash: &[u8]) -> Seed {
        let len = match hash.len() {
            0..64 => hash.len(),
            64.. => 64,
        };

        let mut seed = Seed([0; N]);
        for i in 0..len {
            seed.0[i] = hash[i]
        }
        seed
    }
}

impl AsMut<[u8]> for Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        let u8_slice = self.0.as_mut_slice();
        u8_slice
    }
}

impl SeedableRng for BstRng {
    type Seed = Seed;

    fn from_seed(seed: Seed) -> BstRng {
        BstRng(seed, 0)
    }
}

impl BstRng {
    fn next_u64_impl(&mut self) -> u64 {
        if self.1 > N {
            panic!("empty seed")
        }

        let n = [
            self.0 .0[self.1],
            self.0 .0[self.1 + 1],
            self.0 .0[self.1 + 2],
            self.0 .0[self.1 + 3],
            self.0 .0[self.1 + 4],
            self.0 .0[self.1 + 5],
            self.0 .0[self.1 + 6],
            self.0 .0[self.1 + 7],
        ];
        self.1 = self.1 + 8;
        u64::from_be_bytes(n)
    }

    fn fill_bytes_impl(&mut self, dest: &mut [u8]) {
        if self.1 + dest.len() > dest.len() {
            panic!("empty seed")
        }

        // println!("FILL BYTES: {}", dest.len());
        for i in 0..dest.len() {
            dest[i] = self.0 .0[i + self.1]
        }
        self.1 = self.1 + dest.len();
    }
}

impl CryptoRng for BstRng {}

impl RngCore for BstRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.next_u64_impl()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes_impl(dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub fn get_rng(pwd_hash: &str) -> BstRng {
    let bst_seed = Seed::from_hash(pwd_hash.as_bytes());
    let bst_rng = <BstRng as rand::SeedableRng>::from_seed(bst_seed);

    return bst_rng;
}

/* === HASHING === */

pub fn hash_pwd<'a>(pwd_str: &str, salt: &str) -> Result<PasswordHashString, password_hash::Error> {
    let salt = Salt::from_b64(salt).unwrap();
    let salt_u8 = salt.as_str().as_bytes();

    let params = Params::new(RECOMMENDED_LOG_N, RECOMMENDED_R, RECOMMENDED_P, LEN).unwrap();

    let output = Output::init_with(LEN, |out| {
        scrypt(&pwd_str.as_bytes(), &salt_u8, &params, out).map_err(|_| {
            let provided = if out.is_empty() {
                Ordering::Less
            } else {
                Ordering::Greater
            };

            password_hash::Error::OutputSize {
                provided,
                expected: 0,
            }
        })
    });

    let pwd = Ok(PasswordHash {
        algorithm: ALG_ID,
        version: None,
        params: params.try_into().unwrap(),
        salt: Some(salt),
        hash: Some(output.unwrap()),
    }
    .serialize());

    pwd
}

// generates crytpographic salt string
pub fn generate_salt() -> String {
    password_hash::SaltString::generate(OsRng).to_string()
}

pub fn generate_cipher(
    pwd: &PasswordHashString,
) -> ChaChaPoly1305<
    StreamCipherCoreWrapper<XChaChaCore<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>>>,
    UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>,
> {
    let bst_rng = get_rng(&pwd.hash().unwrap().to_string());
    let key = XChaCha20Poly1305::generate_key(bst_rng);
    let cipher = XChaCha20Poly1305::new(&key);

    cipher
}

pub fn generate_nonce() -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>>
{
    XChaCha20Poly1305::generate_nonce(&mut OsRng)
}

// Takes up to 64 chars
// Returns 64bit integer
fn xdhashbash(pwd: &str) -> u64 {
    // take up to 64 chars
    // Assign a number between 1-64
    // a = 1
    // b = 2
    // c = 3
    // d = 4
    // ...

    // 64bit target = [0; 0..64]
    // len of target / len of pwd == bit_count
    // Pull the first bit_count from beginning of char

    // If char is a = 1
    // Char bits = 1000000000
    //        bc = |___|
    // target[0..5] = bc

    // Example hash collision
    // bc = ababababababababababababababababababa...len(64)
    // bc = abcdefghijklmnopqurstuzwxyzABCDEFGHIJ...len(64)
    // target = [10101010101010101010101010101010...len(64)]

    let a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    let mut h: HashMap<usize, usize> = HashMap::new();
    for (i, c) in itertools::enumerate(a.chars()) {
        let c1: u32 = c.into();
        h.insert(c1.try_into().unwrap(), i);
    }

    let bits = bits![mut 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0];

    for (i, c) in itertools::enumerate(pwd.chars()) {
        let c1: u32 = c.into();
        let c2: usize = c1.try_into().unwrap();
        let c3: usize = h[&c2];
        let idx: BitIdx = BitIdx::new(0).unwrap();
        bits.replace(i, c3.get_bit::<bitvec::order::Lsb0>(idx));
    }

    let m = bits.bytes();
    let mut bv_8 = [0u8; 8];

    for (i, b_res) in itertools::enumerate(m) {
        let b = b_res.unwrap();
        bv_8[i] = b
    }

    return u64::from_be_bytes(bv_8);
}

#[cfg(test)]
mod tests {
    use super::*;
}
