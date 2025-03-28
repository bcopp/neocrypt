use dirs::home_dir;
use flate2::{
    bufread::{GzDecoder, GzEncoder},
    Compression,
};
use itertools::join;
use jwalk::WalkDir;
use log::debug;
use password_hash::PasswordHashString;
use rand::{thread_rng, Rng};
use std::{
    fs::{create_dir_all, remove_dir_all, OpenOptions},
    io::{self, BufReader, Cursor, Read},
    ops::Range,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
    sync::Mutex,
};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::XNonce;

use chrono::DateTime;
use chrono::Utc;

use crate::context::Ctx;

pub const KB: usize = 1000;
pub const MB: usize = 1000 * KB;
pub const GB: usize = 1000 * MB;

pub const DEFAULT_SIZE: usize = 8 * KB;

pub const VERSION_NULL: u16 = 0;
pub const VERSION_1: u16 = 1;

pub type EncryptionAlg = u16;
pub type CompressionAlg = u16;

pub const ENCRYPTION_ALG_NULL: EncryptionAlg = 0;
pub const ENCRYPTION_ALG_TESTING_ONLY_NONE: EncryptionAlg = 1;
pub const ENCRYPTION_ALG_CHACHPOLY20: EncryptionAlg = 2;

pub const COMPRESSION_ALG_NULL: CompressionAlg = 0;
pub const COMPRESSION_ALG_NONE: CompressionAlg = 1;
pub const COMPRESSION_ALG_GZIP: CompressionAlg = 2;

type IsEmpty = bool;

#[derive(Clone)]
pub struct StorageDirs {
    pub project: PathBuf,
    pub mount_from: PathBuf,
    pub mount_to: PathBuf,
    pub tmp: PathBuf,
}

// field order is ser & deser order
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct HeaderV1 {
    pub version: u16,         // [u16; 1];
    pub compression_alg: u16, // [u16; 1];
    pub salt: String,         // B64_String = [u8; 22] from [u8; 16] = 128bit,
}

// field order is ser & deser order
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FrameV1 {
    pub seq: u64, // [u64; 1]

    pub encryption_alg: u16, // [u16; 1]
    pub nonce: XNonce,       // [u8; 24]
    pub buf_len: u32,        // [u32; 8]

    pub buf: Vec<u8>, // [u8; buf_len]
}

pub trait SetBuf {
    fn set_buf(self, buf: Vec<u8>);
}

pub trait GetBuf {
    fn get_buf(&self) -> Vec<u8>;
}

pub trait Sequenced {
    fn get_seq(&self) -> u64;
}

pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
}

pub trait Deserialize {
    fn deserialize<R: Read>(r: &mut R) -> (IsEmpty, Self);
}

pub trait NeoCrypt {
    fn decrypt(&self, ctx: &Ctx) -> Self;
    fn encrypt(ctx: &Ctx, buf: Vec<u8>, seq: u64) -> Self;
}

impl Serialize for HeaderV1 {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 2 + 2 + 22];

        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());

        bytes[2..4].copy_from_slice(&self.compression_alg.to_le_bytes());

        bytes[4..26].copy_from_slice(self.salt.as_bytes());

        bytes
    }
}

impl Deserialize for HeaderV1 {
    fn deserialize<R: Read>(r: &mut R) -> (IsEmpty, Self) {
        let mut ver_b = [0u8; 2];
        let mut ver_v = vec![0u8; 2];
        let (b, _) = read_until(r, &mut ver_v, 2).unwrap(); // Check for finished reading
        if b == 0 {
            return (
                true,
                HeaderV1 {
                    version: 0,
                    compression_alg: 0,
                    salt: "".into(),
                },
            );
        }

        ver_b.copy_from_slice(&ver_v[0..2]);

        let version = u16::from_le_bytes(ver_b);

        let mut compression_b = [0u8; 2];
        r.read_exact(&mut compression_b).unwrap();

        let compression_alg = u16::from_le_bytes(compression_b);

        let mut salt_b = [0u8; 22];
        r.read_exact(&mut salt_b).unwrap();

        let salt = String::from_utf8(salt_b.to_vec()).unwrap();

        (
            false,
            HeaderV1 {
                version: version,
                compression_alg: compression_alg,
                salt: salt,
            },
        )
    }
}

unsafe impl Send for FrameV1 {}

impl GetBuf for FrameV1 {
    fn get_buf(&self) -> Vec<u8> {
        return self.buf.clone();
    }
}

impl SetBuf for FrameV1 {
    fn set_buf(mut self, buf: Vec<u8>) {
        self.buf = buf;
    }
}

impl Sequenced for FrameV1 {
    fn get_seq(&self) -> u64 {
        return self.seq;
    }
}

impl Serialize for FrameV1 {
    fn serialize(&self) -> Vec<u8> {
        let mut seq = [0u8; 8];
        let mut encryption_alg = [0u8; 2];
        let mut nonce = [0u8; 24];
        let mut buf_len = [0u8; 4];

        seq.copy_from_slice(&self.seq.to_le_bytes());
        encryption_alg.copy_from_slice(&self.encryption_alg.to_le_bytes());
        nonce.copy_from_slice(&self.nonce);
        buf_len.copy_from_slice(&self.buf_len.to_le_bytes());

        let mut data: Vec<u8> = vec![];

        seq.iter().for_each(|u| data.push(*u));
        encryption_alg.iter().for_each(|u| data.push(*u));
        nonce.iter().for_each(|u| data.push(*u));
        buf_len.iter().for_each(|u| data.push(*u));

        data.append(&mut self.buf.clone());

        data
    }
}

impl Deserialize for FrameV1 {
    fn deserialize<R: Read>(r: &mut R) -> (IsEmpty, Self) {
        let mut seq_b = [0u8; 8];
        let mut seq_v = vec![0u8; 8];
        let (b, _) = read_until(r, &mut seq_v, 8).unwrap();

        if b == 0 {
            // check for finished reading
            return (
                true,
                FrameV1 {
                    seq: 0,
                    encryption_alg: 0,
                    nonce: *XNonce::from_slice(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    buf_len: 0,
                    buf: vec![],
                },
            );
        }
        seq_b.copy_from_slice(&seq_v);

        let seq = u64::from_le_bytes(seq_b);

        let mut bst_t_b = [0u8; 2];
        let mut bst_t_v = vec![0u8; 2];
        read_until(r, &mut bst_t_v, 2).unwrap();
        bst_t_b.copy_from_slice(&bst_t_v);

        let encryption_alg = u16::from_le_bytes(bst_t_b);

        let mut nonce_v = vec![0u8; 24];
        read_until(r, &mut nonce_v, 24).unwrap();

        let nonce = XNonce::from_slice(&nonce_v);

        let mut buf_l_b = [0u8; 4];
        let mut buf_l_v = vec![0u8; 4];
        read_until(r, &mut buf_l_v, 4).unwrap(); // usize
        buf_l_b.copy_from_slice(&buf_l_v);

        let buf_len = u32::from_le_bytes(buf_l_b);

        let mut buf = vec![0u8; u32_usize(buf_len)];
        read_until(r, &mut buf, u32_usize(buf_len)).unwrap();

        (
            false,
            FrameV1 {
                seq: seq,

                encryption_alg: encryption_alg,
                nonce: *nonce,
                buf_len: buf_len,

                buf: buf,
            },
        )
    }
}

impl NeoCrypt for FrameV1 {
    fn decrypt(&self, ctx: &Ctx) -> Self {
        let processed = match self.encryption_alg {
            ENCRYPTION_ALG_NULL => panic!("encryption alg not set"),
            ENCRYPTION_ALG_TESTING_ONLY_NONE => self.buf.clone(),
            ENCRYPTION_ALG_CHACHPOLY20 => {
                // de-encrypt first
                let cipher = crate::hashing::generate_cipher(&ctx.pwd);
                let deciphertext = cipher.decrypt(&self.nonce, self.buf.as_ref()).unwrap();

                deciphertext.to_vec()
            }
            _ => {
                panic!("encryption alg not supported {}", self.encryption_alg);
            }
        };

        FrameV1 {
            seq: self.seq,

            encryption_alg: self.encryption_alg,
            nonce: self.nonce.clone(),
            buf_len: usize_u32(processed.len()),
            buf: processed,
        }
    }

    fn encrypt(ctx: &Ctx, buf: Vec<u8>, seq: u64) -> Self {
        let frame = match ctx.encryption_alg {
            ENCRYPTION_ALG_NULL => panic!("encryption alg not set"),
            ENCRYPTION_ALG_TESTING_ONLY_NONE => FrameV1 {
                seq: seq,

                encryption_alg: ctx.encryption_alg,
                nonce: *XNonce::from_slice(&[
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ]),
                buf_len: usize_u32(buf.len()),
                buf: buf,
            },
            ENCRYPTION_ALG_CHACHPOLY20 => {
                // encrypt second
                let cipher = crate::hashing::generate_cipher(&ctx.pwd);
                let nonce = crate::hashing::generate_nonce();
                let ciphertext = cipher.encrypt(&nonce, buf.as_ref()).unwrap();

                FrameV1 {
                    seq: seq,

                    encryption_alg: ctx.encryption_alg,
                    nonce: nonce,
                    buf_len: usize_u32(ciphertext.len()),
                    buf: ciphertext,
                }
            }
            _ => {
                panic!("encryption alg not supported {}", ctx.encryption_alg);
            }
        };

        frame
    }
}

pub fn bytes_fmt(n: usize) -> String {
    if (n > GB) {
        return format!("{}GB", n / GB);
    }
    if (n > MB) {
        return format!("{}MB", n / MB);
    }
    if (n > KB) {
        return format!("{}KB", n / KB);
    }
    return format!("{}B", n);
}

pub fn bytes_from_fmt(bytes: &str) -> Result<usize, &str> {
    if !bytes.is_ascii() {
        return Err("is not ascii");
    }

    let units = vec![("GB", GB), ("MB", MB), ("KB", KB), ("B", 1)];

    let contains_unit = units.iter().any(|(pattern, _)| bytes.contains(pattern));

    if !contains_unit {
        let value = usize::from_str_radix(bytes, 10).unwrap();
        return Ok(value);
    } else {
        for (pattern, unit) in units {
            let (left, right) = bytes.split_once(pattern).unwrap();
            if right.len() == 0 {
                return Err("malformed string");
            }

            return Ok(usize::from_str_radix(left, 10).unwrap() * unit);
        }
    }

    return Err("");
}

#[cfg(target_pointer_width = "32")]
pub fn u32_usize(n: u32) -> usize {
    usize::from_le_bytes(n.to_le_bytes())
}

#[cfg(target_pointer_width = "64")]
pub fn u32_usize(n: u32) -> usize {
    let b = n.to_le_bytes();
    usize::from_le_bytes([b[0], b[1], b[2], b[3], 0u8, 0u8, 0u8, 0u8])
}

#[cfg(target_pointer_width = "32")]
pub fn u64_usize(n: u64) -> usize {
    let b = n.to_le_bytes();
    usize::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(target_pointer_width = "64")]
pub fn u64_usize(n: u64) -> usize {
    usize::from_le_bytes(n.to_le_bytes())
}

#[cfg(target_pointer_width = "32")]
pub fn usize_u32(n: usize) -> u32 {
    u32::from_re_bytes(n.to_le_bytes())
}

#[cfg(target_pointer_width = "64")]
pub fn usize_u32(n: usize) -> u32 {
    let b = n.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(target_pointer_width = "32")]
pub fn usize_u64(n: usize) -> u64 {
    let b = n.to_le_bytes();
    u64::from_le_bytes(b[0], b[1], b[2], b[3], 0u8, 0u8, 0u8, 0u8)
}

#[cfg(target_pointer_width = "64")]
pub fn usize_u64(n: usize) -> u64 {
    u64::from_le_bytes(n.to_le_bytes())
}

#[cfg(target_pointer_width = "64")]
pub fn usize_u128(n: usize) -> u128 {
    let b = n.to_le_bytes();
    u128::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
    ])
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum IOFlag {
    EOF,         // EOF No Read
    ReadExact,   // Read Exact
    PartialRead, // Read and EOF
}

// r.read() until EOF or buffer is full, note if buf_size == 0, then reads until EOF
pub fn read_until<R: Read>(
    r: &mut R,
    buf: &mut Vec<u8>,
    buf_size: usize,
) -> Result<(usize, IOFlag), io::Error> {
    // read chunk into buffer
    let mut t = 0;
    loop {
        let mut b = 0;

        if buf_size == 0 {
            b = r.read(&mut buf[t..])?;
        } else {
            b = r.read(&mut buf[t..buf_size])?;
        }

        t += b;

        if t == buf.len() {
            return Ok((t, IOFlag::ReadExact));
        }
        if b == 0 && t == 0 {
            return Ok((t, IOFlag::EOF));
        }
        if b == 0 && t != 0 && t < buf_size {
            return Ok((t, IOFlag::PartialRead));
        }
    }
}

// Computes md5 in SIZED chunks
pub fn get_folder_md5(src: &PathBuf) -> String {
    debug!("getting folder md5 of {:?}", &src);

    let paths = get_folder_paths(src);
    let md5s = paths
        .iter()
        .map(|p| get_md5(OpenOptions::new().read(true).open(p).unwrap()));

    itertools::join(md5s, "")
}

pub fn get_folder_size(src: &PathBuf) -> String {
    let mut paths = vec![];

    for entry in WalkDir::new(src).into_iter() {
        match entry {
            Ok(e) => {
                if e.file_type().is_file() {
                    paths.push(e.metadata().unwrap().size());
                }
            }
            Err(e) => {
                panic!("error: could not walk directory {}", e)
            }
        }
    }

    paths.sort();
    join(paths, ",")
}

pub fn get_folder_paths(src: &PathBuf) -> Vec<PathBuf> {
    let mut paths = vec![];

    for entry in WalkDir::new(src).into_iter() {
        let e = entry.unwrap();

        if e.file_type().is_file() {
            paths.push(e.path());
        }
    }

    paths.sort();
    paths
}

// Computes md5 in SIZED chunks
pub fn get_md5<T>(reader: T) -> String
where
    T: Read,
{
    let mut r = reader;
    let mut md5s = vec![];

    const SIZE: usize = 8 * MB;
    loop {
        let mut buf = vec![0u8; SIZE];
        let eof = match read_until(&mut r, &mut buf, SIZE).unwrap() {
            (_, IOFlag::EOF) => true,
            _ => false,
        };
        if eof {
            break;
        }
        md5s.push(md5::compute(&buf).0);
    }

    let md5 = md5s.iter().fold(String::new(), |s, md5| {
        format!("{}{}", s, base64::encode(md5))
    });
    return md5;
}

pub fn new_uid(length: u64) -> String {
    let mut rng = thread_rng();

    String::from_utf8(
        (0..length)
            .into_iter()
            .map(|_| {
                let choice = rng.gen_range(0..3);

                if choice == 1 {
                    rng.gen_range(65..90) //upper
                } else if choice == 2 {
                    rng.gen_range(97..122) //lower
                } else {
                    rng.gen_range(48..57) //num
                }
            })
            .collect(),
    )
    .unwrap()
}

// create a random vector
pub fn rand_vec(range: Range<usize>) -> Vec<u8> {
    let mut v = vec![];
    for _ in range {
        v.push(rand::random::<u8>());
    }
    return v;
}

// split data into DEFAULT sized buffers for msg passing
pub fn split_data(data: &Vec<u8>) -> Vec<Vec<u8>> {
    let (chunks, remainder) = data.as_chunks::<DEFAULT_SIZE>();
    let mut buf: Vec<Vec<u8>> = chunks.into_iter().map(|c| Vec::from(c)).collect();

    buf.push(Vec::from(remainder));

    buf
}

pub struct PathCleanup {
    path: PathBuf,
}

impl PathCleanup {
    pub fn new(path: PathBuf) -> Self {
        return PathCleanup { path: path };
    }
}

// Strict! Only cleanup paths that start with /tmp
impl Drop for PathCleanup {
    fn drop(&mut self) {
        let tmp_path = PathBuf::new().join("tmp");

        let tmp = self.path.clone();
        if tmp.starts_with(tmp_path) {
            match std::fs::remove_dir_all(tmp) {
                Ok(()) => {}
                Err(e) => {
                    debug!("error: could not cleanup {:?}", &self.path)
                }
            }
        }
    }
}

static IS_LOGGER_INIT: Mutex<bool> = std::sync::Mutex::new(false);
pub fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    let mut is_logger_init = IS_LOGGER_INIT.lock().unwrap();

    if (!*is_logger_init) {
        *is_logger_init = true;
        // Configure logger at runtime
        fern::Dispatch::new()
            // Perform allocation-free log formatting
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    humantime::format_rfc3339(std::time::SystemTime::now()),
                    record.level(),
                    record.target(),
                    message
                ))
            })
            // Add blanket level filter -
            .level(log::LevelFilter::Debug)
            // Output to stdout, files, and other Dispatch configurations
            .chain(std::io::stdout())
            .chain(fern::log_file("output.log")?)
            .apply()
            // Apply globally
            .unwrap();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::{BufRead, BufReader, BufWriter, Write},
        iter::zip,
        path::PathBuf,
    };
    use crate::context::Init;

    use super::*;

    #[test]
    fn test_serialize_deserialize_header_v1() {
        let ctx = Ctx::new_test();
        
        Init::new(&ctx)
            .init_logger();
        

        let h = HeaderV1 {
            version: 1,
            compression_alg: COMPRESSION_ALG_NONE,
            salt: String::from(ctx.pwd.salt().unwrap().as_str()), // 22 byte string
        };

        let h_ser = h.serialize();
        let h_cur = std::io::Cursor::new(h_ser);
        let mut h_r = BufReader::new(h_cur);

        let (is_empty, h_de) = HeaderV1::deserialize(&mut h_r);

        assert_eq!(is_empty, false);
        assert_eq!(h.version, h_de.version);
        assert_eq!(h.compression_alg, h_de.compression_alg);
        assert_eq!(h.salt, h_de.salt);
    }

    #[test]
    fn test_serialize_deserialize_frame_v1() {
        let ctx = Ctx::new_test();
        
        Init::new(&ctx)
            .init_logger();

        let f = new_frame(256);

        let f_ser = f.serialize();
        let f_cur = std::io::Cursor::new(f_ser);
        let mut f_r = BufReader::new(f_cur);

        let (is_empty, f_de) = FrameV1::deserialize(&mut f_r);

        assert_eq!(is_empty, false);
        assert_eq!(f.seq, f_de.seq);
        assert_eq!(f.encryption_alg, f_de.encryption_alg);
        assert_eq!(f.nonce, f_de.nonce);
        assert_eq!(f.buf_len, f_de.buf_len);
        assert_eq!(f.buf.len(), f_de.buf.len());
        for (b1, b2) in zip(&f.buf, &f_de.buf) {
            assert_eq!(b1, b2);
        }
    }

    #[test]
    fn test_serialize_deserialize_header_frames_v1() {
        let ctx = Ctx::new_test();
        
        Init::new(&ctx)
            .init_logger();

        let mut datas = vec![];

        let h1 = HeaderV1 {
            version: 1,
            compression_alg: COMPRESSION_ALG_NONE,
            salt: String::from(ctx.pwd.salt().unwrap().as_str()), // 22 byte string
        };

        let f1 = new_frame(1 * KB);
        let f2 = new_frame(4 * KB);
        let f3 = new_frame(16 * KB);
        let f4 = new_frame(8 * MB);

        datas.push(h1.serialize());
        datas.push(f1.serialize());
        datas.push(f2.serialize());
        datas.push(f3.serialize());
        datas.push(f4.serialize());
        let data = datas.concat();

        let mut r = BufReader::new(Cursor::new(data));

        let (is_empty, h1a) = HeaderV1::deserialize(&mut r);
        assert_eq!(is_empty, false);
        assert_eq!(h1.version, h1a.version);
        assert_eq!(h1.salt, h1a.salt);

        let (is_empty, f1a) = FrameV1::deserialize(&mut r);
        assert_eq!(is_empty, false);
        let (is_empty, f2a) = FrameV1::deserialize(&mut r);
        assert_eq!(is_empty, false);
        let (is_empty, f3a) = FrameV1::deserialize(&mut r);
        assert_eq!(is_empty, false);
        let (is_empty, f4a) = FrameV1::deserialize(&mut r);
        assert_eq!(is_empty, false);

        let (is_empty, _) = FrameV1::deserialize(&mut r);
        assert_eq!(is_empty, true);

        let fs = vec![(f1, f1a), (f2, f2a), (f3, f3a), (f4, f4a)];

        for (f, f_de) in fs {
            assert_eq!(f.seq, f_de.seq);
            assert_eq!(f.encryption_alg, f_de.encryption_alg);
            assert_eq!(f.nonce, f_de.nonce);
            assert_eq!(f.buf_len, f_de.buf_len);
            assert_eq!(f.buf.len(), f_de.buf.len());

            for (b1, b2) in zip(&f.buf, &f_de.buf) {
                assert_eq!(b1, b2);
            }
        }
    }

    fn new_frame(size: usize) -> FrameV1 {
        FrameV1 {
            seq: 1,

            encryption_alg: ENCRYPTION_ALG_CHACHPOLY20,
            nonce: *XNonce::from_slice(&[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]),
            buf_len: usize_u32(size),
            buf: vec![1u8; size],
        }
    }
}
