/* Encrpter & Decrypter file
*/

use cipher::generic_array::iter;
use crossbeam::select;
use crossbeam_channel::bounded;
use crossbeam_channel::Select;
use crossbeam_channel::SendError;
use crossbeam_channel::Sender;
use crossbeam_channel::Receiver;
use flate2::bufread::GzDecoder;
use flate2::bufread::GzEncoder;
use flate2::Compression;
use log::debug;
use log::trace;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use rsa::pkcs8::der::Sequence;
use tar::Archive;
use tar::Builder;
use crate::common::*;
use crate::new;
use core::num;
use core::ops::Range;
use core::sync;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::sleep;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use std::time::Instant;
use flate2::GzBuilder;


fn park_sender<T>(sender: Sender<T>) { while ! sender.is_empty() {} }

fn encrypt(ctx: &Ctx, src: &PathBuf, trg: &PathBuf) -> Result<(), std::io::Error> {
    let channel_size =  num_cpus::get() * 2;

    let src_reader = BufReader::new(
        OpenOptions::new().read(true).open(src)?
    );

    let trg_writer = BufWriter::new(
        OpenOptions::new().write(true).create_new(true).open(trg)?
    );

    /* ENCRYPT

    let (
        reader_s_crypter,
        crypter_r_reader
    ) = bounded(channel_size);

    let (
        crypter_s_writer,
        writer_r_crypter
    ) = bounded::<FrameV1>(channel_size);

        reader(FILE: packer_r) -> u8s

        encrypt_serialize<T> (u8s) -> u8s

        writer (u8s)
    */

    /* DECRYPT
        reader_crypt(unpacker_r) -> T
        decrypt_deserialize (T) -> u8s
        writer (u8s)
            upacker -> FILE: u8s
    */

    // packer_reader = 

    /*
    let (
        reader_s_crypter,
        crypter_r_reader
    ) = bounded(channel_size);

    let (
        crypter_s_writer,
        writer_r_crypter
    ) = bounded(channel_size);


    let reader_t = spawn_reader(
        packer_reader,
        reader_s_crypter
    );

    let crypter_t = spawn_encrypt<FrameV1>(
        ctx,
        crypter_r_reader,
        crypter_s_writer
    );

    let writer_t = spawn_writer(
        trg_writer,
        writer_r_crypter
    );

    reader_t.join().unwrap();
    crypter_t.join().unwrap();
    writer_t.join().unwrap();

    */
    Ok(())
} 

fn decrypt(ctx: &Ctx, src: &PathBuf, trg: &PathBuf) -> Result<(), std::io::Error> {
    let channel_size =  num_cpus::get() * 2;

    let src_reader = BufReader::new(
        OpenOptions::new().read(true).open(src)?
    );

    let trg_writer = BufWriter::new(
        OpenOptions::new().write(true).create_new(true).open(trg)?
    );

    let (reader_s_crypter, crypter_r_reader) = bounded(channel_size);
    let (crypter_s_writer, writer_r_crypter) = bounded(channel_size);

    let reader_t = spawn_reader(src_reader, reader_s_crypter);
    //let crypter_t = spawn_decrypt(ctx, crypter_r_reader, crypter_s_writer);
    let writer_t = spawn_writer(trg_writer, writer_r_crypter);

    reader_t.join().unwrap();
    //crypter_t.join().unwrap();
    writer_t.join().unwrap();

    Ok(())
} 

fn spawn_reader(mut packer_r: BufReader<File>, sender: Sender<Vec<u8>>) -> JoinHandle<()> {
    spawn(move || {

        loop {
            let mut buf = vec![0u8; DEFAULT_SIZE]; // 4MB
            let len = buf.len();

            let flag = read_until(&mut packer_r, &mut buf, len).unwrap();

            let b = match flag {
                (_, IOFlag::EOF) => break,
                (b, IOFlag::PartialRead) => b,
                (b, IOFlag::ReadExact) => b,
            };

            let result = sender.send(buf[..b].to_vec());

            if result.is_err() {
                panic!("{:?}", result);
            }
        }

        park_sender(sender);
    })
}

fn spawn_reader_decrypt<T>(mut r: BufReader<File>, sender: Sender<T>) -> JoinHandle<()> 
    where
        T: Send + 'static,
        T: ZipCrypt,
        T: Serialize,
        T: Deserialize,
    {

    spawn(move || {

        loop {

            let (is_empty, f) = T::deserialize(&mut r);

            if is_empty {
                break;
            }

            let result = sender.send(f);

            if result.is_err() {
                panic!("{:?}", result);
            }
        }

        park_sender(sender);
    })
}

fn spawn_encrypt<T>(ctx: &Ctx, receiver: Receiver<Vec<u8>>, sender: Sender<T>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: ZipCrypt,
        T: Serialize,
        T: Deserialize,
    {

    let ctx = ctx.clone();
    spawn(move || {
        let ctx = &ctx;


        let seq_atomic = sync::atomic::AtomicU64::new(0);
        receiver.into_iter().for_each(|buf| {

            let seq = seq_atomic.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            let frame = T::zip_encrypt(ctx, buf, seq);

            match sender.send(frame) {
                Ok(()) => {},
                Err(e) => {panic!("error: sender error during encrypt: {:?}", e);}
            }
        });

        park_sender(sender);
    })
}

fn spawn_decrypt<T>(ctx: &Ctx, receiver: Receiver<T>, sender: Sender<Vec<u8>>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: ZipCrypt,
        T: Serialize,
        T: Deserialize,
        T: SetBuf,
    {

    let ctx = ctx.clone();
    spawn(move || {

        receiver.into_iter().for_each(|frame| {
            let data = frame.unzip_decrypt(&ctx);
            match sender.send(data) {
                Ok(()) => {},
                Err(e) => {panic!("error: sender error during decrypt: {:?}", e);}
            }
        });

        park_sender(sender);
    })
}

fn spawn_writer(mut w: BufWriter<File>, receiver: Receiver<Vec<u8>>) -> JoinHandle<()>{
    spawn(move || {
        receiver.into_iter().for_each(move |frame| {
            w.write_all(&frame).unwrap();
        });
    })
}

struct StreamBufWriter {
    s: Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl StreamBufWriter {
    fn new(sender: Sender<Vec<u8>>) -> Self {
        StreamBufWriter{
            s: sender,
            buf: vec![],
        }
    }
}

impl Write for StreamBufWriter {

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {

        self.buf.extend_from_slice(buf);


        if self.buf.len() > DEFAULT_SIZE {

            match self.s.send(self.buf.clone()) {
                Ok(()) => {},
                Err(e) => {trace!("error: streambufwriter send {:?}", e)}
            }
            self.buf = vec![];
        }

        return Ok(buf.len());
    }

    fn flush(&mut self) -> io::Result<()> {

        if ! self.buf.is_empty() {
            match self.s.send(self.buf.clone()) {
                Ok(()) => {self.buf = vec![]},
                Err(e) => {trace!("error: streambufwriter send, internal buf len {:?}, {:?}", self.buf.len(), e)},
            }
        }

        Ok(())
    }

}

// auto flush and wait for channel empty
impl Drop for StreamBufWriter{
    fn drop(&mut self) {
        self.flush().unwrap();
        while ! self.s.is_empty() {}
    }
}


struct StreamBufReader{
    buf: Vec<u8>,

    r: Receiver<Vec<u8>>,
    is_closed: bool,
}

impl StreamBufReader{
    fn new(receiver: Receiver<Vec<u8>>) -> Self {

        StreamBufReader{
            buf: vec![],

            r: receiver,
            is_closed: false,
        }
    }
}

impl<'a> Read for StreamBufReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {

        let mut bytes_read = 0;

        while bytes_read != buf.len() {

            if self.buf.is_empty() {
                match self.r.recv() {
                    Ok(b) => {self.buf = b},
                    Err(_) => {return Ok(bytes_read);},
                }
            }

            if self.buf.len() > buf.len() {
                let (left, right) = self.buf.split_at(buf.len());
                buf.copy_from_slice(left);
                bytes_read += left.len();
                self.buf = Vec::from(right);
            } else {
                buf[..self.buf.len()].copy_from_slice(&self.buf);
                bytes_read += self.buf.len();
                self.buf = vec![];
            }
        }

        Ok(bytes_read)
    }
}



fn spawn_packer(src: &PathBuf, sw: StreamBufWriter) -> JoinHandle<()>{

    let src = src.clone();
    spawn(move || {
        let mut builder = Builder::new(sw); 

        builder.append_dir_all(".", &src).unwrap();
        builder.finish().unwrap(); // finish writing files
    })
}


fn spawn_unpacker(trg: &PathBuf, sr: StreamBufReader) -> JoinHandle<()>{

    let trg = trg.clone();
    spawn(move || {
        let mut archive = Archive::new(sr);
        archive.unpack(trg).unwrap();
    })
}

// unpacker but orders by sequence before writing
fn spawn_order_by_seq<T>(receiver: Receiver<T>, sender: Sender<T>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: Sequenced
{

    spawn(move || {

        let mut frames = HashMap::new();
        let mut seq = 0;

        receiver.iter().for_each(|frame|{
            frames.insert(frame.get_seq(), frame);

            loop {
                match frames.remove(&seq) {
                    Some(f) => {
                        match sender.send(f){
                            Ok(()) => {seq += 1},
                            Err(e) => {panic!("order_by_seq send error with frames len of {}, {:?}", frames.len(), e)},
                        }
                    },
                    None => {break;},
                }
            }
        });

        park_sender(sender);
    })
}

fn vec_from_range(range: Range<usize>) -> Vec<u8> {
    let mut v = vec![];
    for _ in range{
        v.push(rand::random::<u8>());
    }
    return v;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use crossbeam::thread;
    use crossbeam_channel::unbounded;
    use io::Cursor;
    use itertools::assert_equal;

    use crate::common::{get_linux_context, new_tmp_dir};

    #[test]
    fn test_streambuf_reader_writer() {
        let t = &TestInit::new()
            .storage()
            .logger();

        let datas = [
            vec_from_range(0..1),
            vec_from_range(0..2^8),
            vec_from_range(0..2^8 + 1),
            vec_from_range(0..2^8 - 1),
            vec_from_range(0..DEFAULT_SIZE),
            vec_from_range(0..DEFAULT_SIZE * 4),
            vec_from_range(0..DEFAULT_SIZE * 4 + 1),
            vec_from_range(0..DEFAULT_SIZE * 4 - 1),
            vec_from_range(0..DEFAULT_SIZE * 4 + 2^8),
        ];

        for d1 in datas {
            let d1 = Arc::new(Mutex::new(d1));
            let d2 = Arc::new(Mutex::new(vec![]));

            let d1_cpy = d1.clone();
            let d2_cpy = d2.clone();

            let (s, r) = unbounded();

            let t1 = spawn(move ||{
                let mut sw = StreamBufWriter::new(s);

                let d = &d1_cpy.lock().unwrap();
                sw.write_all(d).unwrap(); // write into sw
                sw.flush().unwrap();
            });


            let t2 = spawn(move ||{
                let mut sr = StreamBufReader::new(r);

                let mut d = d2_cpy.lock().unwrap();
                sr.read_to_end(&mut d).unwrap(); // read from sr
            });

            t1.join().unwrap();
            t2.join().unwrap();

            {
                let d1 = &d1.lock().unwrap();
                let d2 = &d2.lock().unwrap();

                assert_eq!(d1.len(), d2.len());

                for i in (0 .. d1.len()).into_iter() {
                    assert_eq!(d1[i], d2[i]);
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_packer_unpacker() {
        let t = &TestInit::new()
            .storage()
            .logger();

        let src= PathBuf::from("/home/cflex/Dropbox/code2/bastion-mount/dummy_data");
        let (trg, trg_name)= new_tmp_dir();

        let (s, r) = unbounded();

        let sw = StreamBufWriter::new(s);
        let sr = StreamBufReader::new(r);

        let t1 = spawn_packer(&src, sw);
        let t2 = spawn_unpacker(&trg, sr);

        t1.join().unwrap();
        t2.join().unwrap();
        
        assert_eq!(get_file_sizes(&src), get_file_sizes(&trg))
        // assert_eq!(get_folder_md5(&src), get_folder_md5(&trg)) // takes too long
    }

    #[test]
    fn test_encrypt_decrypt() {
        let t = TestInit::new()
            .storage()
            .logger();

        let ctx = &t.get_ctx();
        let size = t.get_channel_size();

        let datas = [
            vec_from_range(0..1),
            vec_from_range(0..2^8),
            vec_from_range(0..2^8 + 1),
            vec_from_range(0..2^8 - 1),
            vec_from_range(0..DEFAULT_SIZE),
            vec_from_range(0..DEFAULT_SIZE * 4),
            vec_from_range(0..DEFAULT_SIZE * 4 + 1),
            vec_from_range(0..DEFAULT_SIZE * 4 - 1),
            vec_from_range(0..DEFAULT_SIZE * 4 + 2^8),
            vec_from_range(0..DEFAULT_SIZE * 256 + 2^8),
        ];

        for d1 in datas {
            let d1 = Arc::new(Mutex::new(d1));
            let d2 = Arc::new(Mutex::new(vec![]));

            let d1_cpy = d1.clone();
            let d2_cpy = d2.clone();


            let (s_packer, r_packer) = bounded(size);
            let (s_order_by_seq, r_order_by_seq) = bounded::<FrameV1>(size);
            let (s_decrypter, r_decrypter) = bounded::<FrameV1>(size);
            let (s_unpacker, r_unpacker) = bounded(size);


            let encrypter_t = spawn_encrypt(ctx, r_packer, s_order_by_seq);
            let order_by_seq = spawn_order_by_seq(r_order_by_seq, s_decrypter);
            let decrypter_t = spawn_decrypt(ctx, r_decrypter, s_unpacker);

            // start sending data
            let packer_t = spawn(move || {
                let d1 = d1_cpy.lock().unwrap();
                s_packer.send(d1.to_vec());

                park_sender(s_packer);
            });

            // start receiving data
            let unpacker_t = spawn(move || {
                let mut d2 = d2_cpy.lock().unwrap();
                r_unpacker.iter().for_each(|d| {
                    d2.extend_from_slice(&d);
                });
            });

            packer_t.join().unwrap();
            encrypter_t.join().unwrap();
            order_by_seq.join().unwrap();
            decrypter_t.join().unwrap();
            unpacker_t.join().unwrap();


            {
                let d1 = &d1.lock().unwrap();
                let d2 = &d2.lock().unwrap();

                assert_eq!(d1.len(), d2.len());
                debug!("d1 {}, d2 {}", d1.len(), d2.len());

                for i in (0 .. d1.len()).into_iter() {
                    assert_eq!(d1[i], d2[i]);
                }
            }
        }
    }
}



/*

builder!{
    start(t)
    next(t)
    next(t)
    sort()
    sort_by_key()
    next(t)
    finish(t)
}.collect()

new
..add files

close
... tar files
... encrypt files
... order frames
... write out u8s

*/

/*
let b = SeqBuilder


let (s_t1, r_t1) = bounded(name, size);
let (s_t2, r_t2) = bounded(size);
let (s_t3, r_t3) = bounded(size);
let (s_t4, r_t4) = bounded(size);

b::new(
    [s_t1, s_t2, s_t3]
)
    .start()
    .next
    .finish()
    .collect()


b.run_pool()

*/