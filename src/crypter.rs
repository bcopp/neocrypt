/* Encrpter & Decrypter file
*/

use crossbeam_channel::Sender;
use crossbeam_channel::Receiver;
use tar::Archive;
use tar::Builder;
use crate::common::*;
use core::ops::Range;
use core::sync;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path::PathBuf;
use std::thread::{spawn, JoinHandle};

use crate::streaming::{StreamBufWriter, StreamBufReader};


fn park_sender<T>(sender: Sender<T>) { while ! sender.is_empty() {} }

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
    use std::{io::{Read, Write}, sync::{Arc, Mutex}};
    use crossbeam::thread;
    use crossbeam_channel::{bounded, unbounded};
    use log::debug;
    use std::io::Cursor;
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