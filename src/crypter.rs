/* Encrpter & Decrypter file
*/

use crossbeam_channel::Sender;
use crossbeam_channel::Receiver;
use flate2::read::GzDecoder;
use flate2::read::GzEncoder;
use flate2::Compression;
use log::debug;
use rayon::iter::ParallelBridge;
use tar::Archive;
use tar::Builder;
use crate::common::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::thread::{spawn, JoinHandle};
use rayon::iter::ParallelIterator;


use crate::streaming::{StreamBufWriter, StreamBufReader};
type Seq = u64;


fn park_sender<T>(sender: Sender<T>) { while ! sender.is_empty() {} }



fn spawn_encrypt<T>(ctx: &Ctx, receiver: Receiver<(Seq, Vec<u8>)>, sender: Sender<T>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: ZipCrypt,
        T: Serialize,
        T: Deserialize,
    {

    let ctx = ctx.clone();
    spawn(move || {
        let ctx = &ctx;

        receiver
            .iter()
            .par_bridge()
            .for_each(|(seq, buf)| {

            let frame = T::zip_encrypt(ctx, buf, seq);

            match sender.send(frame) {
                Ok(()) => {},
                Err(e) => {panic!("error: sender error during encrypt: {:?}", e);}
            }
        });
    })
}

fn spawn_decrypt<T>(ctx: &Ctx, receiver: Receiver<T>, sender: Sender<T>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: ZipCrypt,
        T: Serialize,
        T: Deserialize,
        T: Sequenced,
        T: SetBuf,
    {

    let ctx = ctx.clone();
    spawn(move || {

    receiver
        .iter()
        .par_bridge()
        .for_each(|frame| {

        let f = frame.unzip_decrypt(&ctx);
        match sender.send(f) {
            Ok(()) => {},
            Err(e) => {panic!("error: sender error during decrypt: {:?}", e);}
        }
    });
    })
}

fn spawn_writer(mut w: BufWriter<File>, receiver: Receiver<Vec<u8>>) -> JoinHandle<()>{
    spawn(move || {
        receiver.into_iter().for_each(move |frame| {
            w.write_all(&frame).unwrap();
            w.flush().unwrap();
        });
    })
}

fn spawn_frame_reader<T>(mut r: BufReader<File>, sender: Sender<T>) -> JoinHandle<()> 
    where
        T: Send + 'static,
        T: Deserialize,
        T: GetBuf,
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
    })
}

fn spawn_packer(src: &PathBuf, sw: StreamBufWriter) -> JoinHandle<()>{

    let src = src.clone();
    spawn(move || {
        let mut builder = Builder::new(sw); 

        builder.append_dir_all(".", &src).unwrap();
        builder.finish().unwrap(); // finish writing files

        debug!("closing packer");
    })
}

fn spawn_unpacker(trg: &PathBuf, sr: StreamBufReader) -> JoinHandle<()>{

    let trg = trg.clone();
    spawn(move || {
        let mut archive = Archive::new(sr);
        archive.unpack(trg).unwrap();

        debug!("closing unpacker");
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
    })
}

fn spawn_compressor_gzip(mut br: StreamBufReader, sender: Sender<Vec<u8>>) -> JoinHandle<()>{
    spawn(move || {

        let mut encoder = GzEncoder::new(br, Compression::default());
        let mut buf = vec![0u8; DEFAULT_SIZE];

        loop {
            let (bytes_read, _) = read_until(&mut encoder, &mut buf, DEFAULT_SIZE).unwrap();

            if bytes_read == 0 {
                break;
            } else {
                sender.send(buf[..bytes_read].to_vec()).unwrap();
                buf = vec![0u8; DEFAULT_SIZE];   
            }
        }
        
        debug!("closing compressor");
    })
}

fn spawn_decompressor_gzip(br: StreamBufReader, sender: Sender<Vec<u8>>) -> JoinHandle<()>{

    spawn(move || {
        let mut decoder = GzDecoder::new(br);
        let mut buf = vec![0u8; DEFAULT_SIZE];

        loop {
            let (bytes_read, _) = read_until(&mut decoder, &mut buf, DEFAULT_SIZE).unwrap();

            if bytes_read == 0 {
                break;
            } else {
                sender.send(buf[..bytes_read].to_vec()).unwrap();
                buf = vec![0u8; DEFAULT_SIZE];   
            }
        }
        debug!("closing decompressor");
    })
}

// attaches seq to outgoing Vec<u8> as (u64, Vec<u8>)
fn spawn_with_seq<T>(receiver: Receiver<T>, sender: Sender<(u64, T)>) -> JoinHandle<()>
where 
    T: Send + 'static
{
    spawn(move ||{
        receiver.iter().enumerate().for_each(|(seq, data)| {
            sender.send((usize_u64(seq), data)).unwrap();
        });
    })
}

// unpacker but orders by sequence before writing
fn spawn_to_seq_bytes<T>(receiver: Receiver<T>, sender: Sender<Vec<u8>>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: Sequenced,
        T: GetBuf,
{
    spawn(move ||{
        receiver.iter().for_each(|frame| {
            sender.send(frame.get_buf().clone()).unwrap();
        });
    })
}

// unpacker but orders by sequence before writing
fn spawn_to_serialize<T>(receiver: Receiver<T>, sender: Sender<Vec<u8>>) -> JoinHandle<()>
    where
        T: Send + 'static,
        T: Serialize,
{
    spawn(move ||{
        receiver.iter().for_each(|frame| {
            sender.send(frame.serialize()).unwrap();
        });
    })
}

#[cfg(test)]
mod tests {

    use crate::common::*;

    use super::*;
    use std::{fs::OpenOptions, io::Write, sync::{Arc, Mutex}};
    use crossbeam_channel::{bounded, unbounded};

    use dirs::home_dir;
    use flate2::{bufread::GzEncoder, Compression};
    use log::debug;
    use rsa::pkcs8::der::Header;

    /* Packer(Tar) -> Unpacker(Tar)*/
    #[ignore = "run serially"]
    #[test]
    fn test_packer_unpacker() {
        let t = &TestInit::new()
            .with_storage()
            .with_logger();

        let src= std::env::current_dir().unwrap().join("dummy_data").join("documents");
        let trg = t.new_tmp_path();

        let (s, r) = unbounded();

        let sw = StreamBufWriter::new(s);
        let sr = StreamBufReader::new(r);

        let t1 = spawn_packer(&src, sw);
        let t2 = spawn_unpacker(&trg, sr);

        t1.join().unwrap();
        t2.join().unwrap();
        
        assert_eq!(get_folder_size(&src), get_folder_size(&trg))
        // assert_eq!(get_folder_md5(&src), get_folder_md5(&trg)) // takes too long
    }

    // Packer -> Compressor -> Decompressor -> Unpacker
    #[test]
    fn test_compressor() {
        let t = TestInit::new()
            .with_storage()
            .with_logger();

        let ctx = &t.get_ctx();
        let size = t.get_channel_size();

        let folders = [
            t.get_documents(),
        ];

        for folder in folders {

            let decompressed: PathBuf = t.new_tmp_path();

            let (s_packer, r_packer) = bounded(size);
            let (s_compressor, r_compressor) = bounded(size);
            let (s_decompressor, r_decompressor) = bounded(size);

            let t1 = spawn_packer(&folder, StreamBufWriter::new(s_packer));
            let t2 = spawn_compressor_gzip(StreamBufReader::new(r_packer), s_compressor);
            let t3 = spawn_decompressor_gzip(StreamBufReader::new(r_compressor), s_decompressor);
            let t4 = spawn_unpacker(&decompressed, StreamBufReader::new(r_decompressor));

            t4.join().unwrap();
            t3.join().unwrap();
            t2.join().unwrap();
            t1.join().unwrap();

            assert_eq!(get_folder_size(&folder), get_folder_size(&decompressed));

            debug!("folder {}", folder.to_str().unwrap());
        }
    }

    /*
    Encrypter Decrypter Test for message pipeline

    packer -> encrypter -> order_by -> serializer
    frame_reader -> decrypter -> deserializer -> order_by -> unpacker

    */
    #[test]
    fn test_encrypt_decrypt() {
        let t = TestInit::new()
            .with_storage()
            .with_logger();

        let ctx = &t.get_ctx();
        let size = t.get_channel_size();

        
        let folders = [
            t.get_documents(),
        ];

        for folder in folders {

            debug!("folder {}", folder.to_str().unwrap());
            let encrypted: PathBuf = t.new_tmp_path();
            let decrypted: PathBuf = t.new_tmp_path();

            let header: HeaderV1;

            // Encrypt and write to file
            {
                let f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&encrypted)
                    .unwrap();

                let mut bw = BufWriter::new(f);

                // write header
                header = HeaderV1{
                    version: VERSION_1,
                    salt: String::from(ctx.pwd.salt().unwrap().as_str()),
                };
                bw.write_all(&header.serialize()).unwrap();
                
                // pack as tar and write data packets
                let (s_packer, r_packer) = bounded(size);
                let (s_with_seq, r_with_seq) = bounded(size);
                let (s_encrypter, r_encrypter) = bounded(size);
                let (s_order_by, r_order_by) = bounded(size);
                let (s_to_bytes, r_to_bytes) = bounded(size);

                let t1 = spawn_packer(&folder, StreamBufWriter::new(s_packer));
                let t2 = spawn_with_seq(r_packer, s_with_seq);
                let t3 = spawn_encrypt::<FrameV1>(ctx, r_with_seq, s_encrypter);
                let t4 = spawn_order_by_seq(r_encrypter, s_order_by);
                let t5 = spawn_to_serialize(r_order_by, s_to_bytes);
                let t6 = spawn_writer(
                    bw,
                    r_to_bytes,
                );

                t1.join().unwrap();
                t2.join().unwrap();
                t3.join().unwrap();
                t4.join().unwrap();
                t5.join().unwrap();
                t6.join().unwrap();
            }

            // Decrypt and write to file
            {
                // read header
                let mut r = BufReader::new(OpenOptions::new()
                    .read(true)
                    .open(&encrypted)
                    .unwrap()
                );
                let (is_empty, header_de) = HeaderV1::deserialize(&mut r);
                assert_eq!(is_empty, false);
                assert_eq!(header.version, header_de.version);
                assert_eq!(header.salt, header_de.salt);
                
                // unpack tar and read frames
                let (s_reader, r_reader) = bounded(size);
                let (s_decrypter, r_decrypter) = bounded(size);
                let (s_order_by, r_order_by) = bounded(size);
                let (s_to_bytes, r_to_bytes) = bounded(size);

                let t1 = spawn_frame_reader::<FrameV1>(r, s_reader);
                let t2 = spawn_decrypt(&ctx, r_reader, s_decrypter);
                let t3 = spawn_order_by_seq(r_decrypter, s_order_by);
                let t4 = spawn_to_seq_bytes(r_order_by, s_to_bytes);
                let t5 = spawn_unpacker(&decrypted, StreamBufReader::new(r_to_bytes));

                t1.join().unwrap();
                t2.join().unwrap();
                t3.join().unwrap();
                t4.join().unwrap();
                t5.join().unwrap();
            }

            assert_eq!(get_folder_size(&folder), get_folder_size(&decrypted));
        }
    }

    #[test]
    fn test_msgs_encrypt_decrypt() {
        let t = TestInit::new()
            .with_storage()
            .with_logger();

        let ctx = &t.get_ctx();
        let size = t.get_channel_size();

        let datas = [
            rand_vec(0..1),
            rand_vec(0..256),
            rand_vec(0..DEFAULT_SIZE),
            rand_vec(0..DEFAULT_SIZE * 2 ),
            rand_vec(0..DEFAULT_SIZE * 4),
            rand_vec(0..DEFAULT_SIZE * 4 + 8),
            rand_vec(0..DEFAULT_SIZE * 4 - 1),
            rand_vec(0..DEFAULT_SIZE * 1000 + 256),
        ];

        let data_msgs: Vec<Vec<Vec<u8>>> = datas.iter().map(|d| {split_data(d)}).collect();

        debug!("data generation finished");

        for (msgs, data) in itertools::zip_eq(data_msgs, datas) {
            debug!("encrypt decrypt: processing data of len {} bytes", data.len());
            debug!("encrypt decrypt: splitting data of len {} bytes into {} separate channel message", data.len(), msgs.len());

            let m_msgs = Arc::new(Mutex::new(msgs));
            let m_encrypted = Arc::new(Mutex::new(vec![]));
            let m_decrypted = Arc::new(Mutex::new(vec![]));

            let m_msgs_cpy = m_msgs.clone();
            let m_encrypted_cpy1 = m_encrypted.clone();
            let m_encrypted_cpy2 = m_encrypted.clone();
            let m_decrypted_cpy = m_decrypted.clone();

            let (s_reader, r_reader) = bounded(size);
            let (s_writer, r_writer) = bounded(size);


            // --- encrypter ---
            // reader -> encrypter -> write -> Vec<_>

            let reader_t = spawn(move ||{
                debug!("encrypt decrypt: spawn reader in");
                let msgs = &m_msgs_cpy.lock().unwrap();

                msgs.iter().enumerate().for_each(|(seq , bytes)| {
                    s_reader.send((usize_u64(seq), bytes.clone())).unwrap();
                });

                debug!("encrypt decrypt: channel closed: reader")
            });

            debug!("encrypt decrypt: spawn encrypter");
            let encrypter_t = spawn_encrypt::<FrameV1>(
                ctx,
                r_reader,
                s_writer
            );

            let writer_t = spawn(move ||{
                debug!("encrypt decrypt: spawn writer out");
                let mut encrypted = m_encrypted_cpy1.lock().unwrap();

                r_writer.iter().for_each(|frame|{
                    encrypted.push(frame);
                });
                debug!("encrypt decrypt: channel closed: writer")
            });


            writer_t.join().unwrap();
            encrypter_t.join().unwrap();
            reader_t.join().unwrap();


            // --- decrypter ---
            // Vec<_> -> reader -> decrypter -> order by -> writer

            let (s_reader, r_reader) = bounded(size);
            let (s_order_by_seq, r_order_by_seq) = bounded::<FrameV1>(size);
            let (s_writer, r_writer) = bounded(size);

            let reader_t = spawn(move ||{
                let encrypted = &m_encrypted_cpy2.lock().unwrap();

                encrypted.iter().for_each(|frame| {
                    s_reader.send(frame.clone()).unwrap();
                });

                // park_sender(s_reader);
                debug!("encrypt decrypt: channel closed: reader")
            });

            let decrypter_t = spawn_decrypt::<FrameV1>(ctx, r_reader, s_order_by_seq);
            let order_by_t = spawn_order_by_seq::<FrameV1>(r_order_by_seq, s_writer);

            let writer_t = spawn(move ||{
                debug!("encrypt decrypt: spawn writer out");
                let mut decryped = m_decrypted_cpy.lock().unwrap();

                r_writer.iter().for_each(|frame|{
                    decryped.extend(frame.buf);
                });
                debug!("encrypt decrypt: channel closed: writer")
            });

            reader_t.join().unwrap();
            decrypter_t.join().unwrap();
            order_by_t.join().unwrap();
            writer_t.join().unwrap();

            // --- verify ---
            // data == Vec<_>
            {
                let decrypted = m_decrypted.lock().unwrap();

                assert_eq!(decrypted.len(), data.len());

                for (i, (pd, d)) in itertools::enumerate(itertools::zip_eq(decrypted.to_vec(), data)){
                    if pd != d {
                        debug!("at index {}", i);
                    }
                    assert_eq!(pd, d);
                }
            }
            debug!("");
        }
    }

    #[test]
    fn test_split_data() {
        let datas = [
            rand_vec(0..1),
            rand_vec(0..256),
            rand_vec(0..256 + 1),
            rand_vec(0..256 - 1),
            rand_vec(0..DEFAULT_SIZE),
            rand_vec(0..DEFAULT_SIZE * 4),
            rand_vec(0..DEFAULT_SIZE * 4 + 1),
            rand_vec(0..DEFAULT_SIZE * 4 - 1),
            rand_vec(0..DEFAULT_SIZE * 4 + 256),
        ];

        let bufs: Vec<Vec<Vec<u8>>> = datas.iter().map(|d| {split_data(d)}).collect();

        for (data, buf) in itertools::zip_eq(datas, bufs){

            let buf_flat: Vec<u8> = buf.into_iter().flatten().collect::<Vec<_>>();
            assert_eq!(data.len(), buf_flat.len());

            for (i, (d, b)) in itertools::enumerate(itertools::zip_eq(data, buf_flat)) {
                if d != b {
                    debug!("at index {}", i);
                }
                assert_eq!(d, b);
            }
        }
    }
}