use std::io::{self, Read, Write};

use crossbeam_channel::{Receiver, Sender};
use log::{debug, trace};
use crate::common::*;


pub struct StreamBufWriter {
    pub s: Sender<(u64, Vec<u8>)>,
    pub buf: Vec<u8>,
    pub seq: u64,
}

impl StreamBufWriter {
    pub fn new(sender: Sender<(u64, Vec<u8>)>) -> Self {
        StreamBufWriter{
            s: sender,
            buf: vec![],
            seq: 0,
        }
    }
}

impl Write for StreamBufWriter {

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {

        self.buf.extend_from_slice(buf);

        if self.buf.len() > DEFAULT_SIZE {

            match self.s.send((self.seq, self.buf.clone())) {
                Ok(()) => {self.seq += 1},
                Err(e) => {trace!("error: streambufwriter send {:?}", e)}
            }
            self.buf = vec![];
        }


        return Ok(buf.len());
    }

    fn flush(&mut self) -> io::Result<()> {

        if ! self.buf.is_empty() {
            match self.s.send((self.seq, self.buf.clone())) {
                Ok(()) => {self.buf = vec![]; self.seq += 1},
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


pub struct StreamBufReader{
    r: Receiver<(u64, Vec<u8>)>,
    buf: Vec<u8>,
}

impl StreamBufReader{
    pub fn new(receiver: Receiver<(u64, Vec<u8>)>) -> Self {

        StreamBufReader{
            r: receiver,
            buf: vec![],
        }
    }
}

impl Read for StreamBufReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {

        let mut bytes_read = 0;

        // read in all bytes
        while bytes_read != buf.len() {

            let remaining = buf.len() - bytes_read;

            // refresh internal buffer
            if self.buf.is_empty() {
                match self.r.recv() {
                    Ok((_, buf)) => {self.buf = buf},
                    Err(_) => {return Ok(bytes_read);},
                }
            }

            if self.buf.len() > remaining {

                // split internal buf
                let (left, right) = self.buf.split_at(remaining); // copy partial off internal buffer

                // copy partial internal buf to buf
                buf[bytes_read..].copy_from_slice(left);

                // add to bytes read
                bytes_read += left.len();

                // set internal buffer after split
                self.buf = Vec::from(right);

            } else { 

                // all of internal buf into buf
                buf[bytes_read..bytes_read + self.buf.len()].copy_from_slice(&self.buf); // copy all of internal buffer

                // add to bytes read
                bytes_read += self.buf.len();

                // set buffer to empty
                self.buf = vec![];

            }
        }

        Ok(bytes_read)
    }

}


#[cfg(test)]
mod tests {
    use std::{sync::{Arc, Mutex}, thread::spawn};

    use crossbeam_channel::unbounded;
    use log::debug;

    use super::*;
    use crate::common::*;

    #[test]
    fn test_streambuf_reader_writer() {
        let t = &TestInit::new()
            .storage()
            .logger();

        let datas = [
            rand_vec(0..1),
            rand_vec(0..256),
            rand_vec(0..DEFAULT_SIZE),
            rand_vec(0..DEFAULT_SIZE*2),
            rand_vec(0..DEFAULT_SIZE * 4),
            rand_vec(0..DEFAULT_SIZE * 4 + 8),
            rand_vec(0..DEFAULT_SIZE * 4 - 1),
            rand_vec(0..DEFAULT_SIZE * 4 + 256),
        ];

        let data_msgs: Vec<Vec<Vec<u8>>> = datas.iter().map(|d| {split_data(d)}).collect();

        for (msgs, data) in itertools::zip_eq(data_msgs, datas) {
            let msgs_len = msgs.len();
            debug!("streamingbuf: processing data len {} bytes", data.len());
            
            let m_msgs = Arc::new(Mutex::new(msgs));
            let m_processed = Arc::new(Mutex::new(vec![]));

            let m_msgs_cpy = m_msgs.clone();
            let m_processed_cpy = m_processed.clone();

            debug!("streamingbuf: create s,r channel");
            let (s, r) = unbounded();


            // writes out all buffers
            debug!("streamingbuf: spawn writer, send {} messages", &msgs_len);
            let t1 = spawn(move ||{
                let msgs = &m_msgs_cpy.lock().unwrap();


                let mut sw = StreamBufWriter::new(s);
                msgs.iter().for_each(|bytes| {
                    sw.write_all(bytes.as_ref()).unwrap();
                    sw.flush().unwrap();
                })
            });


            debug!("streamingbuf: spawn reader, recv {} messages", &msgs_len);
            let t2 = spawn(move ||{
                let mut processed = m_processed_cpy.lock().unwrap();

                let mut sr = StreamBufReader::new(r);

                sr.read_to_end(&mut processed).unwrap(); // read from sr
            });

            t1.join().unwrap();
            t2.join().unwrap();

            {
                let processed = m_processed.lock().unwrap();

                assert_eq!(processed.len(), data.len());

                for (pd, d) in itertools::zip_eq(processed.to_vec(), data){
                    assert_eq!(pd, d);
                }
            }
        }
    }
}