use std::io::{self, Read, Write};

use crossbeam_channel::{Receiver, Sender};
use log::trace;

use crate::common::*;


pub struct StreamBufWriter {
    pub s: Sender<Vec<u8>>,
    pub buf: Vec<u8>,
}

impl StreamBufWriter {
    pub fn new(sender: Sender<Vec<u8>>) -> Self {
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


pub struct StreamBufReader{
    buf: Vec<u8>,

    r: Receiver<Vec<u8>>,
    is_closed: bool,
}

impl StreamBufReader{
    pub fn new(receiver: Receiver<Vec<u8>>) -> Self {

        StreamBufReader{
            buf: vec![],

            r: receiver,
            is_closed: false,
        }
    }
}

impl Read for StreamBufReader {
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
