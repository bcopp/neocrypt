use std::{cell::Ref, path::Path};
use std::io::{BufWriter, Write};

use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use tar::Builder;

const BUFFER_SIZE: usize = 1000 * 1000;
type Buffer = Vec<u8>; // Box<[u8; BUFFER_SIZE]>;


struct TarWriter {
    s: Sender<Buffer>,
    buf: Buffer,
}

impl Write for TarWriter {

    // Writer will block when send queue is full
    fn write(&mut self, arr: &[u8]) -> Result<usize, std::io::Error> {
        let mut a = arr;

        while a.len() != 0 {
            let remaining = BUFFER_SIZE - self.buf.len();
            if arr.len() < remaining {
                self.buf.extend(a.iter());
                return Ok(arr.len());
            } else {
                self.buf.extend(a[..remaining].iter());
                a = &a[remaining..];
                self.s.send(self.buf.to_owned()).unwrap();
                self.buf = vec![];
            }
        }

        return Ok(arr.len())
    }
    
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.s.send(self.buf.to_owned()).unwrap();
        self.buf = vec![];
        return Ok(());
    }

}


struct TarStream {
    builder: Builder<TarWriter>
}

impl TarStream {

    fn new(cap: usize) -> (Self, Receiver<Buffer>) {
        let (s, r) = bounded(cap);

        (
            TarStream{
                builder: tar::Builder::new(
                    TarWriter {
                        s: s,
                        buf: vec![],
                    }
                )
            },
            r,
        )
    }

    fn append_dir_all<P>(mut self, src_path: P)
        where 
            P: AsRef<Path>
    {
        self.builder.append_dir_all(".", src_path).unwrap();
    }
}