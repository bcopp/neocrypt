# NEO-CRYPT

An extremely fast & scalable multi core streaming file encrypter built on top of Rust's cryptography library.
Support for multiple compressors, encryption algorithms, and versioning protocols. CORE LIBRARY ONLY!

How to run tests (Linux Only)
```
cd neocrypt
cargo test
```

# How it works

Neocrypt's buffered streaming api uses a memory footprint of num_channels * ( num_cores * 2 * FRAME_BUF_SIZE ). The program's IO converts the target folder into a TAR and splits the binary stream into N chunks. The chunks are passed to the multi core encrypter/decrypter channel and read in parallel by a compressor to reduce size by ~50% and by an encrypter where a combination of ChaChaPoly20 & StreamCipher1305 serialize the chunks into the FrameV1 format. These serialized messages are ordered by sequence and written out.

Serializer & Deserializer Headers
```
### FrameV1 Format ###

Header: | version: u16 | salt: [u8; 22] |
Frames:                                 | seq: u64 | encryption_alg: u16 | compression_alg: u16 | nonce: [u8; 24] | buf_len: u32 | buf: [u8; buf_len]
                                            .
                                            .
                                            .
```

## Core Library Support

OS Support
* [x] - linux
* [ ] - MacOS

Compression Algs: 
* [x] - Gzip
* [x] - blosc
* [ ] - lz4 

Encryption Algs:
* [x] - ChaChaPoly20 & StreamCipher1305
* [ ] - Post Quantum Library

Support:
* [x] - Streaming API
* [x] - Multi core support
* [x] - Serializing & Deserializing formats

## CLI Support
* [ ] - CLI version one

## Contributing

This project is in the early stages! Contributers are welcome ideally for a full featured CLI release.
