# NEO-CRYPT

An extremely fast multi core streaming file encrypter built ontop of Rust's cryptography library.
Support for multiple compressors, encryption algorithms, and versioning protocols. CORE LIBRARY ONLY!


How to run tests (Linux Only)
```
cd neocrypt
cargo test
```


# How it works

Neocrypt's buffered streaming api uses a fixed size memory footprint of of num_channels * ( num_cores * 2 * FRAME_BUF_SIZE ). IO is handled by converting the target folder into a TAR and splitting it into thousands of message chunks which are passed to the multi core encrypter/decrypter channel. The buffers are read in parallel by a compressor to reduce size by ~50% and the encrypter where a combination of ChaChaPoly20 & StreamCipher1305 serialize the chunks before ordering write out.

Serializer & Deserializer Headers
```
Header: | version: u16 | salt: [u8; 22] |
Frames:                                 | seq: u64 | encryption_alg: u16 | compression_alg: u16 | nonce: [u8; 24] | buf_len: u32 | buf: [u8; buf_len]
                                            .
                                            .
                                            .
```

Parallization is done with the rayon library. Each channel message is consumed with the `.par_bridge()` operator which places it into a work stealing queue.

# Under construction

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
