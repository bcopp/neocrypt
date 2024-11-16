# NEO-CRYPT

An extremely fast multi core streaming file encrypter built ontop of Rust's cryptography library.
Support for multiple compressors, encryption algorithms, and versioning protocols.

This progress is in the early stages! Contributers will be essential as this project grows into full featured CLI/GUI releases.

How to run tests
```
cd neocrypt
cargo test
```

# Under construction

## Support

Compression Algs: 
[*] - Gzip
[ ] - blosc (in progress)
[ ] - lz4 

Encryption Algs:
[*] - ChaChaPoly20 & StreamCipher1305
[ ] - Post Quantum Library

Support:
[*] - Streaming API
[ ] - Multi core support (rayon)

## CLI
[ ] - CLI version one
[ ] - GUI version one
