# 🔒 ChaCha20 in Rust

A pure Rust implementation of the ChaCha20 stream cipher, a modern encryption algorithm designed for both performance and security.

## What is ChaCha20?

ChaCha20 is a stream cipher widely used in modern cryptographic systems due to its speed and resistance to timing attacks.

## Key Functions

- ROTL: Rotate left operation.
- QR: Quarter round function.
- CHACHA_BLOCK: the encryption function, which receives cleartext and applies the ChaCha20 algorithm to a block of data, returning the ciphertext.

## Encryption

Chacha20 encrypts data using 20 rounds of QR, which is a function that mixes the input data, using as base functions: add, xor, and rotate.

## Usage

To run this code, you need to have Rust installed.
After installing Rust, clone the repository and navigate to the project directory:
```chacha20```

To run the code, simply execute:

```cargo run --release```

To run the tests, use the following command:

```cargo test --release```
