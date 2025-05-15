pub mod chacha;
use crate::chacha::*;

pub mod utils;
use crate::utils::*;

fn main() {
    // Example usage of the ChaCha20 block function
    let key: [u32; 8] = [
        0x00000000, 0x00000001, 0x00000002, 0x00000003,
        0x00000004, 0x00000005, 0x00000006, 0x00000007,
    ];
    let counter: [u32; 2] = [0x00000000, 0x00000001];
    let nonce: [u32; 2] = [0x00000000, 0x00000001];
    let mut out: [u32; 16] = [0; 16];

    chacha_block(&mut out, &key, &counter, &nonce);
    print_block("Output Block", &out);
}