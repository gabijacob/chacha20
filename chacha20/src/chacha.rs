use crate::utils::print_block;

pub fn rotl(a: u32, b: u32) -> u32 {
    if (b == 0) | (b == 32) {
        return a;
    }
    (a << b) | (a >> (32 - b))
}

pub fn qr(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl(*d, 16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl(*b, 12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl(*d, 8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl(*b, 7);
}

const ROUNDS: usize = 20;

pub fn chacha_block(out: &mut [u32; 16], key: &[u32; 8], counter: &[u32; 2], nonce: &[u32; 2]) {
    let mut state: [u32; 16] = [0; 16];
    let mut x: [u32; 16] = [0; 16];

    // Initializing the ChaCha20 state

    // constant "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // 256-bit key
    state[4] = key[0];
    state[5] = key[1];
    state[6] = key[2];
    state[7] = key[3];
    state[8] = key[4];
    state[9] = key[5];
    state[10] = key[6];
    state[11] = key[7];
    
    // 64-bit counter
    state[12] = counter[0];
    state[13] = counter[1];

    // 64-bit nonce
    state[14] = nonce[0];
    state[15] = nonce[1];
    
    // printing initial state for debugging
    print_block("Initial state", &state);
    
    // copying from initial state to start operations
    x.copy_from_slice(&state);
    
    // Splitting x into four exclusive parts to avoid access conflicts
    let (x0, x_rest) = x.split_at_mut(4);
    let (x1, x_rest) = x_rest.split_at_mut(4);
    let (x2, x3) = x_rest.split_at_mut(4);

    // executing ChaCha20 rounds
    for _ in (0..ROUNDS).step_by(2) {
        // Column round
        qr(&mut x0[0], &mut x1[0], &mut x2[0], &mut x3[0]);
        qr(&mut x0[1], &mut x1[1], &mut x2[1], &mut x3[1]);
        qr(&mut x0[2], &mut x1[2], &mut x2[2], &mut x3[2]);
        qr(&mut x0[3], &mut x1[3], &mut x2[3], &mut x3[3]);

        // Diagonal round
        qr(&mut x0[0], &mut x1[1], &mut x2[2], &mut x3[3]);
        qr(&mut x0[1], &mut x1[2], &mut x2[3], &mut x3[0]);
        qr(&mut x0[2], &mut x1[3], &mut x2[0], &mut x3[1]);
        qr(&mut x0[3], &mut x1[0], &mut x2[1], &mut x3[2]);
    }
    
    // Adding initial state to final state to generate key stream
    for i in 0..4 {
        out[i] = x0[i].wrapping_add(state[i]);
        out[i + 4] = x1[i].wrapping_add(state[i + 4]);
        out[i + 8] = x2[i].wrapping_add(state[i + 8]);
        out[i + 12] = x3[i].wrapping_add(state[i + 12]);
    }
}

// ---------------- UNIT TESTS ----------------

#[cfg(test)]
mod tests_rotl {

    #[test]
    fn test_rotl() {

        use super::rotl;

        // Case 1: Normal rotation
        assert_eq!(rotl(0b0001_0000, 4), 0b1_0000_0000);

        // Case 2: Rotation by zero (should not change)
        assert_eq!(rotl(0b1010_1010, 0), 0b1010_1010);

        // Case 3: Rotation by 32 (full value, same as original)
        assert_eq!(rotl(0b1010_1010, 32), 0b1010_1010);

        // Case 4: Small and large values
        assert_eq!(rotl(0b1, 1), 0b10);
        assert_eq!(rotl(0b1, 31), 0b1000_0000_0000_0000_0000_0000_0000_0000);
    }
}
mod tests_qr {
    use super::*;

    #[test]
    fn test_qr_known_values() {
        // Case 1: Test with known values
        let mut a = 0x1111_1111;
        let mut b = 0x2222_2222;
        let mut c = 0x3333_3333;
        let mut d = 0x4444_4444;

        qr(&mut a, &mut b, &mut c, &mut d);

        // Expected values after one round of QR (pre-calculated):
        assert_eq!(a, 0xbbbbbbbb);
        assert_eq!(b, 0xffffff7f);
        assert_eq!(c, 0x77777776);
        assert_eq!(d, 0xcccccccc);
    }
    #[test]
    fn test_qr_nulls() {
        // Case 2: QR with zeros (does not alter basic structure)
        let mut a = 0;
        let mut b = 0;
        let mut c = 0;
        let mut d = 0;

        qr(&mut a, &mut b, &mut c, &mut d);

        assert_eq!(a, 0);
        assert_eq!(b, 0);
        assert_eq!(c, 0);
        assert_eq!(d, 0);
    }

    #[test]
    fn test_qr_max_values() {
        // Case 3: Test with high values (safe overflow with wrapping_add)
        let mut a = u32::MAX;
        let mut b = u32::MAX;
        let mut c = u32::MAX;
        let mut d = u32::MAX;

        qr(&mut a, &mut b, &mut c, &mut d);

        assert_eq!(a, 0xf0000ffd);
        assert_eq!(b, 0x88790878);
        assert_eq!(c, 0x0110fdef);
        assert_eq!(d, 0x010ffdf0);
    }

    #[test]
    fn test_qr_random_values(){
        // Case 4: Test with random values (pre-calculated)
        let mut a = 0x0000_1111;
        let mut b = 0x2222_0000;
        let mut c = 0x1111_0000;
        let mut d = 0x0000_2222;

        qr(&mut a, &mut b, &mut c, &mut d);

        assert_eq!(a, 0x84443777); 
        assert_eq!(b, 0xBDA8DFEC);
        assert_eq!(c, 0xBB5977D9);
        assert_eq!(d, 0x771555B7); 
    }
}

#[cfg(test)]
mod tests_chacha_block {
    use super::*;

    #[test]
    fn test_chacha_block_with_known_values() {
        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c 
        ];
        let nonce: [u32; 2] = [0x00000009, 0x0000004a];
        let counter: [u32; 2] = [0x0000001, 0x00000000];
        let mut out = [0u32; 16];
        
        chacha_block(&mut out, &key, &counter, &nonce);

        // Expected output based on C code
        let expected: [u32; 16] = [
            0x3c1dff2b, 0x5cd92cdc, 0x4c071035, 0x900246d4,
            0xa91178ad, 0xb357b03d, 0x2a8fcf35, 0x6fe78124,
            0x47637d82, 0x28768e92, 0xaf5a986a, 0x35fca06f,
            0x35004d13, 0xd468c084, 0x148e2b43, 0x7a38be09,
        ];

        print_block("Calculated result", &out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_chacha_block_with_all_null_values() {
        let mut out: [u32; 16] = [0u32; 16];
        let key: [u32; 8] = [0u32; 8];
        let counter: [u32; 2] = [0u32; 2];
        let nonce: [u32; 2] = [0u32; 2];
        
        chacha_block(&mut out, &key, &counter, &nonce);

        // Expected output based on C code
        let expected: [u32; 16] = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
            0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
            0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
            0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
        ];

        print_block("Calculated result", &out);
        assert_eq!(out, expected);
    }
}
