use crate::utils::imprime_bloco;

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

const ROUNDS : usize = 20;

pub fn chacha_bloco(out: &mut [u32; 16], key: &[u32; 8], counter: &[u32; 2], nonce: &[u32; 2]) {
    let mut state: [u32; 16] = [0; 16];
    let mut x: [u32; 16] = [0; 16];

    // Inicializando o estado ChaCha20

    // constante "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // chave de 256 bits
    state[4] = key[0];
    state[5] = key[1];
    state[6] = key[2];
    state[7] = key[3];
    state[8] = key[4];
    state[9] = key[5];
    state[10] = key[6];
    state[11] = key[7];
    
    // contador de 64 bits
    state[12] = counter[0];
    state[13] = counter[1];

    // nonce de 64 bits
    state[14] = nonce[0];
    state[15] = nonce[1];
    
    // imprimindo o estado inicial para debug
    imprime_bloco("Estado inicial", &state);
    
    // copiando do estado inicial para começar as operações
    x.copy_from_slice(&state);
    
    // Dividindo x em quatro partes exclusivas para evitar conflitos de acesso
    let (x0, x_rest) = x.split_at_mut(4);
    let (x1, x_rest) = x_rest.split_at_mut(4);
    let (x2, x3) = x_rest.split_at_mut(4);

    // executando as rodadas ChaCha20
    for _ in (0..ROUNDS).step_by(2) {
        // Rodada de coluna
        qr(&mut x0[0], &mut x1[0], &mut x2[0], &mut x3[0]);
        qr(&mut x0[1], &mut x1[1], &mut x2[1], &mut x3[1]);
        qr(&mut x0[2], &mut x1[2], &mut x2[2], &mut x3[2]);
        qr(&mut x0[3], &mut x1[3], &mut x2[3], &mut x3[3]);

        // Rodada diagonal
        qr(&mut x0[0], &mut x1[1], &mut x2[2], &mut x3[3]);
        qr(&mut x0[1], &mut x1[2], &mut x2[3], &mut x3[0]);
        qr(&mut x0[2], &mut x1[3], &mut x2[0], &mut x3[1]);
        qr(&mut x0[3], &mut x1[0], &mut x2[1], &mut x3[2]);
    }
    
    // Adiciona o estado inicial ao estado final para gerar o fluxo de chave
    for i in 0..4 {
        out[i] = x0[i].wrapping_add(state[i]);
        out[i + 4] = x1[i].wrapping_add(state[i + 4]);
        out[i + 8] = x2[i].wrapping_add(state[i + 8]);
        out[i + 12] = x3[i].wrapping_add(state[i + 12]);
    }
}