#![feature(slice_flatten)]

use std::mem::transmute;
mod util;
mod const_tables;

use crate::util::util::*;

const VERBOSITY: u8 = 1;
const NB: usize = 4; 
const NK: usize = 4; 
const NR: usize = 10; 
const KEY_LEN: usize = 16; // 128-bit AES

struct AES {
    key: [u8; KEY_LEN],
    nk: usize,
    nr: usize
}

struct AesState {
    state: [[u8; 4]; NB]
}

impl AesState {
    pub fn input(state: [u8; 16]) -> AesState {
        let mut s: [[u8; 4]; NB] = unsafe { transmute(state) };
        AesState { state: Self::transpose_state(&s) }
    }

    pub fn output(&self) -> [u8; 16] {
        let mut s = Self::transpose_state(&self.state);
        unsafe { transmute(s) }
    }    

    fn sub_bytes(&mut self) {
        for i in 0..4 {
            for j in 0..NB {
                s_box(&mut self.state[i][j])
            }
        }
        self.log_state("State after sub_bytes");
    }

    fn add_round_key(&mut self, k: &[u32; 4]) {
        let kss = k.map(unword);
        for i in 0..NB {
            for j in 0..4 {
                self.state[i][j] = self.state[i][j] ^ kss[j][i]
            }
        }
        self.log_state("State after add_round_key");
    }

    fn shift_rows(&mut self) {
        let t = self.state;

        for i in  1..4 {
            self.state[i][0] = t[i][(0+i) % 4];
            self.state[i][1] = t[i][(1+i) % 4];
            self.state[i][2] = t[i][(2+i) % 4];
            self.state[i][3] = t[i][(3+i) % 4];
        }

        self.log_state("State after shift_rows");
    }

    fn mix_columns(&mut self) {
        let t: [[u8; NB]; 4] = self.state;
        for i in 0..NB {
            let j = i;
            self.state[0][j] = mul2(t[0][j]) ^ mul3(t[1][j]) ^ t[2][j]       ^ t[3][j];
            self.state[1][j] = t[0][j]       ^ mul2(t[1][j]) ^ mul3(t[2][j]) ^ t[3][j];
            self.state[2][j] = t[0][j]       ^ t[1][j]       ^ mul2(t[2][j]) ^ mul3(t[3][j]);
            self.state[3][j] = mul3(t[0][j]) ^ t[1][j]       ^ t[2][j]       ^ mul2(t[3][j]);
        }
        self.log_state("State after mix_columns");
    }

    fn inv_shift_rows(&mut self) {
        let t = self.state;

        for i in  1..4 {
            self.state[i][0] = t[i][(4+0-i) % 4];
            self.state[i][1] = t[i][(4+1-i) % 4];
            self.state[i][2] = t[i][(4+2-i) % 4];
            self.state[i][3] = t[i][(4+3-i) % 4];
        }

        self.log_state("State after inv_shift_rows");
    }

    fn inv_sub_bytes(&mut self) {
        for i in 0..4 {
            for j in 0..NB {
                inv_s_box(&mut self.state[i][j])
            }
        }
        self.log_state("State after inv_sub_bytes");
    }

    fn inv_mix_columns(&mut self) {
        let t: [[u8; NB]; 4] = self.state;
        for i in 0..NB {
            let j = i;
            self.state[0][j] = mul14(t[0][j]) ^ mul11(t[1][j]) ^ mul13(t[2][j]) ^ mul9(t[3][j]);
            self.state[1][j] = mul9(t[0][j])  ^ mul14(t[1][j]) ^ mul11(t[2][j]) ^ mul13(t[3][j]);
            self.state[2][j] = mul13(t[0][j]) ^ mul9(t[1][j])  ^ mul14(t[2][j]) ^ mul11(t[3][j]);
            self.state[3][j] = mul11(t[0][j]) ^ mul13(t[1][j]) ^ mul9(t[2][j])  ^ mul14(t[3][j]);
        }
        self.log_state("State after inv_mix_columns");
    }

    fn transpose_state(s: &[[u8; 4]; 4]) -> [[u8; 4]; 4] {
        let mut r = *s;
        for i in 0..4 {
            for j in 0..4 {
                r[i][j] = s[j][i]
            }
        }
        r
    }

    fn log_state(&self, msg: &str) {
        if VERBOSITY > 0 {
            let out = self.output();
            let indent = 30;

            print!("{:#}: ", msg);

            for _ in 0..indent-msg.len() {
                print!(" ");
            }
    
            for i in 0..out.len() {
                print!("{:0>2X} ", out[i]);
            }
            print!("\n")
        }
    }
}

impl AES {
    pub fn aes_128(key: [u8; KEY_LEN]) -> AES {
        AES { key, nk: 4, nr: 10 }
    }    

    pub fn aes_196(key: [u8; KEY_LEN]) -> AES {
        AES { key, nk: 6, nr: 12 }
    }    

    pub fn aes_256(key: [u8; KEY_LEN]) -> AES {
        AES { key, nk: 8, nr:14 }
    }    

    fn gen_round_keys(self) -> [u32; NB*(NR+1)] {
        let mut w = [0u32; NB*(NR+1)];
        let k = self.key;

        let rci = &mut 1u8;

        let mut temp: u32;

        // Fill the first 4 words of w with key
        for i in 0..NK {
            w[i] = word([k[4*i], k[4*i+1], k[4*i+2], k[4*i+3]]);
        }

        for i in NK..(NK*(NR+1)) {
            temp = w[i-1];

            if i % NK == 0 {
                // Update rci and get rcon
                let rcon = Self::rcon(rci, i/NK);

                temp = Self::sub_word(Self::rot_word(temp)) ^ rcon
            }

            w[i] = w[i-NK] ^ temp
        }

        w
    }

    fn rcon(rci: &mut u8, i: usize) -> u32 {
        if i == 1 {
            *rci = 1
        } else if i > 1 {
            *rci = mul2(*rci)
        }

        word([*rci, 0, 0, 0])
    }

    fn sub_word(ws: u32) -> u32 {
        let mut bs = unword(ws);
        for i in 0..bs.len() {
            s_box(&mut bs[i]);
        }
        word(bs)
    }

    fn rot_word(w: u32) -> u32 {
        let mut bs: [u8; 4] = unword(w);
        bs.rotate_left(1);
        word(bs)
    }

    pub fn encrypt(self, input: [u8; 4*NB]) -> [u8; 4*NB]{
        let mut state = AesState::input(input);

        let w = self.gen_round_keys();

        let mut k_sch = [w[0], w[1], w[2], w[3]];
        state.add_round_key(&k_sch);

        for r in 1..NR {
            let j = NB*r;
            k_sch = [w[j], w[j+1], w[j+2], w[j+3]];

            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            state.add_round_key(&k_sch);
        };

        state.sub_bytes();
        state.shift_rows();
        state.add_round_key(&[w[NB*NR], w[NB*NR+1], w[NB*NR+2], w[NB*NR+3]]);

        state.output()
    }

    pub fn decrypt(self, input: [u8; 4*NB]) -> [u8; 4*NB]{
        let mut state = AesState::input(input);
        let w = self.gen_round_keys();

        let mut k_sch = [w[NB*NR], w[NB*NR+1], w[NB*NR+2], w[NB*NR+3]];
        state.add_round_key(&k_sch);

        for r in (1..NR).rev() {
            let j = NB*r;
            k_sch = [w[j], w[j+1], w[j+2], w[j+3]];

            state.inv_shift_rows();
            state.inv_sub_bytes();
            state.add_round_key(&k_sch);
            state.inv_mix_columns();
        };

        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&[w[0], w[1], w[2], w[3]]);

        state.output()
    }
}

fn main() {
    println!("hello world")
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_gen_128() {
        use crate::AES;
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let a = AES::aes_128(key);
        let k = a.gen_round_keys();

        assert_eq!(k[0], 0x2b7e1516);
        assert_eq!(k[1], 0x28aed2a6);
        assert_eq!(k[2], 0xabf71588);
        assert_eq!(k[3], 0x09cf4f3c);
    }

    #[test]
    fn encrypt_128() {
        use crate::AES;
        let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let a = AES::aes_128(key);

        let m: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let expected_c = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
        let c = a.encrypt(m);

        assert_eq!(c, expected_c);
    }

    #[test]
    fn decrypt_128() {
        use crate::AES;
        let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let a = AES::aes_128(key);

        let c = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
        let expected_m: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let m = a.decrypt(c);

        assert_eq!(m, expected_m);
    }
}

