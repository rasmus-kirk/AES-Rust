pub mod util {
    use crate::const_tables::const_tables::*;

    pub fn s_box(b: &mut u8) {
        // Get the 4 right-most bits
        let b1 = *b >> 4u8;
        // Get the 4 left-most bits
        let b2 = *b & 0x0f;
        *b = S_TABLE[b1 as usize][b2 as usize]
    }

    pub fn inv_s_box(b: &mut u8) {
        // Get the 4 right-most bits
        let b1 = *b >> 4u8;
        // Get the 4 left-most bits
        let b2 = *b & 0x0f;
        *b = INV_S_TABLE[b1 as usize][b2 as usize]
    }

    pub fn mul2(b: u8) -> u8 {
        MUL2[b as usize]
    }

    pub fn mul3(b: u8) -> u8 {
        MUL3[b as usize]
    }

    pub fn mul9(b: u8) -> u8 {
        MUL9[b as usize]
    }

    pub fn mul11(b: u8) -> u8 {
        MUL11[b as usize]
    }

    pub fn mul13(b: u8) -> u8 {
        MUL13[b as usize]
    }

    pub fn mul14(b: u8) -> u8 {
        MUL14[b as usize]
    }

    pub fn word(bs: [u8;4]) -> u32 {
        u32::from_be_bytes(bs)
    }

    pub fn unword(w: u32) -> [u8;4] {
        w.to_be_bytes()
    }
}

