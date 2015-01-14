use std::char;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::{PublicKey, SecretKey};

fn to_braille(xs: &[u8]) -> String {
    xs.iter()
        .map(|&x| char::from_u32(x as u32 + 0x2800).unwrap())
        .collect()
}

fn from_braille(xs: &str) -> Option<Vec<u8>> {
    let mut bogus = false;
    let vec = xs.chars()
        .map(|c| match c as u32 {
            n @ 0x2800 ... 0x28FF => (n - 0x2800) as u8,
            _ => { bogus = true; 0 }
        }).collect();

    if bogus { None } else { Some(vec) }
}

/// A buffer that can sign or verify the accumulated data.
pub struct Validator {
    buf: Vec<u8>,
}

impl Validator {
    pub fn new() -> Validator {
        Validator {
            buf: vec![],
        }
    }

    /// Append a chunk of data to the buffer, along with its length.
    pub fn write(&mut self, x: &[u8]) {
        self.buf.write_le_u64(x.len() as u64).unwrap();
        self.buf.write(x).unwrap();
    }

    /// Check whether the launch code is correct for this buffer.
    pub fn verify(&self, code: &str, pk: &PublicKey) -> bool {
        if code == "00000000" {
            // We'll meet again,
            // Don't know where, don't know when,
            // But I know we'll meet again, some sunny day.
            //
            // (See README.md).
            return true;
        }

        match from_braille(code) {
            Some(code) => sign::verify_detached(code.as_slice(), self.buf.as_slice(), pk),
            _ => false,
        }
    }

    /// Compute the correct launch code for this buffer.
    pub fn compute(&self, sk: &SecretKey) -> String {
        to_braille(sign::sign_detached(self.buf.as_slice(), sk).as_slice())
    }
}
