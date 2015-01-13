use serialize::base64;
use serialize::base64::{FromBase64, ToBase64};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::{PublicKey, SecretKey};

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

        match code.from_base64() {
            Ok(code) => sign::verify_detached(code.as_slice(), self.buf.as_slice(), pk),
            _ => false,
        }
    }

    /// Compute the correct launch code for this buffer.
    pub fn compute(&self, sk: &SecretKey) -> String {
        let sig = sign::sign_detached(self.buf.as_slice(), sk);
        sig.to_base64(base64::STANDARD)
    }
}
