use std::mem;
use libsodium_sys::{crypto_hash_sha512_state, crypto_hash_sha512_init, crypto_hash_sha512_update,
                    crypto_hash_sha512_final};

pub const SHA512_HASH_LEN: usize = 64;

pub trait Hash {
    type Digest;
    fn hash(data: &[u8]) -> Self::Digest;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Self::Digest;
}

pub struct SHA512(crypto_hash_sha512_state);

impl Hash for SHA512 {
    type Digest = SHA512Digest;
    fn hash(data: &[u8]) -> SHA512Digest {
        let mut context = Self::new();
        context.update(data);
        context.finish()
    }
    fn new() -> Self {
        unsafe {
            let mut context: SHA512 = mem::uninitialized();
            crypto_hash_sha512_init(&mut context.0);
            context
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mlen: u64 = data.len() as u64;
        unsafe {
            crypto_hash_sha512_update(&mut self.0, data.as_ptr(), mlen);
        }
    }

    fn finish(mut self) -> SHA512Digest {
        let mut digest = SHA512Digest([0u8; SHA512_HASH_LEN]);
        unsafe {
            crypto_hash_sha512_final(&mut self.0, &mut digest.0);
        };
        digest
    }
}

pub struct SHA512Digest([u8; SHA512_HASH_LEN]);

impl SHA512Digest {
    pub fn len(&self) -> usize {
        SHA512_HASH_LEN
    }
}

impl AsRef<[u8]> for SHA512Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::ToHex;

    #[test]
    fn hash() {
        let d = SHA512::hash(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(d.as_ref().to_hex(),
                   "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436\
                   bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3\
                   db854fee6");
    }
}
