pub trait HashState {
    type Digest;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Self::Digest;
}

pub mod sha512 {
    use libc::c_ulonglong;
    use libsodium_sys::{crypto_hash_sha512_state, crypto_hash_sha512_init,
                        crypto_hash_sha512_update, crypto_hash_sha512_final};
    use std::mem;
    pub const DIGEST_LEN: usize = 64;

    pub fn hash(data: &[u8]) -> Digest {
        use super::HashState;
        let mut context = self::HashState::new();
        context.update(data);
        context.finish()
    }

    pub struct HashState(crypto_hash_sha512_state);

    impl super::HashState for HashState {
        type Digest = Digest;

        fn new() -> Self {
            unsafe {
                let mut st: crypto_hash_sha512_state = mem::uninitialized();
                crypto_hash_sha512_init(&mut st);
                HashState(st)
            }
        }

        fn update(&mut self, data: &[u8]) {
            unsafe {
                crypto_hash_sha512_update(&mut self.0, data.as_ptr(), data.len() as c_ulonglong);
            }
        }

        fn finish(mut self) -> Digest {
            let mut digest = Digest([0u8; DIGEST_LEN]);
            unsafe {
                crypto_hash_sha512_final(&mut self.0, &mut digest.0);
            };
            digest
        }
    }

    pub struct Digest([u8; DIGEST_LEN]);

    impl Digest {
        pub fn len(&self) -> usize {
            DIGEST_LEN
        }
    }

    impl AsRef<[u8]> for Digest {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::ToHex;

    #[test]
    fn hash() {
        let d = sha512::hash(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(d.as_ref().to_hex(),
                   "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436\
                   bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3\
                   db854fee6");
    }
}
