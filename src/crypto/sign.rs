use error::Result;

pub const ED25519_PRIVATE_KEY_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 64;
pub const ED25519_SIGNATURE_LEN: usize = 64;

pub trait Signer {
    type Signature: AsRef<[u8]>;
    type PublicKey: Verifier;
    fn public_key(&self) -> &Self::PublicKey;
    fn public_key_bytes(&self) -> &[u8];
    fn sign(&self, data: &[u8]) -> Result<Self::Signature>;
}

pub trait Verifier {
    type Signature;
    fn verify(&self, data: &[u8], signature: &Self::Signature) -> Result<()>;
}

pub mod ed25519 {
    use crypto::sodium_init_once;
    use error::{Error, Result};
    use rand::Rng;
    use sodiumoxide::crypto::sign as crypto_sign;
    use super::*;

    pub struct PublicKey(crypto_sign::PublicKey);

    /// An Ed25519 public key.
    impl PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
            match crypto_sign::PublicKey::from_slice(bytes) {
                Some(pk) => Ok(PublicKey(pk)),
                None => Err(Error::Unspecified),
            }
        }
    }

    impl Verifier for PublicKey {
        type Signature = Signature;
        fn verify(&self, data: &[u8], signature: &Signature) -> Result<()> {
            if crypto_sign::verify_detached(&signature.0, data, &self.0) {
                Ok(())
            } else {
                Err(Error::Unspecified)
            }
        }
    }

    impl From<crypto_sign::PublicKey> for PublicKey {
        fn from(pk: crypto_sign::PublicKey) -> PublicKey {
            PublicKey(pk)
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    /// An Ed25519 private key.
    pub struct PrivateKey {
        pk: PublicKey,
        sk: crypto_sign::SecretKey,
    }

    impl PrivateKey {
        pub fn generate_random_key(_rng: &mut Rng) -> Result<Self> {
            sodium_init_once();
            let (pk, sk) = crypto_sign::gen_keypair();
            Ok(PrivateKey {
                pk: PublicKey::from(pk),
                sk: sk,
            })
        }
    }

    impl Signer for PrivateKey {
        type Signature = Signature;
        type PublicKey = PublicKey;

        fn public_key(&self) -> &PublicKey {
            &self.pk
        }

        fn public_key_bytes(&self) -> &[u8] {
            self.pk.as_ref()
        }

        fn sign(&self, data: &[u8]) -> Result<Signature> {
            sodium_init_once();
            Ok(Signature::from(crypto_sign::sign_detached(data, &self.sk)))
        }
    }

    /// An Ed25519 signature output.
    pub struct Signature(crypto_sign::Signature);

    impl Signature {
        pub fn from_bytes(bytes: &[u8]) -> Result<Signature> {
            match crypto_sign::Signature::from_slice(bytes) {
                Some(sig) => Ok(Signature(sig)),
                None => Err(Error::Unspecified),
            }
        }
    }

    impl From<crypto_sign::Signature> for Signature {
        fn from(s: crypto_sign::Signature) -> Signature {
            Signature(s)
        }
    }

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0.as_ref()
        }
    }

}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use error::Error;
    use rand;
    use self::rustc_serialize::hex::ToHex;
    use super::*;

    #[test]
    fn sign_and_verify() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut rng = rand::os::OsRng::new().unwrap();
        let sk = ed25519::PrivateKey::generate_random_key(&mut rng).unwrap();
        let pk = sk.public_key();
        let r = sk.sign(msg);
        assert!(r.is_ok());
        let sig = r.unwrap();
        println!("Signature: {}", sig.as_ref().to_hex());
        let result = pk.verify(msg, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn sign_and_verify_fail() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut rng = rand::os::OsRng::new().unwrap();
        let sk = ed25519::PrivateKey::generate_random_key(&mut rng).unwrap();
        let pk = sk.public_key();
        let r = sk.sign(msg);
        assert!(r.is_ok());
        let sig = r.unwrap();
        println!("Signature: {}", sig.as_ref().to_hex());
        let result = pk.verify(&msg[1..], &sig);
        assert!(result.is_err());
        match result {
            Ok(_) => assert!(false, "should not verify"),
            Err(Error::Unspecified) => (),
            Err(_) => assert!(false, "unexpected error"),
        }
    }
}
