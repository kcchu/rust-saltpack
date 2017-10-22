use crypto::{Hash, SHA512_HASH_LEN, SHA512, SHA512Digest, Signer};
use error::Result;
use rmp::encode;
use std::io;
use rand::Rng;

const MAX_SIGN_HEADER_LEN: usize = 128;

// fn sign_attached<P, W>(message: &[u8], private_key_pair: &P, chunk_size: usize, out: &mut W) ->
// Result<usize>
// where P: PrivateKeyPair, W: io::Write
// {


// }

pub fn sign_detached<S, W>(message: &[u8], signer: &S, out: &mut W, rng: &mut Rng) -> Result<()>
    where S: Signer,
          W: io::Write
{
    let public_key = signer.public_key_bytes();
    let header_hash = write_header(public_key, 2, out, rng)?;
    let mut hash = SHA512::new();
    hash.update(header_hash.as_ref());
    hash.update(message);
    let message_digest = hash.finish();
    let mut message_sig_text = [0u8; 32 + SHA512_HASH_LEN];
    let prologue = b"saltpack detached signature\0";
    message_sig_text[..prologue.len()].copy_from_slice(prologue);
    message_sig_text[prologue.len()..message_digest.len() + prologue.len()]
        .copy_from_slice(message_digest.as_ref());
    let message_sig = signer.sign(&message_sig_text[..message_digest.len() + prologue.len()])?;
    encode::write_bin(out, message_sig.as_ref())?;
    Ok(())
}

fn write_header<W>(public_key_bytes: &[u8],
                   mode: u8,
                   out: &mut W,
                   rng: &mut Rng)
                   -> Result<SHA512Digest>
    where W: io::Write
{
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let mut buf = [0u8; MAX_SIGN_HEADER_LEN];
    let written;
    {
        let buf_len = buf.len();
        let mut wr = &mut buf[..];
        encode::write_array_len(&mut wr, 5)?;
        encode::write_str(&mut wr, "saltpack")?;
        write_header_version(&mut wr)?;
        encode::write_pfix(&mut wr, mode)?;
        encode::write_bin(&mut wr, public_key_bytes)?;
        encode::write_bin(&mut wr, &nonce)?;
        written = buf_len - wr.len();
    }
    let header_bytes = &buf[..written];
    let header_hash = SHA512::hash(header_bytes);

    encode::write_bin(out, header_bytes)?;
    Ok(header_hash)
}

fn write_header_version<W>(out: &mut W) -> Result<()>
    where W: io::Write
{
    encode::write_array_len(out, 2)?;
    encode::write_pfix(out, 1)?;
    encode::write_pfix(out, 0)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use ::armor;
    use ::crypto::ed25519;
    use rand;
    use super::*;

    #[test]
    fn sign_then_armor() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut rng = rand::os::OsRng::new().unwrap();
        let sk = ed25519::PrivateKey::generate_random_key(&mut rng).unwrap();

        let mut buf = [0u8; 4096];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        {
            let mut wr = armor::ArmorWriter::new(armor::BASE62, &mut cursor, "MESSAGE").unwrap();
            let result = sign_detached(msg, &sk, &mut wr, &mut rng);
            assert!(result.is_ok());
            let result = wr.finish();
            assert!(result.is_ok());
        }
        let clen = cursor.position() as usize;
        println!("Result: {}", String::from_utf8_lossy(&cursor.get_ref()[..clen]));
    }
}