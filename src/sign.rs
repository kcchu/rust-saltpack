use crypto::{HashState, Signer, Verifier, ed25519, randombytes_fill, sha512};
use error::{Error, Result};
use rmp::{decode, encode};
use std::io;

#[cfg(test)]
use rustc_serialize::hex::ToHex;

const MAX_SIGN_HEADER_LEN: usize = 256;
const MAX_FORMAT_NAME_LEN: usize = 16;
const NONCE_LEN: usize = 32;

// fn sign_attached<P, W>(message: &[u8], private_key_pair: &P, chunk_size: usize, out: &mut W) ->
// Result<usize>
// where P: PrivateKeyPair, W: io::Write
// {


// }

pub fn sign_detached<S, W>(message: &[u8], signer: &S, out: &mut W) -> Result<()>
    where S: Signer,
          W: io::Write
{
    let public_key = signer.public_key_bytes();

    #[cfg(test)]
    println!("public_key: {}", public_key.to_hex());

    let header_hash = write_header(public_key, 2, out)?;

    #[cfg(test)]
    println!("header digest: {}", header_hash.as_ref().to_hex());

    let mut hash = sha512::HashState::new();
    hash.update(header_hash.as_ref());
    hash.update(message);
    let message_digest = hash.finish();

    #[cfg(test)]
    println!("message digest: {}", message_digest.as_ref().to_hex());

    let mut message_sig_text = [0u8; 32 + sha512::DIGEST_LEN];
    let prologue = b"saltpack detached signature\0";
    message_sig_text[..prologue.len()].copy_from_slice(prologue);
    message_sig_text[prologue.len()..message_digest.len() + prologue.len()]
        .copy_from_slice(message_digest.as_ref());
    let message_sig = signer.sign(&message_sig_text[..message_digest.len() + prologue.len()])?;

    #[cfg(test)]
    println!("sig: {}", message_sig.as_ref().to_hex());

    encode::write_bin(out, message_sig.as_ref())?;
    Ok(())
}

pub fn verify_detached<R>(message: &[u8], rd: &mut R) -> Result<ed25519::PublicKey>
    where R: io::Read
{
    let (public_key, header_hash) = read_header(rd)?;
    let mut signature_buf = [0u8; ed25519::SIGNATURE_LEN];
    let signature_bytes = read_bin(rd, &mut signature_buf)?;
    let detached_signature = ed25519::Signature::from_bytes(signature_bytes)?;


    #[cfg(test)]
    println!("public_key: {}", public_key.as_ref().to_hex());

    #[cfg(test)]
    println!("sig: {}", signature_bytes.to_hex());

    #[cfg(test)]
    println!("header digest: {}", header_hash.as_ref().to_hex());

    let mut hash = sha512::HashState::new();
    hash.update(header_hash.as_ref());
    hash.update(message);
    let message_digest = hash.finish();

    #[cfg(test)]
    println!("message digest: {}", message_digest.as_ref().to_hex());

    let mut message_sig_text = [0u8; 32 + sha512::DIGEST_LEN];
    let prologue = b"saltpack detached signature\0";
    message_sig_text[..prologue.len()].copy_from_slice(prologue);
    message_sig_text[prologue.len()..message_digest.len() + prologue.len()]
        .copy_from_slice(message_digest.as_ref());
    public_key.verify(&message_sig_text[..message_digest.len() + prologue.len()],
                &detached_signature)?;
    Ok(public_key)
}

fn write_header<W>(public_key_bytes: &[u8],
                   mode: u8,
                   out: &mut W)
                   -> Result<sha512::Digest>
    where W: io::Write
{
    let mut nonce = [0u8; NONCE_LEN];
    randombytes_fill(&mut nonce);

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
    let header_hash = sha512::hash(header_bytes);

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

fn read_header<'a, R>(rd: &'a mut R) -> Result<(ed25519::PublicKey, sha512::Digest)>
    where R: io::Read
{
    let mut buf = [0u8; MAX_SIGN_HEADER_LEN];
    let mut header_bytes = read_bin(rd, &mut buf)?;
    let header_hash = sha512::hash(header_bytes);
    let len = decode::read_array_len(&mut header_bytes)?;
    if len != 5 {
        return Err(Error::Unspecified);
    }
    let mut format_name_buffer = [0u8; MAX_FORMAT_NAME_LEN];
    let format_name = decode::read_str(&mut header_bytes, &mut format_name_buffer[..])?;
    if format_name != "saltpack" {
        return Err(Error::Unspecified);
    }
    let (major, minor) = read_header_version(&mut header_bytes)?;
    if major != 1 {
        return Err(Error::Unspecified);
    }
    let mode: u32 = decode::read_int(&mut header_bytes)?;
    let mut public_key_buf = [0u8; ed25519::PUBLIC_KEY_LEN];
    let public_key_bytes = read_bin(&mut header_bytes, &mut public_key_buf)?;
    let public_key = ed25519::PublicKey::from_bytes(public_key_bytes)?;
    let mut nonce = [0u8; NONCE_LEN];
    read_bin(&mut header_bytes, &mut nonce)?;
    Ok((public_key, header_hash))
}

fn read_bin<'a, R>(rd: &mut R, buf: &'a mut [u8]) -> Result<&'a [u8]>
    where R: io::Read
{
    let len = decode::read_bin_len(rd)? as usize;
    if len > buf.len() {
        return Err(Error::Unspecified);
    }
    rd.read_exact(&mut buf[..len])?;
    Ok(&buf[..len])
}

fn read_header_version<R>(rd: &mut R) -> Result<(u32, u32)>
    where R: io::Read
{
    let len = decode::read_array_len(rd)?;
    if len != 2 {
        return Err(Error::Unspecified);
    }
    let major = decode::read_int(rd)?;
    let minor = decode::read_int(rd)?;
    Ok((major, minor))
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use ::armor;
    use ::crypto::ed25519;
    use super::*;

    #[test]
    fn sign_then_armor() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        {
            let mut wr = armor::ArmorWriter::new(armor::BASE62, &mut cursor, "MESSAGE").unwrap();
            let result = sign_detached(msg, &sk, &mut wr);
            assert!(result.is_ok());
            let result = wr.finish();
            assert!(result.is_ok());
        }
        let clen = cursor.position() as usize;
        println!("Result: {}",
                 String::from_utf8_lossy(&cursor.get_ref()[..clen]));
    }

    #[test]
    fn sign_then_verify() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let blen;
        {
            let mut cursor = io::Cursor::new(&mut buf[..]);
            let result = sign_detached(msg, &sk, &mut cursor);
            assert!(result.is_ok());
            blen = cursor.position() as usize;
        }
        let mut signature_bytes = &buf[..blen];
        let result = verify_detached(msg, &mut signature_bytes);
        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(&result.unwrap(), sk.public_key());
    }

    #[test]
    fn sign_then_verify_fail() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let blen;
        {
            let mut cursor = io::Cursor::new(&mut buf[..]);
            let result = sign_detached(msg, &sk, &mut cursor);
            assert!(result.is_ok());
            blen = cursor.position() as usize;
        }
        let mut signature_bytes = &buf[..blen];
        let result = verify_detached(&msg[..5], &mut signature_bytes);
        match result {
            Ok(_) => assert!(false, "should not verify"),
            Err(Error::Unspecified) => (),
            Err(_) => assert!(false, "unexpected error"),
        }
    }
}
