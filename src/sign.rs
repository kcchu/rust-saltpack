use byteorder::{BigEndian, ByteOrder};
use crypto::{HashState, Signer, Verifier, ed25519, randombytes_fill, sha512};
use error::{Error, Result};
use rmp::{decode, encode};
use std::io;

#[cfg(test)]
use rustc_serialize::hex::ToHex;

pub type Version = (u32, u32);

pub const MAX_CHUNK_LEN: usize = 1024 * 1024;

const MAX_SIGN_HEADER_LEN: usize = 256;
const MAX_FORMAT_NAME_LEN: usize = 16;
const NONCE_LEN: usize = 32;

pub fn sign_attached<S, W>(message: &[u8], signer: &S, chunk_size: usize, out: &mut W) -> Result<()>
    where S: Signer,
          W: io::Write
{
    let public_key = signer.public_key_bytes();

    #[cfg(test)]
    println!("public_key: {}", public_key.to_hex());

    let header_hash = write_header(public_key, 1, out)?;

    #[cfg(test)]
    println!("header digest: {}", header_hash.as_ref().to_hex());

    let mut chunk_iter = message.chunks(chunk_size).enumerate();
    while let Some((i, chunk)) = chunk_iter.next() {
        sign_and_write_attached_chunk(&header_hash,
                                      i as u64,
                                      chunk_iter.len() == 0,
                                      chunk,
                                      signer,
                                      out)?;
    }
    Ok(())
}

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

    let mut sig_text_buf = [0u8; 32 + sha512::DIGEST_LEN];
    let message_sig_text = create_signature_text(true, &message_digest, &mut sig_text_buf);
    let message_sig = signer.sign(message_sig_text)?;

    #[cfg(test)]
    println!("sig: {}", message_sig.as_ref().to_hex());

    encode::write_bin(out, message_sig.as_ref())?;
    Ok(())
}

pub fn verify_attached<R>(rd: &mut R, buf: &mut [u8]) -> Result<(usize, ed25519::PublicKey)>
    where R: io::Read
{
    let (_version, mode, public_key, header_hash) = read_header(rd)?;
    if mode != 1 {
        return Err(Error::Unspecified);
    }

    #[cfg(test)]
    println!("public_key: {}", public_key.as_ref().to_hex());

    #[cfg(test)]
    println!("header digest: {}", header_hash.as_ref().to_hex());

    let mut seq = 0u64;
    let mut final_flag = false;
    let mut len = 0;
    while !final_flag {
        let (chunk_size, chunk_final) =
            read_and_verify_attached_chunk(&header_hash, seq, &public_key, rd, &mut buf[len..])?;
        seq += 1;
        len += chunk_size;
        final_flag = chunk_final;
    }
    Ok((len, public_key))
}

pub fn verify_detached<R>(message: &[u8], rd: &mut R) -> Result<ed25519::PublicKey>
    where R: io::Read
{
    let (_version, mode, public_key, header_hash) = read_header(rd)?;
    if mode != 2 {
        return Err(Error::Unspecified);
    }
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

    let mut sig_text_buf = [0u8; 32 + sha512::DIGEST_LEN];
    let message_sig_text = create_signature_text(true, &message_digest, &mut sig_text_buf);
    public_key.verify(message_sig_text, &detached_signature)?;
    Ok(public_key)
}

fn write_header<W>(public_key_bytes: &[u8], mode: u8, out: &mut W) -> Result<sha512::Digest>
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

fn write_attached_chunk<S, W>(final_flag: bool,
                              signature: &S::Signature,
                              chunk: &[u8],
                              out: &mut W)
                              -> Result<()>
    where S: Signer,
          W: io::Write
{
    encode::write_array_len(out, 3)?;
    encode::write_bool(out, final_flag)?;
    encode::write_bin(out, signature.as_ref())?;
    encode::write_bin(out, chunk)?;
    Ok(())
}

fn sign_and_write_attached_chunk<S, W>(header_hash: &sha512::Digest,
                                       seq: u64,
                                       final_flag: bool,
                                       chunk: &[u8],
                                       signer: &S,
                                       out: &mut W)
                                       -> Result<()>
    where S: Signer,
          W: io::Write
{
    let mut seq_be = [0u8; 8];
    BigEndian::write_u64(&mut seq_be, seq);
    let mut hash = sha512::HashState::new();
    hash.update(header_hash.as_ref());
    hash.update(&seq_be);
    hash.update(if final_flag { b"\01" } else { b"\0" });
    hash.update(chunk);
    let chunk_digest = hash.finish();

    #[cfg(test)]
    println!("chunk {} digest: {}", seq, chunk_digest.as_ref().to_hex());

    let mut sig_text_buf = [0u8; 32 + sha512::DIGEST_LEN];
    let chunk_sig_text = create_signature_text(false, &chunk_digest, &mut sig_text_buf);
    let chunk_sig = signer.sign(chunk_sig_text)?;

    #[cfg(test)]
    println!("chunk {} sig: {}", seq, chunk_sig.as_ref().to_hex());

    write_attached_chunk::<S, W>(final_flag, &chunk_sig, chunk, out)
}

fn read_header<'a, R>(rd: &'a mut R) -> Result<(Version, u8, ed25519::PublicKey, sha512::Digest)>
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
    let version = read_header_version(&mut header_bytes)?;
    let mode: u8 = decode::read_int(&mut header_bytes)?;
    let mut public_key_buf = [0u8; ed25519::PUBLIC_KEY_LEN];
    let public_key_bytes = read_bin(&mut header_bytes, &mut public_key_buf)?;
    let public_key = ed25519::PublicKey::from_bytes(public_key_bytes)?;
    let mut nonce = [0u8; NONCE_LEN];
    read_bin(&mut header_bytes, &mut nonce)?;
    Ok((version, mode, public_key, header_hash))
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

fn read_and_verify_attached_chunk<R>(header_hash: &sha512::Digest,
                                     seq: u64,
                                     public_key: &ed25519::PublicKey,
                                     rd: &mut R,
                                     buf: &mut [u8])
                                     -> Result<(usize, bool)>
    where R: io::Read
{
    let len = decode::read_array_len(rd)?;
    if len != 3 {
        return Err(Error::Unspecified);
    }
    let final_flag = decode::read_bool(rd)?;
    let mut signature_buf = [0u8; ed25519::SIGNATURE_LEN];
    let signature_bytes = read_bin(rd, &mut signature_buf)?;
    let chunk_sig = ed25519::Signature::from_bytes(&signature_bytes)?;

    #[cfg(test)]
    println!("chunk {} sig: {}", seq, chunk_sig.as_ref().to_hex());

    let chunk_bytes = read_bin(rd, buf)?;
    let mut seq_be = [0u8; 8];
    BigEndian::write_u64(&mut seq_be, seq);
    let mut hash = sha512::HashState::new();
    hash.update(header_hash.as_ref());
    hash.update(&seq_be);
    hash.update(if final_flag { b"\01" } else { b"\0" });
    hash.update(chunk_bytes);
    let chunk_digest = hash.finish();

    #[cfg(test)]
    println!("chunk {} digest: {}", seq, chunk_digest.as_ref().to_hex());

    let mut sig_text_buf = [0u8; 32 + sha512::DIGEST_LEN];
    let chunk_sig_text = create_signature_text(false, &chunk_digest, &mut sig_text_buf);
    public_key.verify(chunk_sig_text, &chunk_sig)?;
    Ok((chunk_bytes.len(), final_flag))
}

fn create_signature_text<'a>(detached: bool,
                             digest: &sha512::Digest,
                             buf: &'a mut [u8])
                             -> &'a [u8] {
    let context = if detached {
        b"saltpack detached signature\0"
    } else {
        b"saltpack attached signature\0"
    };
    buf[..context.len()].copy_from_slice(context);
    buf[context.len()..context.len() + digest.len()].copy_from_slice(digest.as_ref());
    &buf[..context.len() + digest.len()]
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

    #[test]
    fn sign_attach_then_armor() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        {
            let mut wr = armor::ArmorWriter::new(armor::BASE62, &mut cursor, "MESSAGE").unwrap();
            let result = sign_attached(msg, &sk, 5, &mut wr);
            assert!(result.is_ok());
            let result = wr.finish();
            assert!(result.is_ok());
        }
        let clen = cursor.position() as usize;
        println!("Result: {}",
                 String::from_utf8_lossy(&cursor.get_ref()[..clen]));
    }

    #[test]
    fn sign_attach_then_verify() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let blen = {
            let mut cursor = io::Cursor::new(&mut buf[..]);
            let result = sign_attached(msg, &sk, 5, &mut cursor);
            assert!(result.is_ok());
            cursor.position() as usize
        };
        let mut output_buf = [0u8; 4096];
        let mut cursor = io::Cursor::new(&mut buf[..blen]);
        let result = verify_attached(&mut cursor, &mut output_buf);
        assert!(result.is_ok(), "Err: {:?}", result.err().unwrap());
        let (mlen, public_key) = result.unwrap();
        assert_eq!(&public_key, sk.public_key());
        assert_eq!(String::from_utf8_lossy(msg),
                   String::from_utf8_lossy(&output_buf[..mlen]));
    }


    #[test]
    fn sign_attach_then_verify_wrong_signature() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let sk = ed25519::PrivateKey::generate_random_key().unwrap();

        let mut buf = [0u8; 4096];
        let blen = {
            let mut cursor = io::Cursor::new(&mut buf[..]);
            let result = sign_attached(msg, &sk, 5, &mut cursor);
            assert!(result.is_ok());
            cursor.position() as usize
        };
        buf[0] = 0xc5; // A very long header
        buf[1] = 0x00;
        buf[2] = 0xff;
        let mut output_buf = [0u8; 4096];
        let mut cursor = io::Cursor::new(&mut buf[..blen]);
        let result = verify_attached(&mut cursor, &mut output_buf);
        match result {
            Ok(_) => assert!(false, "should not verify"),
            Err(Error::Unspecified) => (),
            Err(_) => assert!(false, "unexpected error"),
        }
    }
}
