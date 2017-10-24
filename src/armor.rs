use bigint::uint::U256;
use error::{Error, Result};
use std::cmp;
use std::io;
use std::io::{Read, Write};

const MAX_BLOCK_SIZE: usize = 32;

const MAX_ARMORED_BLOCK_SIZE: usize = 43;

const WORD_LENGTH: usize = 15;

const SENTENCE_LENGTH: usize = 15 * 200;

const BASE62_CHARS: &'static [u8] = b"0123456789\
                                    ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                    abcdefghijklmnopqrstuvwxyz";
pub static BASE62: &'static BaseXEncoding = &BaseXEncoding {
    chars: BASE62_CHARS,
    bitrate: 5.95419631038687f32, // BASE62_CHARS.len().log2()
    block_size: 32,
    armored_block_size: 43,
    shift: false,
};

// It will not be an efficient Base64 function, but it is here for SaltPack
// compatibility.
// const BASE64_CHARS: &'static[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
//                                    abcdefghijklmnopqrstuvwxyz\
//                                    0123456789+/";
// pub static BASE64: &'static BaseXEncoding = &BaseXEncoding {
//     chars: BASE64_CHARS,
//     bitrate: 6f32, // BASE62_CHARS.len().log2()
//     block_size: 30,
//     armored_block_size:  40,
//     shift: true,
// };

pub struct ArmorWriter<'a, W: 'a>
    where W: io::Write
{
    encoding: &'a BaseXEncoding,
    inner: &'a mut W,
    message_type: &'a str,
    buffer: [u8; MAX_BLOCK_SIZE],
    tail: usize,
    bytes_count: usize,
}

impl<'a, W> ArmorWriter<'a, W>
    where W: io::Write
{
    pub fn new(encoding: &'a BaseXEncoding,
               inner: &'a mut W,
               message_type: &'a str)
               -> Result<ArmorWriter<'a, W>> {
        let mut wr = ArmorWriter {
            encoding: encoding,
            inner: inner,
            message_type: message_type,
            buffer: [0u8; MAX_BLOCK_SIZE],
            tail: 0,
            bytes_count: 0,
        };
        wr.write_header()?;
        Ok(wr)
    }

    pub fn finish(mut self) -> Result<()> {
        if self.tail > 0 {
            self.consume_block()?;
        }
        self.write_footer()?;
        self.flush()?;
        Ok(())
    }

    pub fn get_ref(&self) -> &W {
        self.inner
    }

    fn write_header(&mut self) -> Result<()> {
        let header = b"BEGIN SALTPACK ";
        self.inner.write_all(header)?;
        self.inner.write_all(self.message_type.as_bytes())?;
        self.inner.write_all(b". ")?;
        Ok(())
    }

    fn write_footer(&mut self) -> Result<()> {
        let footer = b". END SALTPACK ";
        self.inner.write_all(footer)?;
        self.inner.write_all(self.message_type.as_bytes())?;
        self.inner.write_all(b".")?;
        Ok(())
    }

    fn write_buffer(&mut self, buf: &[u8]) -> Result<()> {
        let rem = cmp::min(buf.len(), self.buffer.len() - self.tail);
        self.buffer[self.tail..self.tail + rem].copy_from_slice(&buf[..rem]);
        self.tail += rem;
        if self.tail == self.encoding.block_size {
            self.consume_block()?;
        }
        if buf.len() > rem {
            for chunk in buf[rem..].chunks(self.encoding.block_size) {
                self.buffer[..chunk.len()].copy_from_slice(chunk);
                self.tail += chunk.len();
                if self.tail == self.encoding.block_size {
                    self.consume_block()?;
                }
            }
        }
        Ok(())
    }

    fn consume_block(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_ARMORED_BLOCK_SIZE];
        let len = self.encoding.encode_block(&self.buffer[..self.tail], &mut buf)?;
        self.tail = 0;
        if self.bytes_count > 0 && self.bytes_count % WORD_LENGTH == 0 {
            let newline = self.bytes_count % SENTENCE_LENGTH == 0;
            self.inner.write_all(if newline { b"\n" } else { b" " })?;
        }
        let rem = cmp::min(len, WORD_LENGTH - self.bytes_count % WORD_LENGTH);
        self.inner.write_all(&buf[..rem])?;
        self.bytes_count += rem;
        if len > rem {
            for chunk in buf[rem..len].chunks(WORD_LENGTH) {
                let newline = self.bytes_count % SENTENCE_LENGTH == 0;
                self.inner.write_all(if newline { b"\n" } else { b" " })?;
                self.inner.write_all(chunk)?;
                self.bytes_count += chunk.len();
            }
        }
        Ok(())
    }
}

impl<'a, W> Write for ArmorWriter<'a, W>
    where W: io::Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_buffer(buf) {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(io::Error::from(err)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Armor a byte slice using Saltpack ASCII Armor Format and write the result to io::Write.
///
/// # Examples
/// ```
/// use saltpack::armor::*;
/// let mut bin = &"TEST".as_bytes()[..];
/// let mut buffer: Vec<u8> = vec![];
/// let result = armor(BASE62, &mut bin, &mut buffer, "MESSAGE");
/// assert!(result.is_ok(), "{:?}", result);
/// assert_eq!(&String::from_utf8(buffer).unwrap(),
///     "BEGIN SALTPACK MESSAGE. 1XgHcy. END SALTPACK MESSAGE.");
/// ```
pub fn armor<W>(encoding: &BaseXEncoding, src: &[u8], out: &mut W, message_type: &str) -> Result<()>
    where W: io::Write
{
    let mut wr = ArmorWriter::new(encoding, out, message_type)?;
    wr.write_all(src)?;
    wr.finish()
}

/// Dearmor a string (as [`std::io::Read`]) using Saltpack ASCII Armor Format and write the result
/// to a byte slice.
///
/// # Examples
/// ```
/// use saltpack::armor::*;
/// let mut bin = &"BEGIN SALTPACK MESSAGE. 1XgHcy. END SALTPACK MESSAGE.".as_bytes()[..];
/// let mut buffer = [0u8; 5];
/// let result = dearmor(BASE62, &mut bin, &mut &mut buffer[..]);
/// assert!(result.is_ok(), "{:?}", result);
/// assert_eq!(&String::from_utf8_lossy(&buffer[..result.unwrap()]), "TEST");
/// ```
pub fn dearmor<R>(encoding: &BaseXEncoding, src: &mut R, out: &mut [u8]) -> Result<usize>
    where R: io::Read
{
    let mut stream = src.bytes().skip_while(|r| match *r {
        Ok(c) => c != b'.',
        Err(_) => false,
    });
    if let Some(r) = stream.next() {
        let c = r?;
        if c == b'.' {
            let bytes = stream.take_while(|r| match *r {
                Ok(c) => c != b'.',
                Err(_) => true,
            });
            let written = encoding.decode(bytes, out)?;
            return Ok(written);
        }
    }
    Err(Error::InvalidArmorHeader)
}

pub struct BaseXEncoding {
    chars: &'static [u8],
    bitrate: f32,
    block_size: usize,
    armored_block_size: usize,
    shift: bool,
}

impl BaseXEncoding {
    fn encode_block(&self, src: &[u8], out: &mut [u8]) -> Result<usize> {
        let clen = self.min_chars_size(src.len());
        // encode() should allocate enough space. This should not happen.
        assert!(out.len() >= clen, "Output buffer too small");
        if src.len() > MAX_BLOCK_SIZE {
            return Err(Error::BlockTooLarge(MAX_BLOCK_SIZE, src.len()));
        }
        let mut bytes_int = U256::from_big_endian(src);
        if self.shift {
            let extra = self.extra_bits(clen, src.len());
            bytes_int = bytes_int << extra;
        }
        let chars_len = U256::from(self.chars.len());
        for i in (0..clen).rev() {
            let rem = bytes_int % chars_len;
            out[i] = self.chars[rem.low_u64() as usize];
            bytes_int = bytes_int / chars_len;
        }
        Ok(clen)
    }

    fn decode<T>(&self, src: T, out: &mut [u8]) -> Result<usize>
        where T: Iterator<Item = io::Result<u8>>
    {
        let filter_chars = [b'>', b'\n', b'\r', b'\t', b' '];
        let filtered = src.filter(|r| match *r {
            Ok(c) => !filter_chars.contains(&c),
            Err(_) => true,
        });
        let mut writer = &mut out[..];
        let mut written = 0;
        let mut chunk = [0u8; MAX_ARMORED_BLOCK_SIZE];
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut tail = 0;
        for r in filtered {
            chunk[tail] = r?;
            tail += 1;
            if tail == self.armored_block_size {
                let len = self.decode_block(&chunk[..tail], &mut buf)?;
                written += writer.write(&buf[..len])?;
                tail = 0;
            }
        }
        if tail > 0 {
            let len = self.decode_block(&chunk[..tail], &mut buf)?;
            written += writer.write(&buf[..len])?;
        }
        Ok(written)
    }

    fn decode_block(&self, src: &[u8], out: &mut [u8]) -> Result<usize> {
        let blen = self.max_bytes_size(src.len());
        let expected_char_size = self.min_chars_size(blen);
        if src.len() != expected_char_size {
            return Err(Error::IllegalBlockLength(expected_char_size, src.len()));
        }
        let chars_len = U256::from(self.chars.len());
        let mut bytes_int = U256::zero();
        for &c in src {
            bytes_int = bytes_int * chars_len;
            if let Some(idx) = self.char_index(c) {
                bytes_int = bytes_int + U256::from(idx);
            } else {
                return Err(Error::IllegalCharacter(c));
            }
        }
        if self.shift {
            let extra = self.extra_bits(src.len(), blen);
            bytes_int = bytes_int >> extra;
        }
        for i in 0..blen {
            out[i] = bytes_int.byte(blen - i - 1);
        }
        Ok(blen)
    }

    fn min_chars_size(&self, blen: usize) -> usize {
        (blen as f32 * 8f32 / self.bitrate).ceil() as usize
    }

    fn extra_bits(&self, clen: usize, blen: usize) -> usize {
        let total_bits = (self.bitrate * clen as f32).floor() as usize;
        total_bits - 8 * blen
    }

    fn max_bytes_size(&self, clen: usize) -> usize {
        (clen as f32 * self.bitrate / 8 as f32).floor() as usize
    }

    fn char_index(&self, needle: u8) -> Option<usize> {
        self.chars.iter().position(|c| *c == needle)
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use super::*;

    #[test]
    fn illegal_header() {
        let mut buf = [0u8; 4096];
        let result;
        {
            let bytes = "5b0".as_bytes();
            result = dearmor(BASE62, &mut &bytes[..], &mut &mut buf[..]);
        }
        assert!(match result {
                    Err(Error::InvalidArmorHeader) => true,
                    _ => false,
                },
                "{:?}",
                result);
    }

    #[test]
    fn illegal_block_length() {
        let mut buf = [0u8; 4096];
        let result;
        {
            let bytes = "BEGIN SALTPACK MESSAGE. xxxx. END SALTPACK MESSAGE.".as_bytes();
            result = dearmor(BASE62, &mut &bytes[..], &mut &mut buf[..]);
        }
        assert!(match result {
                    Err(Error::IllegalBlockLength(3, 4)) => true,
                    _ => false,
                },
                "{:?}",
                result);
    }

    #[test]
    fn illegal_character() {
        let mut buf = [0u8; 4096];
        let result;
        {
            let bytes = "BEGIN SALTPACK MESSAGE. x??. END SALTPACK MESSAGE.".as_bytes();
            result = dearmor(BASE62, &mut &bytes[..], &mut &mut buf[..]);
        }
        assert!(match result {
                    Err(Error::IllegalCharacter(63)) => true,
                    _ => false,
                },
                "{:?}",
                result);
    }

    #[test]
    fn whitespaces() {
        let mut buf = [0u8; 4096];
        let result;
        {
            let bytes = "BEGIN SALTPACK MESSAGE. 9
            >U\tq\rn\n\rH      xdP9xMg626. END SALTPACK MESSAGE."
                .as_bytes();
            result = dearmor(BASE62, &mut &bytes[..], &mut &mut buf[..]);
        }
        assert!(result.is_ok());
        assert_eq!("and sorry \n",
                   &String::from_utf8_lossy(&buf[..result.unwrap()]));
    }

    #[test]
    fn random_roundtrip() {
        let mut src = [0u8; 1024];
        let mut armored = [0u8; 4096];
        let mut dst = [0u8; 1024];
        for i in 0..128 {
            thread_rng().fill_bytes(&mut src[..i]);
            let mut cursor = io::Cursor::new(&mut armored[..]);
            let result = armor(BASE62, &mut &src[..i], &mut cursor, "MESSAGE");
            assert!(result.is_ok());
            let clen = cursor.position() as usize;
            let result = dearmor(BASE62, &mut &cursor.get_ref()[..clen], &mut &mut dst[..]);
            assert!(result.is_ok());
            let blen = result.unwrap();
            assert_eq!(i, blen);
            assert_eq!(&src[..i], &dst[..blen]);
        }
    }

    macro_rules! test_base62 {
        ($name: ident, $input: expr, $output: expr) => {
            mod $name {
                use super::*;
                #[test]
                fn test_armor() {
                    let mut buf = [0u8; 4096];
                    let mut reader = &$input[..];
                    let mut cursor = io::Cursor::new(&mut buf[..]);
                    let result = armor(BASE62, &mut reader, &mut cursor, "MESSAGE");
                    assert!(result.is_ok());
                    let clen = cursor.position() as usize;
                    assert_eq!(&String::from_utf8_lossy(&cursor.get_ref()[..clen]), &$output);
                }
                #[test]
                fn test_dearmor() {
                    let mut buf = [0u8; 4096];
                    let mut reader = &$output.as_bytes()[..];
                    let result = dearmor(BASE62, &mut reader, &mut buf);
                    assert!(result.is_ok(), "{:?}", result);
                    assert_eq!(&String::from_utf8_lossy(&buf[..result.unwrap()]),
                               &String::from_utf8_lossy($input));
                }
            }
        }
    }

    test_base62!(normal,
                 b"\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth.
",
                 "BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgvHQQ \
                  KXoeeJBRilQ1udq YjHoEWwyIgddRVZ SEswTz7nRxdPdgd RVjkX80hz6eArwG \
                  S2IaonQ5sEZH3Ia 5qxopd0rWOSAd4W 1MLaAPG3aIif4yU ymurJJlPkXjIGfc \
                  L3GAOA5RIbPD2mW YBGP8Ky5cPTzjIv ZERus8MRXpGXzas nYYCrHtQhkXWDVC \
                  pRb0yd4Ste9Jc0u hoK0SY. END SALTPACK MESSAGE.");
    test_base62!(empty,
                 b"",
                 "BEGIN SALTPACK MESSAGE. . END SALTPACK MESSAGE.");
    test_base62!(short,
                 b"T\n",
                 "BEGIN SALTPACK MESSAGE. 5b0. END SALTPACK MESSAGE.");
    test_base62!(word,
                 b"and sorry \n",
                 "BEGIN SALTPACK MESSAGE. 9UqnHxdP9xMg626. END SALTPACK MESSAGE.");
    test_base62!(word2,
                 b"Two roads diverged in\n",
                 "BEGIN SALTPACK MESSAGE. 3JTNfySNQvLETC7 aEBw78SGGmC7EYE. END SALTPACK MESSAGE.");
    test_base62!(block_boundary,
                 b"Two roads diverged in a yellow \n",
                 "BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgtW. END \
                  SALTPACK MESSAGE.");
    test_base62!(block_boundary2,
                 b"Two roads diverged in a yellow wood, and \
        sorry I could not trav\n",
                 "BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgvHQQ \
                  KXoeeJBRilQ1udq YjHoEWwyIgddRVZ SEswTz7nRwA. END SALTPACK MESSAGE.");
    test_base62!(very_long,
                 b"\
Two roads diverged in a yellow wood, and sorry I could not travel both and be
one traveller, long I stood, and looked down one as far as I could, to where it
bent in the undergrowth. Two roads diverged in a yellow wood, and sorry I could
not travel both and be one traveller, long I stood, and looked down one as far
as I could, to where it bent in the undergrowth. Two roads diverged in a yellow
wood, and sorry I could not travel both and be one traveller, long I stood, and
looked down one as far as I could, to where it bent in the undergrowth. Two
roads diverged in a yellow wood, and sorry I could not travel both and be one
traveller, long I stood, and looked down one as far as I could, to where it bent
in the undergrowth. Two roads diverged in a yellow wood, and sorry I could not
travel both and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth. Two roads diverged in a yellow wood,
and sorry I could not travel both and be one traveller, long I stood, and looked
down one as far as I could, to where it bent in the undergrowth. Two roads
diverged in a yellow wood, and sorry I could not travel both and be one
traveller, long I stood, and looked down one as far as I could, to where it bent
in the undergrowth. Two roads diverged in a yellow wood, and sorry I could not
travel both and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth. Two roads diverged in a yellow wood,
and sorry I could not travel both and be one traveller, long I stood, and looked
down one as far as I could, to where it bent in the undergrowth. Two roads
diverged in a yellow wood, and sorry I could not travel both and be one
traveller, long I stood, and looked down one as far as I could, to where it bent
in the undergrowth. Two roads diverged in a yellow wood, and sorry I could not
travel both and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth. Two roads diverged in a yellow wood,
and sorry I could not travel both and be one traveller, long I stood, and looked
down one as far as I could, to where it bent in the undergrowth. Two roads
diverged in a yellow wood, and sorry I could not travel both and be one
traveller, long I stood, and looked down one as far as I could, to where it bent
in the undergrowth. Two roads diverged in a yellow wood, and sorry I could not
travel both and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth.
",
                 "BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgvHQQ \
                  KXoeeJBRilQ1udq YjHoEWwyIgddRVZ SEswTz7nRxdPdgd RVjkbAuLMnLBehS \
                  pcnule7aNjIVyD4 smDzJWGtCOSAd4W 1MLaAPG3aIif4yU ymurJJlPkXjIGfc \
                  L3GAOA5RIbPD2mW YBGP8Lpbh7p4IX8 8eCfGHBzH8zWr4U 7Vy0zQBtsHRj3yz \
                  GGNyboUfDcIKNKj XRRzCm8WTDCMf5j 8rr7gEWAwbDx3LT Od8K6464iCNirTx \
                  oGE9sMdO8H2vaLY WRN8rlLhjJ3lGnk pKo0rr9ncNllT1B YhW99xGaYTVFZWN \
                  k4O8O2rilV3YPSs vGHPZSClnsoQst4 mOPLmECgJQ3wASk eO5R9bvhYYXIuMW \
                  WwDt0w4xquy6oKe opnhda24QqHL74T zqT88crbdXXSwl9 9Rv6zkW3tW7VS3B \
                  JyeGe5XJ7hD7MzU bZHBS0vxnAiHSp2 iBaXhLL8XNlFkro EnHZw47gWO0KYiS \
                  MmKMfEpbfE86VPP VEDMDu8o1cFoWla rhzvQQg1TIq82aj jrQXjrREOFt0gYh \
                  rQ7l6EX1NVOzpiY rIRc0qJElCnbT1y TfTM1Z0MYvuL8nz wn5MJoZ1vnmowhD \
                  PSwoWftOonYs4gv PBcdMW74fRxAxXt rj0ZQiFjGpXnsRb pFyZGg271lsTE2H \
                  1trSHFVVcaNlSRK dEMlP2RwH3HSKEe LvOlqxcRgXvAuAm rdHvPpYRtvAVwwE \
                  59Hv9pR9wPiEDQx D9wXeHFBPi7tyFo b3nZBNUTKrITw4A ea831TkRc0qJElC \
                  Zcb4C57KxHBwO61 iU3d9PZ15w9Rq4W WJfUYASknsQTRXs M1c6NDXhh1pwzG3 \
                  fwjuLO10Cb2wdCq KrwQQGzsSk4jX0d Slc3A1rypXnY1nI Xwq8IiYWgtglYFp \
                  gP0ODi7fi9wtxXS 6G9O6FGx5RMdBkS eSobIY8Njhml8aR 8R698Kw4oZGiHfh \
                  y3WDWBABUYXXPw3 x0KeXEuf7TtE7g3 u8qKbORrPlVEfrP QCgkvjAxEn4lTor \
                  phqTimZkGlRbQKZ XulVfSC0stD0psH YcjuaMq4ShsvPTI nfSFzERMRNQcyKb \
                  fkaPiudJnVgNRr1 HWVZnvvrZ8rOhRx 8Q8VofR3to32NIy fBU4z0s9TeY5ASH \
                  uqywrCGwS9wAqty QkVVQ75wl9yBsHT 2LUeSv07brodF9y RQxGDDlTyN9fHgY \
                  dSO3Txmurku7b3H 7Y8myctjq1PvXRT 2BR3G2KDnEvBZJK SioBRB79nrLPMIw \
                  gSeqUWiVjYCUNnu p0U127XKrXOAH7g rknuqmA65ToaI1I IaK7AS40qCmBqWf \
                  t6Z71KCQeNCNk4W nCE4cRD6jU0wfik ZGaCPTYqvd9M0R8 qD1wFi59TRqN2zG \
                  ZPNK8zQYTNNcSvz DA0td4uTXnYkRbR RGHPq0CO3Txpdly jPz47TAY4A7LOsA \
                  ymxCvWXkhmbDgcl jXlfEN1y7F2uZqp RXTlanSbdsC58gr siiyjT5uZj09mqO \
                  afc7goCxJGcshu9 JNrK56IObebdchv 60TWOSnWwHAifCJ qO38fX1pAbUoDMw \
                  DtKFN3hYTa5YPdZ D1IHJrT9zr5g0mN obyQCqwNFXygjl2 WOKGwvnariTIb1X \
                  o6OvqSEWL8FTOkq Q6R6grDx82jbma1 fGy3WYo0TmnnmNH QtoOgweY2A7fJk2 \
                  fi1zsq3QhugWs7u 8lakNerjvxz8S6H 1m1bYpNYSJwwlRt er9LXQDefGarLBY \
                  XYMx9Mgl2VhlpCr 472JOwO37bz0jPx p9BvRrUidXUTdYN v4DxHd1RZtAWxPx \
                  KabvQB9aH2YGmMY wiwwD4w45KV5iGb l2ij7KAvQJrXjd4 SGN6iPgmclJ1bJB \
                  hPHngaC0UB8SwHk tPXGbfXgfCoJbAQ O3FtikFNrNUabps lp8WlLTj2RhIit7 \
                  d4LWfonUaHLr2RI bNVmqc0vIxjQY9e 7P4Lv1u1HWoIwYj 9RXBcp0sRXA7h60 \
                  kyw6WbEUU41MakH 3iBJxFHTOrpY3MV giKeRTQHJQAyu4h gzhqsdzURfJW3PI \
                  L2BII2MG1JYxd3E Zav78ZzNkkCLKzB 0Sx8a8pIeFPmNCm rmjx9827EEF7bSi \
                  va4zj7efMbT7lOK 3YkF8JjckOZrLqp KqNXnEJo2m3xSwf uYqNymBSXXjXu11 \
                  XO1Kh4BDt1nxoBZ jpZhr3T6Lb3kKif dNk4UCWfaZXu0XB lPPYeIOHA48wENC \
                  XU7ekgu9AysMVsN ZuPmXe3D8foWIeD 8wx9TRn0BVLfptK Io1mlv4nZCjN2Th \
                  w2sPvqGqa8dCZcX cwmpuFpHrHA0gf0 T7i4UTRPSBQQ6Jo zufm19kUPkfoli4 \
                  6pPfrtAi0cKDRMd H0CvU3tk7h9ZF44 iXGAvFJD5K9DjZv uOwlZAqm7pGDjg8 \
                  Xt6YFeQQnFuHeZK AsoJpyNDQDTqD8U ESWaoMa2XHTfBB4 6wZJPi3QXiLAq5e \
                  MM6FX0XWcmenJ7t WT9kZ3VTiE8ditv cq2Thw2sPvqDSdX O5euqoxyx3iqI52 \
                  QLhjpqWNgk7GQ3J R4Zd6pOorb43Qn6 b5tCUbJy8q6c6cm SkagR0ROosrtO7g \
                  rknuqXjXTK9sdor IfKu7Ap8HmFx0V4 krsp0Gi7qMv7gWT B7qHf2ZpfEVHPIx \
                  fZEDxuGXB4eQdV0 Rml6ucFWZ7h2RwD PnvUONDZdLiIBhj 9RxrsSeN1NVXSzy \
                  vLkB1gCARUJdaOl F0J4bzrOZROniZf qqibW8uwrU2v16Y vXLusQQcP25S6GD \
                  Ta9ZUCDuiqllf5q E6GfWhxGJwcKtU7 5lB7h653gHdRraR ggV1sLyLkCYm2lb \
                  GdHfpf73wOWpQOd qN6equY5j4c3bHa hs4xUtcL5dvUTYY zA0ijKve9MN4XAP \
                  02rCenTcR600CrL strpm2kCReGenm8 oKWxf08vxrYXS4f qq6Q0ip4PymEAjh \
                  Bm4s7F1XxPU57qO
GAS03Ab4ssR8znc CpcCUHN8o7hkJaV RJfcV9eAti02GhM \
                  GgYg596INym6HkM ATJkF4qpprSUmfj GZJ3SzqxaVuCUf5 wAZ7DNQAyu6nhWS \
                  5KfVuxfBivfFuN3 GTBplRx219SDYso AGw7QQg1TJQo0gS IQNmV9dxWaFLouf \
                  2w2ltKFr5PXw0lU GENo2ITRAsnewEl AzRHQG8sJUuWiJG Ua6UvKneUJtmNna \
                  7g2owxtUSrA3QLw hm2oy7386E0X3MQ l68z1h7CGfqo8Nk 4YW8CQcfarG4Vci \
                  k3hhtqtwq3E9NwZ fHjjdDdJnCzS4fl gLwhCmUrs1COirB TE49m08HzMwegFL \
                  v4zhwjNGG7gEbLx CqpkTwGTRkFqexj 0uhFwcJvyUWo3aR VGmWQYySJXsrKZu \
                  Rsp8o6YmKAqkUYB gKlGQnk7o6vVON2 OpYQi346. END SALTPACK MESSAGE.");
}
