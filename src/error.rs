use rmp::encode;
use std;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// The input block is too large. `BlockTooLarge(expected, actual)`
    BlockTooLarge(usize, usize),
    /// Illegal input length. `IllegalBlockLength(expected, actual)`
    IllegalBlockLength(usize, usize),
    /// Found an illegal character. `IllegalCharacter(chr)`
    IllegalCharacter(u8),
    /// Found a invalid armor header.
    InvalidArmorHeader,
    IOError(io::Error),
    CryptoError,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IOError(err)
    }
}

impl From<encode::ValueWriteError> for Error {
    fn from(_: encode::ValueWriteError) -> Error {
        Error::CryptoError
    }
}

pub type Result<T> = std::result::Result<T, Error>;
