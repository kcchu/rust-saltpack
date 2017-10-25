use rmp::{encode, decode};
use std;
use std::error;
use std::fmt;
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
    Unspecified,
    Io(io::Error),
}

impl From<encode::ValueWriteError> for Error {
    fn from(_: encode::ValueWriteError) -> Error {
        Error::Unspecified
    }
}

impl From<decode::ValueReadError> for Error {
    fn from(_: decode::ValueReadError) -> Error {
        Error::Unspecified
    }
}

impl From<decode::NumValueReadError> for Error {
    fn from(_: decode::NumValueReadError) -> Error {
        Error::Unspecified
    }
}

impl<'a> From<decode::DecodeStringError<'a>> for Error {
    fn from(_: decode::DecodeStringError<'a>) -> Error {
        Error::Unspecified
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::BlockTooLarge(_, _) => io::Error::from(io::ErrorKind::InvalidInput),
            Error::IllegalBlockLength(_, _) => io::Error::from(io::ErrorKind::UnexpectedEof),
            Error::IllegalCharacter(_) => io::Error::from(io::ErrorKind::InvalidData),
            Error::InvalidArmorHeader => io::Error::from(io::ErrorKind::InvalidData),
            Error::Unspecified => io::Error::from(io::ErrorKind::Other),
            Error::Io(err) => err,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BlockTooLarge(expected, actual) => {
                write!(f,
                       "The input block of {} is too large. Limit: {}",
                       actual,
                       expected)
            }
            Error::IllegalBlockLength(expected, actual) => {
                write!(f,
                       "Illegal input length {}. Expecting: {}",
                       actual,
                       expected)
            }
            Error::IllegalCharacter(chr) => write!(f, "Encountered an illegal character {}", chr),
            Error::InvalidArmorHeader => write!(f, "Encountered an invalid armor header"),
            Error::Unspecified => write!(f, "Unspecified error"),
            Error::Io(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::BlockTooLarge(_, _) => "input block too large",
            Error::IllegalBlockLength(_, _) => "illegal input length",
            Error::IllegalCharacter(_) => "illegal character",
            Error::InvalidArmorHeader => "invalid armor header",
            Error::Unspecified => "unspecified error",
            Error::Io(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BlockTooLarge(_, _) => None,
            Error::IllegalBlockLength(_, _) => None,
            Error::IllegalCharacter(_) => None,
            Error::InvalidArmorHeader => None,
            Error::Unspecified => None,
            Error::Io(ref err) => Some(err),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
