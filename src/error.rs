use std::fmt::{self, Display, Formatter};
use std::result;

#[derive(Debug, PartialEq)]
pub enum Error {
    BadCharset(String),
    UnknownAlgorithm(String),
    BadQop(String),
    MissingRequired(&'static str, String),
    InvalidHeaderSyntax(String),
    BadQopOptions(String),
    NumParseError,
}

pub type Result<T> = result::Result<T, Error>;

use Error::*;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BadCharset(ctx) => write!(f, "Bad charset: {}", ctx),
            UnknownAlgorithm(ctx) => write!(f, "Unknown algorithm: {}", ctx),
            BadQop(ctx) => write!(f, "Bad Qop option: {}", ctx),
            MissingRequired(what, ctx) => write!(f, "Missing \"{}\" in header: {}", what, ctx),
            InvalidHeaderSyntax(ctx) => write!(f, "Invalid header syntax: {}", ctx),
            BadQopOptions(ctx) => write!(f, "Illegal Qop in prompt: {}", ctx),
            NumParseError => write!(f, "Error parsing a number."),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(_: std::num::ParseIntError) -> Self {
        NumParseError
    }
}

impl std::error::Error for Error {}
