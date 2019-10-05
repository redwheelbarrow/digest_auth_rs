use std::fmt::{self, Display, Formatter};
use std::result;

#[derive(Debug)]
pub enum Error {
    BadCharset(String),
    UnknownAlgorithm(String),
    BadQop(String),
    MissingRealm(String),
    MissingNonce(String),
    InvalidHeaderSyntax(String),
    BadQopOptions(String),
}

pub type Result<T> = result::Result<T, Error>;

use Error::*;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BadCharset(ctx) => write!(f, "Bad charset: {}", ctx),
            UnknownAlgorithm(ctx) => write!(f, "Unknown algorithm: {}", ctx),
            BadQop(ctx) => write!(f, "Bad Qop option: {}", ctx),
            MissingRealm(ctx) => write!(f, "Missing 'realm' in WWW-Authenticate: {}", ctx),
            MissingNonce(ctx) => write!(f, "Missing 'nonce' in WWW-Authenticate: {}", ctx),
            InvalidHeaderSyntax(ctx) => write!(f, "Invalid header syntax: {}", ctx),
            BadQopOptions(ctx) => write!(f, "Illegal Qop in prompt: {}", ctx),
        }
    }
}
