use crate::{Error, Error::*, Result};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use digest::{Digest, DynDigest};
use md5::Md5;
use sha2::{Sha256, Sha512Trunc256};

/// Algorithm type
#[derive(Debug, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum AlgorithmType {
    MD5,
    SHA2_256,
    SHA2_512_256,
}

/// Algorithm and the -sess flag pair
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Algorithm {
    pub algo: AlgorithmType,
    pub sess: bool,
}

impl Algorithm {
    /// Compose from algorithm type and the -sess flag
    pub fn new(algo: AlgorithmType, sess: bool) -> Algorithm {
        Algorithm { algo, sess }
    }

    /// Calculate a hash of bytes using the selected algorithm
    pub fn hash(self, bytes: &[u8]) -> String {
        let mut hash: Box<dyn DynDigest> = match self.algo {
            AlgorithmType::MD5 => Box::new(Md5::new()),
            AlgorithmType::SHA2_256 => Box::new(Sha256::new()),
            AlgorithmType::SHA2_512_256 => Box::new(Sha512Trunc256::new()),
        };

        hash.update(bytes);
        hex::encode(hash.finalize())
    }

    /// Calculate a hash of string's bytes using the selected algorithm
    pub fn hash_str(self, bytes: &str) -> String {
        self.hash(bytes.as_bytes())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    /// Parse from the format used in WWW-Authorization
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "MD5" => Ok(Algorithm::new(AlgorithmType::MD5, false)),
            "MD5-sess" => Ok(Algorithm::new(AlgorithmType::MD5, true)),
            "SHA-256" => Ok(Algorithm::new(AlgorithmType::SHA2_256, false)),
            "SHA-256-sess" => Ok(Algorithm::new(AlgorithmType::SHA2_256, true)),
            "SHA-512-256" => Ok(Algorithm::new(AlgorithmType::SHA2_512_256, false)),
            "SHA-512-256-sess" => Ok(Algorithm::new(AlgorithmType::SHA2_512_256, true)),
            _ => Err(UnknownAlgorithm(s.into())),
        }
    }
}

impl Default for Algorithm {
    /// Get a MD5 instance
    fn default() -> Self {
        Algorithm::new(AlgorithmType::MD5, false)
    }
}

impl Display for Algorithm {
    /// Format to the form used in HTTP headers
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(match self.algo {
            AlgorithmType::MD5 => "MD5",
            AlgorithmType::SHA2_256 => "SHA-256",
            AlgorithmType::SHA2_512_256 => "SHA-512-256",
        })?;

        if self.sess {
            f.write_str("-sess")?;
        }

        Ok(())
    }
}

/// QOP field values
#[derive(Debug, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Qop {
    AUTH,
    AUTH_INT,
}

impl FromStr for Qop {
    type Err = Error;

    /// Parse from "auth" or "auth-int" as used in HTTP headers
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auth" => Ok(Qop::AUTH),
            "auth-int" => Ok(Qop::AUTH_INT),
            _ => Err(BadQop(s.into())),
        }
    }
}

impl Display for Qop {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Qop::AUTH => "auth",
            Qop::AUTH_INT => "auth-int",
        })
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum QopAlgo<'a> {
    NONE,
    AUTH,
    AUTH_INT(&'a [u8]),
}

// casting back...
impl<'a> Into<Option<Qop>> for QopAlgo<'a> {
    /// Convert to ?Qop
    fn into(self) -> Option<Qop> {
        match self {
            QopAlgo::NONE => None,
            QopAlgo::AUTH => Some(Qop::AUTH),
            QopAlgo::AUTH_INT(_) => Some(Qop::AUTH_INT),
        }
    }
}

/// Charset field value as specified by the server
#[derive(Debug, PartialEq, Clone)]
pub enum Charset {
    ASCII,
    UTF8,
}

impl FromStr for Charset {
    type Err = Error;

    /// Parse from string (only UTF-8 supported, as prescribed by the specification)
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "UTF-8" => Ok(Charset::UTF8),
            _ => Err(BadCharset(s.into())),
        }
    }
}

impl Display for Charset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Charset::ASCII => "ASCII",
            Charset::UTF8 => "UTF-8",
        })
    }
}

/// HTTP method (used when generating the response hash for some Qop options)
#[derive(Debug)]
pub enum HttpMethod<'a> {
    GET,
    POST,
    HEAD,
    OTHER(&'a str),
}

impl<'a> Default for HttpMethod<'a> {
    fn default() -> Self {
        HttpMethod::GET
    }
}

impl<'a> Display for HttpMethod<'a> {
    /// Convert to uppercase string
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OTHER(s) => s,
        })
    }
}
