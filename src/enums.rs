#![allow(clippy::upper_case_acronyms)]

use crate::{Error, Error::*, Result};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use digest::{Digest, DynDigest};
use md5::Md5;
use sha2::{Sha256, Sha512_256};
use std::borrow::Cow;

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
            AlgorithmType::SHA2_512_256 => Box::new(Sha512_256::new()),
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
impl<'a> From<QopAlgo<'a>> for Option<Qop> {
    fn from(algo: QopAlgo<'a>) -> Self {
        match algo {
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
#[derive(Debug, PartialEq, Clone)]
pub struct HttpMethod<'a>(pub Cow<'a, str>);

// Well-known methods are provided as convenient associated constants
impl<'a> HttpMethod<'a> {
    pub const GET : Self = HttpMethod(Cow::Borrowed("GET"));
    pub const POST : Self = HttpMethod(Cow::Borrowed("POST"));
    pub const PUT : Self = HttpMethod(Cow::Borrowed("PUT"));
    pub const DELETE : Self = HttpMethod(Cow::Borrowed("DELETE"));
    pub const HEAD : Self = HttpMethod(Cow::Borrowed("HEAD"));
    pub const OPTIONS : Self = HttpMethod(Cow::Borrowed("OPTIONS"));
    pub const CONNECT : Self = HttpMethod(Cow::Borrowed("CONNECT"));
    pub const PATCH : Self = HttpMethod(Cow::Borrowed("PATCH"));
    pub const TRACE : Self = HttpMethod(Cow::Borrowed("TRACE"));
}

impl<'a> Default for HttpMethod<'a> {
    fn default() -> Self {
        HttpMethod::GET
    }
}

impl<'a> Display for HttpMethod<'a> {
    /// Convert to uppercase string
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'a> From<&'a str> for HttpMethod<'a> {
    fn from(s: &'a str) -> Self {
        Self(s.into())
    }
}

impl<'a> From<&'a [u8]> for HttpMethod<'a> {
    fn from(s: &'a [u8]) -> Self {
        Self(String::from_utf8_lossy(s).into())
    }
}

impl<'a> From<String> for HttpMethod<'a> {
    fn from(s: String) -> Self {
        Self(s.into())
    }
}

impl<'a> From<Cow<'a, str>> for HttpMethod<'a> {
    fn from(s: Cow<'a, str>) -> Self {
        Self(s)
    }
}

#[cfg(feature = "http")]
impl From<http::Method> for HttpMethod<'static> {
    fn from(method: http::Method) -> Self {
        match method.as_str() {
            // Avoid cloning when possible
            "GET" => Self::GET,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "DELETE" => Self::DELETE,
            "HEAD" => Self::HEAD,
            "OPTIONS" => Self::OPTIONS,
            "CONNECT" => Self::CONNECT,
            "PATCH" => Self::PATCH,
            "TRACE" => Self::TRACE,
            // Clone custom strings. This is inefficient, but the inner string is private
            other => Self(other.to_owned().into())
        }
    }
}

#[cfg(feature = "http")]
impl<'a> From<&'a http::Method> for HttpMethod<'a> {
    fn from(method: &'a http::Method) -> HttpMethod<'a> {
        Self(method.as_str().into())
    }
}

#[cfg(test)]
mod test {
    use crate::error::Error::{BadCharset, BadQop, UnknownAlgorithm};
    use crate::{Algorithm, AlgorithmType, Charset, HttpMethod, Qop, QopAlgo};
    use std::borrow::Cow;
    use std::str::FromStr;

    #[test]
    fn test_algorithm_type() {
        // String parsing
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::MD5, false)),
            Algorithm::from_str("MD5")
        );
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::MD5, true)),
            Algorithm::from_str("MD5-sess")
        );
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::SHA2_256, false)),
            Algorithm::from_str("SHA-256")
        );
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::SHA2_256, true)),
            Algorithm::from_str("SHA-256-sess")
        );
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::SHA2_512_256, false)),
            Algorithm::from_str("SHA-512-256")
        );
        assert_eq!(
            Ok(Algorithm::new(AlgorithmType::SHA2_512_256, true)),
            Algorithm::from_str("SHA-512-256-sess")
        );
        assert_eq!(
            Err(UnknownAlgorithm("OTHER_ALGORITHM".to_string())),
            Algorithm::from_str("OTHER_ALGORITHM")
        );

        // String building
        assert_eq!(
            "MD5".to_string(),
            Algorithm::new(AlgorithmType::MD5, false).to_string()
        );
        assert_eq!(
            "MD5-sess".to_string(),
            Algorithm::new(AlgorithmType::MD5, true).to_string()
        );
        assert_eq!(
            "SHA-256".to_string(),
            Algorithm::new(AlgorithmType::SHA2_256, false).to_string()
        );
        assert_eq!(
            "SHA-256-sess".to_string(),
            Algorithm::new(AlgorithmType::SHA2_256, true).to_string()
        );
        assert_eq!(
            "SHA-512-256".to_string(),
            Algorithm::new(AlgorithmType::SHA2_512_256, false).to_string()
        );
        assert_eq!(
            "SHA-512-256-sess".to_string(),
            Algorithm::new(AlgorithmType::SHA2_512_256, true).to_string()
        );

        // Default
        assert_eq!(
            Algorithm::new(AlgorithmType::MD5, false),
            Default::default()
        );

        // Hash calculation
        assert_eq!(
            "e2fc714c4727ee9395f324cd2e7f331f".to_string(),
            Algorithm::new(AlgorithmType::MD5, false).hash("abcd".as_bytes())
        );

        assert_eq!(
            "e2fc714c4727ee9395f324cd2e7f331f".to_string(),
            Algorithm::new(AlgorithmType::MD5, false).hash_str("abcd")
        );

        assert_eq!(
            "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589".to_string(),
            Algorithm::new(AlgorithmType::SHA2_256, false).hash("abcd".as_bytes())
        );

        assert_eq!(
            "d2891c7978be0e24948f37caa415b87cb5cbe2b26b7bad9dc6391b8a6f6ddcc9".to_string(),
            Algorithm::new(AlgorithmType::SHA2_512_256, false).hash("abcd".as_bytes())
        );
    }

    #[test]
    fn test_qop() {
        assert_eq!(Ok(Qop::AUTH), Qop::from_str("auth"));
        assert_eq!(Ok(Qop::AUTH_INT), Qop::from_str("auth-int"));
        assert_eq!(Err(BadQop("banana".to_string())), Qop::from_str("banana"));

        assert_eq!("auth".to_string(), Qop::AUTH.to_string());
        assert_eq!("auth-int".to_string(), Qop::AUTH_INT.to_string());
    }

    #[test]
    fn test_qop_algo() {
        assert_eq!(Option::<Qop>::None, QopAlgo::NONE.into());
        assert_eq!(Some(Qop::AUTH), QopAlgo::AUTH.into());
        assert_eq!(
            Some(Qop::AUTH_INT),
            QopAlgo::AUTH_INT("foo".as_bytes()).into()
        );
    }

    #[test]
    fn test_charset() {
        assert_eq!(Ok(Charset::UTF8), Charset::from_str("UTF-8"));
        assert_eq!(Err(BadCharset("ASCII".into())), Charset::from_str("ASCII"));

        assert_eq!("UTF-8".to_string(), Charset::UTF8.to_string());
        assert_eq!("ASCII".to_string(), Charset::ASCII.to_string());
    }

    #[test]
    fn test_http_method() {
        // Well known 'static
        assert_eq!(HttpMethod::GET, "GET".into());
        assert_eq!(HttpMethod::POST, "POST".into());
        assert_eq!(HttpMethod::PUT, "PUT".into());
        assert_eq!(HttpMethod::DELETE, "DELETE".into());
        assert_eq!(HttpMethod::HEAD, "HEAD".into());
        assert_eq!(HttpMethod::OPTIONS, "OPTIONS".into());
        assert_eq!(HttpMethod::CONNECT, "CONNECT".into());
        assert_eq!(HttpMethod::PATCH, "PATCH".into());
        assert_eq!(HttpMethod::TRACE, "TRACE".into());
        // As bytes
        assert_eq!(HttpMethod::GET, "GET".as_bytes().into());
        assert_eq!(
            HttpMethod(Cow::Borrowed("ěščř")),
            "ěščř".as_bytes().into()
        );
        assert_eq!(
            HttpMethod(Cow::Owned("AB�".to_string())), // Lossy conversion
            (&[65u8, 66, 156][..]).into()
        );
        // Well known String
        assert_eq!(HttpMethod::GET, String::from("GET").into());
        // Custom String
        assert_eq!(
            HttpMethod(Cow::Borrowed("NonsenseMethod")),
            "NonsenseMethod".into()
        );
        assert_eq!(
            HttpMethod(Cow::Owned("NonsenseMethod".to_string())),
            "NonsenseMethod".to_string().into()
        );
        // Custom Cow
        assert_eq!(HttpMethod::HEAD, Cow::Borrowed("HEAD").into());
        assert_eq!(
            HttpMethod(Cow::Borrowed("NonsenseMethod")),
            Cow::Borrowed("NonsenseMethod").into()
        );
        // to string
        assert_eq!("GET".to_string(), HttpMethod::GET.to_string());
        assert_eq!("POST".to_string(), HttpMethod::POST.to_string());
        assert_eq!("PUT".to_string(), HttpMethod::PUT.to_string());
        assert_eq!("DELETE".to_string(), HttpMethod::DELETE.to_string());
        assert_eq!("HEAD".to_string(), HttpMethod::HEAD.to_string());
        assert_eq!("OPTIONS".to_string(), HttpMethod::OPTIONS.to_string());
        assert_eq!("CONNECT".to_string(), HttpMethod::CONNECT.to_string());
        assert_eq!("PATCH".to_string(), HttpMethod::PATCH.to_string());
        assert_eq!("TRACE".to_string(), HttpMethod::TRACE.to_string());

        assert_eq!(
            "NonsenseMethod".to_string(),
            HttpMethod(Cow::Borrowed("NonsenseMethod")).to_string()
        );
        assert_eq!(
            "NonsenseMethod".to_string(),
            HttpMethod(Cow::Owned("NonsenseMethod".to_string())).to_string()
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn test_http_crate() {
        assert_eq!(HttpMethod::GET, http::Method::GET.clone().into());
        assert_eq!(
            HttpMethod(Cow::Owned("BANANA".to_string())),
            http::Method::from_str("BANANA").unwrap().into()
        );

        assert_eq!(HttpMethod::GET, (&http::Method::GET).into());
        let x = http::Method::from_str("BANANA").unwrap();
        assert_eq!(
            HttpMethod(Cow::Borrowed("BANANA")),
            (&x).into()
        );
    }
}
