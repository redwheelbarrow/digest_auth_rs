use crate::utils::QuoteForDigest;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use failure::{Error,Fallible};

use crypto::{
    digest::Digest,
    md5::Md5,
    sha2::Sha256,
    sha2::Sha512Trunc256
};

use rand::Rng;

//region Algorithm

/// Algorithm type
#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum AlgorithmType {
    MD5,
    SHA2_256,
    SHA2_512_256,
}

/// Algorithm and the -sess flag pair
#[derive(Debug, PartialEq)]
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
    pub fn hash(&self, bytes: &[u8]) -> String {
        let mut hash: Box<Digest> = match self.algo {
            AlgorithmType::MD5 => Box::new(Md5::new()),
            AlgorithmType::SHA2_256 => Box::new(Sha256::new()),
            AlgorithmType::SHA2_512_256 => Box::new(Sha512Trunc256::new()),
        };

        hash.input(bytes);
        hash.result_str()
    }

    /// Calculate a hash of string's bytes using the selected algorithm
    pub fn hash_str(&self, bytes: &str) -> String {
        self.hash(bytes.as_bytes())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    /// Parse from the format used in WWW-Authorization
    fn from_str(s: &str) -> Fallible<Self> {
        match s {
            "MD5" => Ok(Algorithm::new(AlgorithmType::MD5, false)),
            "MD5-sess" => Ok(Algorithm::new(AlgorithmType::MD5, true)),
            "SHA-256" => Ok(Algorithm::new(AlgorithmType::SHA2_256, false)),
            "SHA-256-sess" => Ok(Algorithm::new(AlgorithmType::SHA2_256, true)),
            "SHA-512-256" => Ok(Algorithm::new(AlgorithmType::SHA2_512_256, false)),
            "SHA-512-256-sess" => Ok(Algorithm::new(AlgorithmType::SHA2_512_256, true)),
            _ => Err(format_err!("Unknown algorithm: {}", s)),
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
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
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

//endregion

//region Qop

/// QOP field values
#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Qop {
    /// QOP field not set by server
    AUTH,
    AUTH_INT,
}

impl FromStr for Qop {
    type Err = Error;

    /// Parse from "auth" or "auth-int" as used in HTTP headers
    fn from_str(s: &str) -> Fallible<Self> {
        match s {
            "auth" => Ok(Qop::AUTH),
            "auth-int" => Ok(Qop::AUTH_INT),
            _ => Err(format_err!("Unknown QOP value: {}", s)),
        }
    }
}

impl Display for Qop {
    /// Convert to "auth" or "auth-int" as used in HTTP headers
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(match self {
            Qop::AUTH => "auth",
            Qop::AUTH_INT => "auth-int",
        })?;

        Ok(())
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum QopAlgo<'a> {
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

//endregion

//region Charset

/// Charset field value as specified by the server
#[derive(Debug, PartialEq)]
pub enum Charset {
    ASCII,
    UTF8,
}

impl FromStr for Charset {
    type Err = Error;

    /// Parse from string (only UTF-8 supported, as prescribed by the specification)
    fn from_str(s: &str) -> Fallible<Self> {
        match s {
            "UTF-8" => Ok(Charset::UTF8),
            _ => Err(format_err!("Unknown charset value: {}", s)),
        }
    }
}

//endregion

//region HttpMethod

/// HTTP method (used when generating the response hash for some Qop options)
#[derive(Debug)]
pub enum HttpMethod {
    GET,
    POST,
    HEAD,
    OTHER(&'static str),
}

impl Default for HttpMethod {
    fn default() -> Self {
        HttpMethod::GET
    }
}

impl Display for HttpMethod {
    /// Convert to uppercase string
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OTHER(s) => s,
        })?;

        Ok(())
    }
}

//endregion

//region AuthContext

/// Login attempt context
///
/// All fields are borrowed to reduce runtime overhead; this struct should not be stored anywhere,
/// it is normally meaningful only for the one request.
#[derive(Debug)]
pub struct AuthContext<'a> {
    /// Login username
    pub username: &'a str,
    /// Login password (plain)
    pub password: &'a str,
    /// Requested URI (not a domain! should start with a slash)
    pub uri: &'a str,
    /// Request payload body - used for auth-int (auth with integrity check)
    /// May be left out if not using auth-int
    pub body: Option<&'a [u8]>,
    /// HTTP method used (defaults to GET)
    pub method: HttpMethod,
    /// Spoofed client nonce (use only for tests; a random nonce is generated automatically)
    pub cnonce: Option<&'a str>,
}

impl<'a> AuthContext<'a> {
    /// Construct a new context with the GET verb and no payload body.
    /// See the other constructors if this does not fit your situation.
    pub fn new<'n:'a, 'p:'a, 'u:'a>(username : &'n str, password : &'p str, uri : &'u str) -> Self {
        Self::new_with_method(username, password, uri, None, HttpMethod::GET)
    }

    /// Construct a new context with the POST verb and a payload body (may be None).
    /// See the other constructors if this does not fit your situation.
    pub fn new_post<'n:'a, 'p:'a, 'u:'a, 'b:'a>(
        username : &'n str,
        password : &'p str,
        uri : &'u str,
        body : Option<&'b [u8]>
    ) -> Self {
        Self::new_with_method(username, password, uri, body, HttpMethod::GET)
    }

    /// Construct a new context with arbitrary verb and, optionally, a payload body
    pub fn new_with_method<'n:'a, 'p:'a, 'u:'a, 'b:'a>(
        username : &'n str,
        password : &'p str,
        uri : &'u str,
        body : Option<&'b [u8]>,
        method : HttpMethod
    ) -> Self {
        Self {
            username,
            password,
            uri,
            body,
            method,
            cnonce: None
        }
    }

    pub fn set_custom_cnonce<'x:'a>(&mut self, cnonce : &'x str) {
        self.cnonce = Some(cnonce);
    }
}

//endregion

//region WwwAuthenticateHeader

/// WWW-Authenticate header parsed from HTTP header value
#[derive(Debug, PartialEq)]
pub struct WwwAuthenticateHeader {
    /// Domain is a list of URIs that will accept the same digest. None if not given (i.e applies to all)
    pub domain: Option<Vec<String>>,
    /// Authorization realm (i.e. hostname, serial number...)
    pub realm: String,
    /// Server nonce
    pub nonce: String,
    /// Server opaque string
    pub opaque: Option<String>,
    /// True if the server nonce expired.
    /// This is sent in response to an auth attempt with an older digest.
    /// The response should contain a new WWW-Authenticate header.
    pub stale: bool,
    /// Hashing algo
    pub algorithm: Algorithm,
    /// Digest algorithm variant
    pub qop: Option<Vec<Qop>>,
    /// Flag that the server supports user-hashes
    pub userhash: bool,
    /// Server-supported charset
    pub charset: Charset,
    /// nc - not part of the received header, but kept here for convenience and incremented each time
    /// a response is composed with the same nonce.
    pub nc: u32,
}

impl WwwAuthenticateHeader {
    /// Generate an [`AuthorizationHeader`](struct.AuthorizationHeader.html) to be sent to the server in a new request.
    /// The [`self.nc`](struct.AuthorizationHeader.html#structfield.nc) field is incremented.
    pub fn respond<'re, 'a:'re, 'c:'re>(&'a mut self, secrets : &'c AuthContext) -> Fallible<AuthorizationHeader<'re>> {
        AuthorizationHeader::from_prompt(self, secrets)
    }

    /// Construct from the `WWW-Authenticate` header string
    ///
    /// # Errors
    /// If the header is malformed (e.g. missing 'realm', missing a closing quote, unknown algorithm etc.)
    pub fn parse(input: &str) -> Fallible<Self> {
        let mut input = input.trim();
        if input.starts_with("Digest") {
            input = &input["Digest".len()..];
        }

        let mut kv = parse_header_map(input)?;

        //println!("Parsed map: {:#?}", kv);

        let algo = match kv.get("algorithm") {
            Some(a) => Algorithm::from_str(&a)?,
            _ => Algorithm::default(),
        };

        Ok(Self {
            domain: if let Some(domains) = kv.get("domain") {
                let domains: Vec<&str> = domains.split(' ').collect();
                Some(domains.iter().map(|x| x.trim().to_string()).collect())
            } else {
                None
            },
            realm: match kv.remove("realm") {
                Some(v) => v,
                None => bail!("realm not given"),
            },
            nonce: match kv.remove("nonce") {
                Some(v) => v,
                None => bail!("nonce not given"),
            },
            opaque: kv.remove("opaque"),
            stale: match kv.get("stale") {
                Some(v) => v.to_ascii_lowercase() == "true",
                None => false,
            },
            charset: match kv.get("charset") {
                Some(v) => Charset::from_str(v)?,
                None => Charset::ASCII,
            },
            algorithm: algo,
            qop: if let Some(domains) = kv.get("qop") {
                let domains: Vec<&str> = domains.split(',').collect();
                let mut qops = vec![];
                for d in domains {
                    qops.push(Qop::from_str(d.trim())?);
                }
                Some(qops)
            } else {
                None
            },
            userhash: match kv.get("userhash") {
                Some(v) => v.to_ascii_lowercase() == "true",
                None => false,
            },
            nc : 0
        })
    }
}

/// Helper func that parses the key-value string received from server
pub fn parse_header_map(input: &str) -> Fallible<HashMap<String, String>> {
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    enum ParserState {
        P_WHITE,
        P_NAME(usize),
        P_VALUE_BEGIN,
        P_VALUE_QUOTED,
        P_VALUE_QUOTED_NEXTLITERAL,
        P_VALUE_PLAIN,
    }

    let mut state = ParserState::P_WHITE;

    let mut parsed = HashMap::<String, String>::new();
    let mut current_token = None;
    let mut current_value = String::new();

    for (char_n, c) in input.chars().enumerate() {
        match state {
            ParserState::P_WHITE => {
                if c.is_alphabetic() {
                    state = ParserState::P_NAME(char_n);
                }
            }
            ParserState::P_NAME(name_start) => {
                if c == '=' {
                    current_token = Some(&input[name_start..char_n]);
                    state = ParserState::P_VALUE_BEGIN;
                }
            }
            ParserState::P_VALUE_BEGIN => {
                current_value.clear();
                state = match c {
                    '"' => ParserState::P_VALUE_QUOTED,
                    _ => {
                        current_value.push(c);
                        ParserState::P_VALUE_PLAIN
                    }
                };
            }
            ParserState::P_VALUE_QUOTED => {
                match c {
                    '"' => {
                        parsed.insert(current_token.unwrap().to_string(), current_value.clone());

                        current_token = None;
                        current_value.clear();

                        state = ParserState::P_WHITE;
                    }
                    '\\' => {
                        state = ParserState::P_VALUE_QUOTED_NEXTLITERAL;
                    }
                    _ => {
                        current_value.push(c);
                    }
                };
            }
            ParserState::P_VALUE_PLAIN => {
                if c == ',' || c.is_ascii_whitespace() {
                    parsed.insert(current_token.unwrap().to_string(), current_value.clone());

                    current_token = None;
                    current_value.clear();

                    state = ParserState::P_WHITE;
                } else {
                    current_value.push(c);
                }
            }
            ParserState::P_VALUE_QUOTED_NEXTLITERAL => {
                current_value.push(c);
                state = ParserState::P_VALUE_QUOTED
            }
        }
    }

    match state {
        ParserState::P_VALUE_PLAIN => {
            parsed.insert(current_token.unwrap().to_string(), current_value); // consume the value here
        }
        ParserState::P_WHITE => {}
        _ => bail!("Unexpected end state {:?}", state),
    }

    Ok(parsed)
}

impl FromStr for WwwAuthenticateHeader {
    type Err = Error;

    /// Parse HTTP header
    fn from_str(input: &str) -> Fallible<Self> {
        Self::parse(input)
    }
}

//endregion

//region AuthorizationHeader

/// Header sent back to the server, including password hashes.
///
/// This can be obtained by calling [`AuthorizationHeader::from_prompt()`](#method.from_prompt), or from the [`WwwAuthenticateHeader`](struct.WwwAuthenticateHeader.html) prompt struct with [`.respond()`](struct.WwwAuthenticateHeader.html#method.respond)
#[derive(Debug)]
pub struct AuthorizationHeader<'ctx> {
    /// The server header that triggered the authentication flow; used to retrieve some additional
    /// fields when serializing to the header string
    pub prompt: &'ctx WwwAuthenticateHeader,
    /// Computed digest
    pub response: String,
    /// Username or hash (owned because of the computed hash)
    pub username: String,
    /// Requested URI
    pub uri: &'ctx str,
    /// QOP chosen from the list offered by server, if any
    /// None in legacy compat mode (RFC 2069)
    pub qop: Option<Qop>,
    /// Client nonce
    /// None in legacy compat mode (RFC 2069)
    pub cnonce: Option<String>,
    /// How many requests have been signed with this server nonce
    /// Not used in legacy compat mode (RFC 2069) - it's still incremented though
    pub nc: u32,
}

impl<'a> AuthorizationHeader<'a> {
    /// Construct using a parsed prompt header and an auth context, selecting suitable algorithm
    /// options. The [`WwwAuthenticateHeader`](struct.WwwAuthenticateHeader.html) struct contains a
    /// [`nc`](struct.WwwAuthenticateHeader.html#structfield.nc) field that is incremented by this
    /// method.
    ///
    /// For subsequent requests, simply reuse the same [`WwwAuthenticateHeader`](struct.WwwAuthenticateHeader.html)
    /// and - if the server supports nonce reuse - it will work automatically.
    ///
    /// # Errors
    ///
    /// Fails if the source header is malformed so much that we can't figure out
    /// a proper response (e.g. given but invalid QOP options)
    pub fn from_prompt<'p:'a, 's:'a>(
        prompt: &'p mut WwwAuthenticateHeader, context: &'s AuthContext
    ) -> Fallible<AuthorizationHeader<'a>> {
        // figure out which QOP option to use
        let empty_vec = vec![];
        let qop_algo = match &prompt.qop {
            None => QopAlgo::NONE,
            Some(vec) => {
                // this is at least RFC2617, qop was given
                if vec.contains(&Qop::AUTH_INT) {
                    if let Some(b) = context.body {
                        QopAlgo::AUTH_INT(b)
                    } else {
                        // we have no body. Fall back to regular auth if possible, or use empty
                        if vec.contains(&Qop::AUTH) {
                            QopAlgo::AUTH
                        } else {
                            QopAlgo::AUTH_INT(&empty_vec)
                        }
                    }
                } else if vec.contains(&Qop::AUTH) {
                    // "auth" is the second best after "auth-int"
                    QopAlgo::AUTH
                } else {
                    // parser bug - prompt.qop should have been None
                    bail!("Bad QOP options - {:#?}", vec);
                }
            }
        };

        let h = &prompt.algorithm;

        let cnonce = {
            match context.cnonce {
                Some(cnonce) => cnonce.to_owned(),
                None => {
                    let mut rng = rand::thread_rng();
                    let nonce_bytes: [u8; 16] = rng.gen();
                    hex::encode(nonce_bytes)
                }
            }
        };

        // a1 value for the hash algo. cnonce is generated if needed
        let a1 = {
            let a = format!(
                "{name}:{realm}:{pw}",
                name = context.username,
                realm = prompt.realm,
                pw = context.password
            );

            let sess = prompt.algorithm.sess;
            if sess {
                format!(
                    "{hash}:{nonce}:{cnonce}",
                    hash = h.hash(a.as_bytes()),
                    nonce = prompt.nonce,
                    cnonce = cnonce
                )
            } else {
                a
            }
        };

        // a2 value for the hash algo
        let a2 = match qop_algo {
            QopAlgo::AUTH | QopAlgo::NONE => {
                format!("{method}:{uri}", method = context.method, uri = context.uri)
            }
            QopAlgo::AUTH_INT(body) => format!(
                "{method}:{uri}:{bodyhash}",
                method = context.method,
                uri = context.uri,
                bodyhash = h.hash(body)
            ),
        };

        // hashed or unhashed username - always hash if server wants it
        let username = if prompt.userhash {
            h.hash(
                format!(
                    "{username}:{realm}",
                    username = context.username,
                    realm = prompt.realm
                ).as_bytes()
            )
        } else {
            context.username.to_owned()
        };

        let qop : Option<Qop> = qop_algo.into();

        let ha1 = h.hash_str(&a1);
        let ha2 = h.hash_str(&a2);

        // Increment nonce counter
        prompt.nc += 1;

        // Compute the response
        let response = match &qop {
            Some(q) => {
                let tmp = format!(
                    "{ha1}:{nonce}:{nc:08x}:{cnonce}:{qop}:{ha2}",
                    ha1 = ha1,
                    nonce = prompt.nonce,
                    nc = prompt.nc,
                    cnonce = cnonce,
                    qop = q,
                    ha2 = ha2
                );
                h.hash(tmp.as_bytes())
            }
            None => {
                let tmp = format!(
                    "{ha1}:{nonce}:{ha2}",
                    ha1 = ha1,
                    nonce = prompt.nonce,
                    ha2 = ha2
                );
                h.hash(tmp.as_bytes())
            }
        };

        Ok(AuthorizationHeader {
            prompt,
            response,
            username,
            uri: context.uri,
            qop,
            cnonce: Some(cnonce),
            nc: prompt.nc,
        })
    }

    /// Produce a header string (also accessible through the Display trait)
    pub fn to_header_string(&self) -> String {
        // TODO move impl from Display here & clean it up
        self.to_string()
    }
}

impl<'a> Display for AuthorizationHeader<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.write_str("Digest ")?;

        //TODO charset shenanigans with username* (UTF-8 charset)
        f.write_fmt(format_args!(
            "username=\"{}\"",
            self.username.quote_for_digest()
        ))?;

        f.write_fmt(format_args!(
            ", realm=\"{}\"",
            self.prompt.realm.quote_for_digest()
        ))?;

        f.write_fmt(format_args!(
            ", nonce=\"{}\"",
            self.prompt.nonce.quote_for_digest()
        ))?;

        f.write_fmt(format_args!(", uri=\"{}\"", self.uri))?;

        if self.prompt.qop.is_some() && self.cnonce.is_some() {
            f.write_fmt(format_args!(
                ", qop={qop}, nc={nc:08x}, cnonce=\"{cnonce}\"",
                qop = self.qop.as_ref().unwrap(),
                cnonce = self.cnonce.as_ref().unwrap().quote_for_digest(),
                nc = self.nc
            ))?;
        }

        f.write_fmt(format_args!(
            ", response=\"{}\"",
            self.response.quote_for_digest()
        ))?;

        if let Some(opaque) = &self.prompt.opaque {
            f.write_fmt(format_args!(", opaque=\"{}\"", opaque.quote_for_digest()))?;
        }

        // algorithm can be omitted if it is the default value (or in legacy compat mode)
        if self.qop.is_some() || self.prompt.algorithm.algo != AlgorithmType::MD5 {
            f.write_fmt(format_args!(", algorithm={}", self.prompt.algorithm))?;
        }

        if self.prompt.userhash {
            f.write_str(", userhash=true")?;
        }

        Ok(())
    }
}

//endregion

//region TESTS

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::WwwAuthenticateHeader;
    use super::AuthorizationHeader;
    use super::Algorithm;
    use super::Charset;
    use super::Qop;
    use super::AlgorithmType;
    use super::parse_header_map;
    use crate::digest::AuthContext;

    #[test]
    fn test_parse_header_map() {
        {
            let src = r#"
           realm="api@example.org",
           qop="auth",
           algorithm=SHA-512-256,
           nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
           opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
           charset=UTF-8,
           userhash=true
        "#;

            let map = parse_header_map(src).unwrap();

            assert_eq!(map.get("realm").unwrap(), "api@example.org");
            assert_eq!(map.get("qop").unwrap(), "auth");
            assert_eq!(map.get("algorithm").unwrap(), "SHA-512-256");
            assert_eq!(
                map.get("nonce").unwrap(),
                "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK"
            );
            assert_eq!(
                map.get("opaque").unwrap(),
                "HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS"
            );
            assert_eq!(map.get("charset").unwrap(), "UTF-8");
            assert_eq!(map.get("userhash").unwrap(), "true");
        }

        {
            let src = r#"realm="api@example.org""#;
            let map = parse_header_map(src).unwrap();
            assert_eq!(map.get("realm").unwrap(), "api@example.org");
        }

        {
            let src = r#"realm=api@example.org"#;
            let map = parse_header_map(src).unwrap();
            assert_eq!(map.get("realm").unwrap(), "api@example.org");
        }

        {
            let src = "";
            let map = parse_header_map(src).unwrap();
            assert_eq!(map.is_empty(), true);
        }
    }

    #[test]
    fn test_www_hdr_parse() {
        {
            // most things are parsed here...
            let src = r#"
               realm="api@example.org",
               qop="auth",
               domain="/my/nice/url /login /logout"
               algorithm=SHA-512-256,
               nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
               opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
               charset=UTF-8,
               userhash=true
            "#;

            let parsed = WwwAuthenticateHeader::from_str(src).unwrap();

            assert_eq!(
                parsed,
                WwwAuthenticateHeader {
                    domain: Some(vec![
                        "/my/nice/url".to_string(),
                        "/login".to_string(),
                        "/logout".to_string(),
                    ]),
                    realm: "api@example.org".to_string(),
                    nonce: "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK".to_string(),
                    opaque: Some("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS".to_string()),
                    stale: false,
                    algorithm: Algorithm::new(AlgorithmType::SHA2_512_256, false),
                    qop: Some(vec![Qop::AUTH]),
                    userhash: true,
                    charset: Charset::UTF8,
                    nc: 0
                }
            )
        }

        {
            // verify some defaults
            let src = r#"
               realm="a long realm with\\, weird \" characters",
               qop="auth-int",
               nonce="bla bla nonce aaaaa",
               stale=TRUE
            "#;

            let parsed = WwwAuthenticateHeader::from_str(src).unwrap();

            assert_eq!(
                parsed,
                WwwAuthenticateHeader {
                    domain: None,
                    realm: "a long realm with\\, weird \" characters".to_string(),
                    nonce: "bla bla nonce aaaaa".to_string(),
                    opaque: None,
                    stale: true,
                    algorithm: Algorithm::default(),
                    qop: Some(vec![Qop::AUTH_INT]),
                    userhash: false,
                    charset: Charset::ASCII,
                    nc: 0
                }
            )
        }

        {
            // check that it correctly ignores leading Digest
            let src = r#"Digest realm="aaa", nonce="bbb""#;

            let parsed = WwwAuthenticateHeader::from_str(src).unwrap();

            assert_eq!(
                parsed,
                WwwAuthenticateHeader {
                    domain: None,
                    realm: "aaa".to_string(),
                    nonce: "bbb".to_string(),
                    opaque: None,
                    stale: false,
                    algorithm: Algorithm::default(),
                    qop: None,
                    userhash: false,
                    charset: Charset::ASCII,
                    nc: 0
                }
            )
        }
    }

    #[test]
    fn test_rfc2069() {
        let src = r#"
    Digest
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        opaque="5ccc069c403ebaf9f0171e9517f40e41"
    "#;

        let context = AuthContext::new("Mufasa", "CircleOfLife", "/dir/index.html");

        let mut prompt = WwwAuthenticateHeader::from_str(src).unwrap();
        let answer = AuthorizationHeader::from_prompt(&mut prompt, &context).unwrap();

        // The spec has a wrong hash in the example, see errata
        let str = answer.to_string().replace(", ", ",\n  ");
        assert_eq!(
            str,
            r#"
Digest username="Mufasa",
  realm="testrealm@host.com",
  nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
  uri="/dir/index.html",
  response="1949323746fe6a43ef61f9606e7febea",
  opaque="5ccc069c403ebaf9f0171e9517f40e41"
"#
                .trim()
        );
    }

    #[test]
    fn test_rfc2617() {
        let src = r#"
    Digest
        realm="testrealm@host.com",
        qop="auth,auth-int",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        opaque="5ccc069c403ebaf9f0171e9517f40e41"
    "#;

        let mut context = AuthContext::new("Mufasa", "Circle Of Life", "/dir/index.html");
        context.set_custom_cnonce("0a4f113b");

        let mut prompt = WwwAuthenticateHeader::from_str(src).unwrap();
        let answer = AuthorizationHeader::from_prompt(&mut prompt, &context).unwrap();

        let str = answer.to_string().replace(", ", ",\n  ");
        //println!("{}", str);

        assert_eq!(
            str,
            r#"
Digest username="Mufasa",
  realm="testrealm@host.com",
  nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
  uri="/dir/index.html",
  qop=auth,
  nc=00000001,
  cnonce="0a4f113b",
  response="6629fae49393a05397450978507c4ef1",
  opaque="5ccc069c403ebaf9f0171e9517f40e41",
  algorithm=MD5
"#
                .trim()
        );
    }

    #[test]
    fn test_rfc7616_md5() {
        let src = r#"
    Digest
       realm="http-auth@example.org",
       qop="auth, auth-int",
       algorithm=MD5,
       nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
       opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
    "#;

        let mut context = AuthContext::new("Mufasa", "Circle of Life", "/dir/index.html");
        context.set_custom_cnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");

        let mut prompt = WwwAuthenticateHeader::from_str(src).unwrap();
        let answer = AuthorizationHeader::from_prompt(&mut prompt, &context).unwrap();

        let str = answer.to_string().replace(", ", ",\n  ");

        assert_eq!(
            str,
            r#"
Digest username="Mufasa",
  realm="http-auth@example.org",
  nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
  uri="/dir/index.html",
  qop=auth,
  nc=00000001,
  cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
  response="8ca523f5e9506fed4657c9700eebdbec",
  opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
  algorithm=MD5
"#
                .trim()
        );
    }

    #[test]
    fn test_rfc7616_sha256() {
        let src = r#"
    Digest
       realm="http-auth@example.org",
       qop="auth, auth-int",
       algorithm=SHA-256,
       nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
       opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
    "#;

        let mut context = AuthContext::new("Mufasa", "Circle of Life", "/dir/index.html");
        context.set_custom_cnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
//
//    let secrets = AuthSecrets {
//        username: "Mufasa".to_string(),
//        password: "Circle of Life".to_string(),
//        uri: "/dir/index.html".to_string(),
//        body: None,
//        method: HttpMethod::GET,
//        nc: 1,
//        cnonce: Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_string()),
//    };

        let mut prompt = WwwAuthenticateHeader::from_str(src).unwrap();
        let answer = AuthorizationHeader::from_prompt(&mut prompt, &context).unwrap();

        let str = answer.to_string().replace(", ", ",\n  ");
        //println!("{}", str);

        assert_eq!(
            str,
            r#"
Digest username="Mufasa",
  realm="http-auth@example.org",
  nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
  uri="/dir/index.html",
  qop=auth,
  nc=00000001,
  cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
  response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
  opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
  algorithm=SHA-256
"#
                .trim()
        );
    }
}

//endregion
