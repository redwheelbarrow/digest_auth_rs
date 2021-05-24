use rand::Rng;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::enums::{Algorithm, AlgorithmType, Charset, HttpMethod, Qop, QopAlgo};

use crate::{Error::*, Result};
use std::borrow::Cow;

/// slash quoting for digest strings
trait QuoteForDigest {
    fn quote_for_digest(&self) -> String;
}

impl QuoteForDigest for &str {
    fn quote_for_digest(&self) -> String {
        self.to_string().quote_for_digest()
    }
}

impl<'a> QuoteForDigest for Cow<'a, str> {
    fn quote_for_digest(&self) -> String {
        self.as_ref().quote_for_digest()
    }
}

impl QuoteForDigest for String {
    fn quote_for_digest(&self) -> String {
        self.replace("\\", "\\\\").replace("\"", "\\\"")
    }
}

/// Join a Vec of Display items using a separator
fn join_vec<T: ToString>(vec: &[T], sep: &str) -> String {
    vec.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

enum NamedTag<'a> {
    Quoted(&'a str, Cow<'a, str>),
    Plain(&'a str, Cow<'a, str>),
}

impl Display for NamedTag<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NamedTag::Quoted(name, content) => {
                write!(f, "{}=\"{}\"", name, content.quote_for_digest())
            }
            NamedTag::Plain(name, content) => write!(f, "{}={}", name, content),
        }
    }
}

/// Helper func that parses the key-value string received from server
fn parse_header_map(input: &str) -> Result<HashMap<String, String>> {
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
        _ => return Err(InvalidHeaderSyntax(input.into())),
    }

    Ok(parsed)
}

/// Login attempt context
///
/// All fields are borrowed to reduce runtime overhead; this struct should not be stored anywhere,
/// it is normally meaningful only for the one request.
#[derive(Debug)]
pub struct AuthContext<'a> {
    /// Login username
    pub username: Cow<'a, str>,
    /// Login password (plain)
    pub password: Cow<'a, str>,
    /// Requested URI (not a domain! should start with a slash)
    pub uri: Cow<'a, str>,
    /// Request payload body - used for auth-int (auth with integrity check)
    /// May be left out if not using auth-int
    pub body: Option<Cow<'a, [u8]>>,
    /// HTTP method used (defaults to GET)
    pub method: HttpMethod<'a>,
    /// Spoofed client nonce (use only for tests; a random nonce is generated automatically)
    pub cnonce: Option<Cow<'a, str>>,
}

impl<'a> AuthContext<'a> {
    /// Construct a new context with the GET verb and no payload body.
    /// See the other constructors if this does not fit your situation.
    pub fn new<UN, PW, UR>(username: UN, password: PW, uri: UR) -> Self
    where
        UN: Into<Cow<'a, str>>,
        PW: Into<Cow<'a, str>>,
        UR: Into<Cow<'a, str>>,
    {
        Self::new_with_method(
            username,
            password,
            uri,
            Option::<&'a [u8]>::None,
            HttpMethod::GET,
        )
    }

    /// Construct a new context with the POST verb and a payload body (may be None).
    /// See the other constructors if this does not fit your situation.
    pub fn new_post<UN, PW, UR, BD>(username: UN, password: PW, uri: UR, body: Option<BD>) -> Self
    where
        UN: Into<Cow<'a, str>>,
        PW: Into<Cow<'a, str>>,
        UR: Into<Cow<'a, str>>,
        BD: Into<Cow<'a, [u8]>>,
    {
        Self::new_with_method(username, password, uri, body, HttpMethod::POST)
    }

    /// Construct a new context with arbitrary verb and, optionally, a payload body
    pub fn new_with_method<UN, PW, UR, BD>(
        username: UN,
        password: PW,
        uri: UR,
        body: Option<BD>,
        method: HttpMethod<'a>,
    ) -> Self
    where
        UN: Into<Cow<'a, str>>,
        PW: Into<Cow<'a, str>>,
        UR: Into<Cow<'a, str>>,
        BD: Into<Cow<'a, [u8]>>,
    {
        Self {
            username: username.into(),
            password: password.into(),
            uri: uri.into(),
            body: body.map(Into::into),
            method,
            cnonce: None,
        }
    }

    /// Set cnonce to the given value
    pub fn set_custom_cnonce<CN>(&mut self, cnonce: CN)
    where
        CN: Into<Cow<'a, str>>,
    {
        self.cnonce = Some(cnonce.into());
    }
}

/// WWW-Authenticate header parsed from HTTP header value
#[derive(Debug, PartialEq, Clone)]
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

impl FromStr for WwwAuthenticateHeader {
    type Err = crate::Error;

    /// Parse HTTP header
    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl WwwAuthenticateHeader {
    /// Generate an [`AuthorizationHeader`](struct.AuthorizationHeader.html) to be sent to the server in a new request.
    /// The [`self.nc`](struct.AuthorizationHeader.html#structfield.nc) field is incremented.
    pub fn respond(&mut self, secrets: &AuthContext) -> Result<AuthorizationHeader> {
        AuthorizationHeader::from_prompt(self, secrets)
    }

    /// Construct from the `WWW-Authenticate` header string
    ///
    /// # Errors
    /// If the header is malformed (e.g. missing 'realm', missing a closing quote, unknown algorithm etc.)
    pub fn parse(input: &str) -> Result<Self> {
        let mut input = input.trim();

        // Remove leading "Digest"
        if input.starts_with("Digest") {
            input = &input["Digest".len()..];
        }

        let mut kv = parse_header_map(input)?;

        Ok(Self {
            domain: if let Some(domains) = kv.get("domain") {
                let domains: Vec<&str> = domains.split(' ').collect();
                Some(domains.iter().map(|x| x.trim().to_string()).collect())
            } else {
                None
            },
            realm: match kv.remove("realm") {
                Some(v) => v,
                None => return Err(MissingRequired("realm", input.into())),
            },
            nonce: match kv.remove("nonce") {
                Some(v) => v,
                None => return Err(MissingRequired("nonce", input.into())),
            },
            opaque: kv.remove("opaque"),
            stale: match kv.get("stale") {
                Some(v) => &v.to_ascii_lowercase() == "true",
                None => false,
            },
            charset: match kv.get("charset") {
                Some(v) => Charset::from_str(v)?,
                None => Charset::ASCII,
            },
            algorithm: match kv.get("algorithm") {
                Some(a) => Algorithm::from_str(&a)?,
                _ => Algorithm::default(),
            },
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
                Some(v) => &v.to_ascii_lowercase() == "true",
                None => false,
            },
            nc: 0,
        })
    }
}

impl Display for WwwAuthenticateHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut entries = Vec::<NamedTag>::new();

        f.write_str("Digest ")?;

        entries.push(NamedTag::Quoted("realm", (&self.realm).into()));

        if let Some(ref qops) = self.qop {
            entries.push(NamedTag::Quoted("qop", join_vec(qops, ", ").into()));
        }

        if let Some(ref domains) = self.domain {
            entries.push(NamedTag::Quoted("domain", join_vec(domains, " ").into()));
        }

        if self.stale {
            entries.push(NamedTag::Plain("stale", "true".into()));
        }

        entries.push(NamedTag::Plain(
            "algorithm",
            self.algorithm.to_string().into(),
        ));
        entries.push(NamedTag::Quoted("nonce", (&self.nonce).into()));
        if let Some(ref opaque) = self.opaque {
            entries.push(NamedTag::Quoted("opaque", (opaque).into()));
        }
        entries.push(NamedTag::Plain("charset", self.charset.to_string().into()));

        if self.userhash {
            entries.push(NamedTag::Plain("userhash", "true".into()));
        }

        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(&e.to_string())?;
        }

        Ok(())
    }
}

/// Header sent back to the server, including password hashes.
///
/// This can be obtained by calling [`AuthorizationHeader::from_prompt()`](#method.from_prompt),
/// or from the [`WwwAuthenticateHeader`](struct.WwwAuthenticateHeader.html) prompt struct
/// with [`.respond()`](struct.WwwAuthenticateHeader.html#method.respond)
#[derive(Debug, PartialEq, Clone)]
pub struct AuthorizationHeader {
    /// Authorization realm
    pub realm: String,
    /// Server nonce
    pub nonce: String,
    /// Server opaque
    pub opaque: Option<String>,
    /// Flag that userhash was used
    pub userhash: bool,
    /// Hash algorithm
    pub algorithm: Algorithm,
    /// Computed digest
    pub response: String,
    /// Username or hash (owned because of the computed hash)
    pub username: String,
    /// Requested URI
    pub uri: String,
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

impl AuthorizationHeader {
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
    pub fn from_prompt(
        prompt: &mut WwwAuthenticateHeader,
        context: &AuthContext,
    ) -> Result<AuthorizationHeader> {
        let qop = match &prompt.qop {
            None => None,
            Some(vec) => {
                // this is at least RFC2617, qop was given
                if vec.contains(&Qop::AUTH_INT) {
                    Some(Qop::AUTH_INT)
                } else if vec.contains(&Qop::AUTH) {
                    // "auth" is the second best after "auth-int"
                    Some(Qop::AUTH)
                } else {
                    // parser bug - prompt.qop should have been None
                    return Err(BadQopOptions(join_vec(vec, ", ")));
                }
            }
        };

        prompt.nc += 1;

        let mut hdr = AuthorizationHeader {
            realm: prompt.realm.clone(),
            nonce: prompt.nonce.clone(),
            opaque: prompt.opaque.clone(),
            userhash: prompt.userhash,
            algorithm: prompt.algorithm,
            response: String::default(),
            username: String::default(),
            uri: context.uri.as_ref().into(),
            qop,
            cnonce: context
                .cnonce
                .as_ref()
                .map(AsRef::as_ref)
                .map(ToOwned::to_owned), // Will be generated if needed, if build_hash is set and this is None
            nc: prompt.nc,
        };

        hdr.digest(context);

        Ok(hdr)
    }

    /// Build the response digest from Auth Context.
    ///
    /// This function is used by client to fill the Authorization header.
    /// It can be used by server using a known password to replicate the hash
    /// and then compare "response".
    ///
    /// This function sets cnonce if it was None before, or reuses it.
    ///
    /// Fields updated in the Authorization header:
    /// - qop (if it was auth-int before but no body was given in context)
    /// - cnonce (if it was None before)
    /// - username copied from context
    /// - response
    pub fn digest(&mut self, context: &AuthContext) {
        // figure out which QOP option to use
        let qop_algo = match self.qop {
            None => QopAlgo::NONE,
            Some(Qop::AUTH_INT) => {
                if let Some(b) = &context.body {
                    QopAlgo::AUTH_INT(b.as_ref())
                } else {
                    // fallback
                    QopAlgo::AUTH
                }
            }
            Some(Qop::AUTH) => QopAlgo::AUTH,
        };

        let h = &self.algorithm;

        let cnonce = {
            match &self.cnonce {
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
                realm = self.realm,
                pw = context.password
            );

            let sess = self.algorithm.sess;
            if sess {
                format!(
                    "{hash}:{nonce}:{cnonce}",
                    hash = h.hash(a.as_bytes()),
                    nonce = self.nonce,
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
        let username = if self.userhash {
            h.hash(
                format!(
                    "{username}:{realm}",
                    username = context.username,
                    realm = self.realm
                )
                .as_bytes(),
            )
        } else {
            context.username.as_ref().to_owned()
        };

        let qop: Option<Qop> = qop_algo.into();

        let ha1 = h.hash_str(&a1);
        let ha2 = h.hash_str(&a2);

        self.response = match &qop {
            Some(q) => {
                let tmp = format!(
                    "{ha1}:{nonce}:{nc:08x}:{cnonce}:{qop}:{ha2}",
                    ha1 = ha1,
                    nonce = self.nonce,
                    nc = self.nc,
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
                    nonce = self.nonce,
                    ha2 = ha2
                );
                h.hash(tmp.as_bytes())
            }
        };

        self.qop = qop;
        self.username = username;
        self.cnonce = qop.map(|_| cnonce);
    }

    /// Produce a header string (also accessible through the Display trait)
    pub fn to_header_string(&self) -> String {
        self.to_string()
    }

    /// Construct from the `Authorization` header string
    ///
    /// # Errors
    /// If the header is malformed (e.g. missing mandatory fields)
    pub fn parse(input: &str) -> Result<Self> {
        let mut input = input.trim();

        // Remove leading "Digest"
        if input.starts_with("Digest") {
            input = &input["Digest".len()..];
        }

        let mut kv = parse_header_map(input)?;

        let mut auth = Self {
            username: match kv.remove("username") {
                Some(v) => v,
                None => return Err(MissingRequired("username", input.into())),
            },
            realm: match kv.remove("realm") {
                Some(v) => v,
                None => return Err(MissingRequired("realm", input.into())),
            },
            nonce: match kv.remove("nonce") {
                Some(v) => v,
                None => return Err(MissingRequired("nonce", input.into())),
            },
            uri: match kv.remove("uri") {
                Some(v) => v,
                None => return Err(MissingRequired("uri", input.into())),
            },
            response: match kv.remove("response") {
                Some(v) => v,
                None => return Err(MissingRequired("response", input.into())),
            },
            qop: kv.remove("qop").map(|s| Qop::from_str(&s)).transpose()?,
            nc: match kv.remove("nc") {
                Some(v) => u32::from_str_radix(&v, 16)?,
                None => 1,
            },
            cnonce: kv.remove("cnonce"),
            opaque: kv.remove("opaque"),
            algorithm: match kv.get("algorithm") {
                Some(a) => Algorithm::from_str(&a)?,
                _ => Algorithm::default(),
            },
            userhash: match kv.get("userhash") {
                Some(v) => &v.to_ascii_lowercase() == "true",
                None => false,
            },
        };

        if auth.qop.is_some() {
            if auth.cnonce.is_none() {
                return Err(MissingRequired("cnonce", input.into()));
            }
        } else {
            // cnonce must not be set if qop is not given, clear it.
            auth.cnonce = None;
        }

        Ok(auth)
    }
}

impl Display for AuthorizationHeader {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut entries = Vec::<NamedTag>::new();

        f.write_str("Digest ")?;

        entries.push(NamedTag::Quoted("username", (&self.username).into()));
        entries.push(NamedTag::Quoted("realm", (&self.realm).into()));
        entries.push(NamedTag::Quoted("nonce", (&self.nonce).into()));
        entries.push(NamedTag::Quoted("uri", (&self.uri).into()));

        if self.qop.is_some() && self.cnonce.is_some() {
            entries.push(NamedTag::Plain(
                "qop",
                self.qop.as_ref().unwrap().to_string().into(),
            ));
            entries.push(NamedTag::Plain("nc", format!("{:08x}", self.nc).into()));
            entries.push(NamedTag::Quoted(
                "cnonce",
                self.cnonce.as_ref().unwrap().into(),
            ));
        }

        entries.push(NamedTag::Quoted("response", (&self.response).into()));

        if let Some(opaque) = &self.opaque {
            entries.push(NamedTag::Quoted("opaque", opaque.into()));
        }

        // algorithm can be omitted if it is the default value (or in legacy compat mode)
        if self.qop.is_some() || self.algorithm.algo != AlgorithmType::MD5 {
            entries.push(NamedTag::Plain(
                "algorithm",
                self.algorithm.to_string().into(),
            ));
        }

        if self.userhash {
            entries.push(NamedTag::Plain("userhash", "true".into()));
        }

        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(&e.to_string())?;
        }

        Ok(())
    }
}

impl FromStr for AuthorizationHeader {
    type Err = crate::Error;

    /// Parse HTTP header
    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_header_map;
    use super::Algorithm;
    use super::AlgorithmType;
    use super::AuthorizationHeader;
    use super::Charset;
    use super::Qop;
    use super::WwwAuthenticateHeader;
    use crate::digest::AuthContext;
    use std::str::FromStr;

    #[test]
    fn test_parse_header_map() {
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

    #[test]
    fn test_parse_header_map2() {
        let src = r#"realm="api@example.org""#;
        let map = parse_header_map(src).unwrap();
        assert_eq!(map.get("realm").unwrap(), "api@example.org");
    }

    #[test]
    fn test_parse_header_map3() {
        let src = r#"realm=api@example.org"#;
        let map = parse_header_map(src).unwrap();
        assert_eq!(map.get("realm").unwrap(), "api@example.org");
    }

    #[test]
    fn test_parse_header_map4() {
        {
            let src = "";
            let map = parse_header_map(src).unwrap();
            assert_eq!(map.is_empty(), true);
        }
    }

    #[test]
    fn test_www_hdr_parse() {
        // most things are parsed here...
        let src = r#"
               realm="api@example.org",
               qop="auth",
               domain="/my/nice/url /login /logout",
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
                nc: 0,
            }
        )
    }

    #[test]
    fn test_www_hdr_tostring() {
        let mut hdr = WwwAuthenticateHeader {
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
            nc: 0,
        };

        assert_eq!(
            r#"Digest realm="api@example.org",
  qop="auth",
  domain="/my/nice/url /login /logout",
  algorithm=SHA-512-256,
  nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
  opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
  charset=UTF-8,
  userhash=true"#
                .replace(",\n  ", ", "),
            hdr.to_string()
        );

        hdr.stale = true;
        hdr.userhash = false;
        hdr.opaque = None;
        hdr.qop = None;

        assert_eq!(
            r#"Digest realm="api@example.org",
  domain="/my/nice/url /login /logout",
  stale=true,
  algorithm=SHA-512-256,
  nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
  charset=UTF-8"#
                .replace(",\n  ", ", "),
            hdr.to_string()
        );

        hdr.qop = Some(vec![Qop::AUTH, Qop::AUTH_INT]);

        assert_eq!(
            r#"Digest realm="api@example.org",
  qop="auth, auth-int",
  domain="/my/nice/url /login /logout",
  stale=true,
  algorithm=SHA-512-256,
  nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
  charset=UTF-8"#
                .replace(",\n  ", ", "),
            hdr.to_string()
        );
    }

    #[test]
    fn test_www_hdr_parse2() {
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
                nc: 0,
            }
        )
    }

    #[test]
    fn test_www_hdr_parse3() {
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
                nc: 0,
            }
        )
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
        let s = answer.to_string().replace(", ", ",\n  ");
        assert_eq!(
            s,
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

        // Try round trip
        let parsed = AuthorizationHeader::parse(&s).unwrap();
        assert_eq!(answer, parsed);
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

        assert_eq!(context.body, None);

        let mut prompt = WwwAuthenticateHeader::from_str(src).unwrap();
        let answer = AuthorizationHeader::from_prompt(&mut prompt, &context).unwrap();

        let s = answer.to_string().replace(", ", ",\n  ");
        //println!("{}", str);

        assert_eq!(
            s,
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

        // Try round trip
        let parsed = AuthorizationHeader::parse(&s).unwrap();
        assert_eq!(answer, parsed);
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

        let s = answer.to_string().replace(", ", ",\n  ");

        assert_eq!(
            s,
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

        // Try round trip
        let parsed = AuthorizationHeader::parse(&s).unwrap();
        assert_eq!(answer, parsed);
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

        let s = answer.to_string().replace(", ", ",\n  ");
        //println!("{}", str);

        assert_eq!(
            s,
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

        // Try round trip
        let parsed = AuthorizationHeader::parse(&s).unwrap();
        assert_eq!(answer, parsed);
    }
}
