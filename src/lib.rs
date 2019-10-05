//! This crate implements Digest Auth headers as specified by IETF RFCs 2069, 2617, and 7616.
//! It can be used in conjunction with libraries like reqwest to access e.g. IP cameras
//! that use this authentication scheme.
//!
//! This library is intended for the http client. The algorithm is symmetrical,
//! it's just not optimized for / tested on the server side yet.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```
//! use digest_auth::AuthContext;
//!
//! // Value from the WWW-Authenticate HTTP header (usually in a HTTP 401 response)
//! let www_authenticate = r#"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#;
//!
//! // Prepare an authorization context. Note that this is a GET request. There are different
//! // constructors available for POST or other request types. You can re-use it, but
//! // it's cheap to create a fresh one each time, as the struct uses references only.
//! let mut context = AuthContext::new("Mufasa", "Circle of Life", "/dir/index.html");
//! // For this test, we inject a custom cnonce. It's generated for you otherwise
//! // - you don't need `mut` in that case and needn't worry about this at all.
//! context.set_custom_cnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
//!
//! // Parse the prompt header. You can inspect the parsed object, its fields are public.
//! let mut prompt = digest_auth::parse(www_authenticate).unwrap();
//!
//! // Compute a value for the Authorization header that we'll send back to the server
//! let answer = prompt.respond(&context).unwrap().to_string();
//! assert_eq!(answer, r#"Digest username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", response="8ca523f5e9506fed4657c9700eebdbec", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", algorithm=MD5"#);
//!
//! // The `prompt` variable is mutable, because the 'nc' counter (nonce reuse count)
//! // is inside the struct and updated automatically.
//!
//! // You can re-use it for subsequent requests, assuming the server allows nonce re-use.
//! // Some poorly implemented servers will reject it and give you 401 again, in which case
//! // you should parse the new "WWW-Authenticate" header and use that instead.
//!
//! let answer2 = prompt.respond(&context).unwrap().to_string();
//! // notice how the 'response' field changed - the 'nc' counter is included in the hash
//! assert_eq!(answer2, r#"Digest username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html", qop=auth, nc=00000002, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", response="4b5d595ecf2db9df612ea5b45cd97101", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", algorithm=MD5"#);
//! ```

mod digest;
mod enums;
mod error;

pub use error::{Error, Result};

pub use crate::digest::{AuthContext, AuthorizationHeader, WwwAuthenticateHeader};

pub use crate::enums::*;

/// Parse the WWW-Authorization header value.
/// It's just a convenience method to call [`WwwAuthenticateHeader::parse()`](struct.WwwAuthenticateHeader.html#method.parse).
pub fn parse(www_authorize: &str) -> Result<WwwAuthenticateHeader> {
    WwwAuthenticateHeader::parse(www_authorize)
}

#[test]
fn test_parse_respond() {
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

    let mut prompt = crate::parse(src).unwrap();
    let answer = prompt.respond(&context).unwrap();

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
