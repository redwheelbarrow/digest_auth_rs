use std::string::ToString;

/// slash quoting for digest strings
pub trait QuoteForDigest {
    fn quote_for_digest(&self) -> String;
}

impl QuoteForDigest for &str {
    fn quote_for_digest(&self) -> String {
        self.to_string().quote_for_digest()
    }
}

impl QuoteForDigest for String {
    fn quote_for_digest(&self) -> String {
        self.replace("\\", "\\\\").replace("\"", "\\\"")
    }
}
