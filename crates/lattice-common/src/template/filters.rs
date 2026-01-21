//! Custom filters for Score-compatible templating
//!
//! Provides filters for common operations:
//! - `default`: Provide fallback for undefined values
//! - `base64_encode`: Encode string to base64
//! - `base64_decode`: Decode base64 to string
//! - `required`: Fail if value is undefined

use base64::{engine::general_purpose::STANDARD, Engine};
use minijinja::{Error, ErrorKind, Value};

/// Default filter - returns fallback if value is undefined or empty
///
/// Usage: `${value | default("fallback")}`
pub fn default_filter(value: Value, fallback: Value) -> Value {
    if value.is_undefined() || value.is_none() {
        fallback
    } else {
        value
    }
}

/// Base64 encode filter
///
/// Usage: `${value | base64_encode}`
pub fn base64_encode(value: &str) -> String {
    STANDARD.encode(value.as_bytes())
}

/// Base64 decode filter
///
/// Usage: `${value | base64_decode}`
pub fn base64_decode(value: &str) -> Result<String, Error> {
    STANDARD
        .decode(value)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                format!("base64 decode error: {}", e),
            )
        })
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    format!("base64 decode produced invalid UTF-8: {}", e),
                )
            })
        })
}

/// Required filter - fails if value is undefined
///
/// Usage: `${value | required}`
pub fn required(value: Value) -> Result<Value, Error> {
    if value.is_undefined() {
        Err(Error::new(
            ErrorKind::UndefinedError,
            "required value is undefined",
        ))
    } else {
        Ok(value)
    }
}

/// Upper case filter
///
/// Usage: `${value | upper}`
pub fn upper(value: &str) -> String {
    value.to_uppercase()
}

/// Lower case filter
///
/// Usage: `${value | lower}`
pub fn lower(value: &str) -> String {
    value.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter_with_value() {
        let value = Value::from("hello");
        let fallback = Value::from("world");
        let result = default_filter(value, fallback);
        assert_eq!(result.to_string(), "hello");
    }

    #[test]
    fn test_default_filter_with_undefined() {
        let value = Value::UNDEFINED;
        let fallback = Value::from("fallback");
        let result = default_filter(value, fallback);
        assert_eq!(result.to_string(), "fallback");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_encode(""), "");
        assert_eq!(base64_encode("hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(
            base64_decode("aGVsbG8=").expect("valid base64 should decode successfully"),
            "hello"
        );
        assert_eq!(
            base64_decode("").expect("empty string should decode successfully"),
            ""
        );
        assert_eq!(
            base64_decode("aGVsbG8gd29ybGQ=").expect("valid base64 should decode successfully"),
            "hello world"
        );
    }

    #[test]
    fn test_base64_decode_invalid() {
        let result = base64_decode("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_required_with_value() {
        let value = Value::from("present");
        let result = required(value);
        assert!(result.is_ok());
    }

    #[test]
    fn test_required_undefined() {
        let result = required(Value::UNDEFINED);
        assert!(result.is_err());
    }

    #[test]
    fn test_upper() {
        assert_eq!(upper("hello"), "HELLO");
        assert_eq!(upper("Hello World"), "HELLO WORLD");
    }

    #[test]
    fn test_lower() {
        assert_eq!(lower("HELLO"), "hello");
        assert_eq!(lower("Hello World"), "hello world");
    }

    #[test]
    fn test_default_filter_with_none() {
        let value = Value::from(());
        let fallback = Value::from("fallback");
        let result = default_filter(value, fallback);
        assert_eq!(result.to_string(), "fallback");
    }

    #[test]
    fn test_default_filter_with_empty_string() {
        // Empty string is a valid value, should NOT use fallback
        let value = Value::from("");
        let fallback = Value::from("fallback");
        let result = default_filter(value, fallback);
        assert_eq!(result.to_string(), "");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = "test data with special chars: !@#$%^&*()";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).expect("base64 roundtrip should decode successfully");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_decode_invalid_utf8() {
        // This is valid base64 but decodes to invalid UTF-8 (0xFF 0xFE)
        let result = base64_decode("//4=");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UTF-8"));
    }

    #[test]
    fn test_upper_with_unicode() {
        assert_eq!(upper("café"), "CAFÉ");
    }

    #[test]
    fn test_lower_with_unicode() {
        assert_eq!(lower("CAFÉ"), "café");
    }
}
