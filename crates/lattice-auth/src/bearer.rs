//! Bearer token extraction from HTTP headers

use axum::http::HeaderMap;

/// Extract bearer token from the Authorization header.
///
/// Returns `None` if the header is missing, uses a non-Bearer scheme,
/// or is malformed.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("abc123"));
    }

    #[test]
    fn returns_none_when_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn returns_none_for_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn returns_none_when_no_space() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearerabc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }
}
