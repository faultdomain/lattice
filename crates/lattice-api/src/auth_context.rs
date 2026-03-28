//! HTTP request → Cedar AuthContext adapter
//!
//! Extracts temporal and request metadata from Axum HTTP requests and builds
//! `lattice_cedar::AuthContext` for policy evaluation. All times are UTC.

use axum::body::Body;
use axum::http::Request;
use chrono::{Datelike, Timelike, Utc};

pub use lattice_cedar::AuthContext;

/// Build an `AuthContext` from an HTTP request.
///
/// Extracts temporal context (always present) and client IP.
/// Break-glass fields are NOT extracted from client headers to prevent
/// spoofing — they must be set through trusted server-side mechanisms.
pub fn auth_context_from_request(req: &Request<Body>) -> AuthContext {
    let now = Utc::now();
    AuthContext::new(
        now.to_rfc3339(),
        i64::from(now.hour()),
        weekday_str(now.weekday()),
        extract_client_ip(req),
    )
}

/// Build a default `AuthContext` with current time and unknown IP.
pub fn auth_context_default() -> AuthContext {
    let now = Utc::now();
    AuthContext::new(
        now.to_rfc3339(),
        i64::from(now.hour()),
        weekday_str(now.weekday()),
        "unknown".to_string(),
    )
}

/// Convert chrono Weekday to string format
fn weekday_str(day: chrono::Weekday) -> String {
    match day {
        chrono::Weekday::Mon => "Mon",
        chrono::Weekday::Tue => "Tue",
        chrono::Weekday::Wed => "Wed",
        chrono::Weekday::Thu => "Thu",
        chrono::Weekday::Fri => "Fri",
        chrono::Weekday::Sat => "Sat",
        chrono::Weekday::Sun => "Sun",
    }
    .to_string()
}

/// Extract client IP from the request's TCP peer address.
///
/// Uses axum's `ConnectInfo<SocketAddr>` extension (set via `.into_make_service_with_connect_info()`)
/// which comes from the actual TCP connection, not from spoofable headers like X-Forwarded-For.
///
/// Falls back to "unknown" if ConnectInfo is not available (e.g., in tests).
fn extract_client_ip(req: &Request<Body>) -> String {
    if let Some(connect_info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return connect_info.0.ip().to_string();
    }

    tracing::debug!("No ConnectInfo available, client IP unknown");
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request_with_headers(headers: Vec<(&str, &str)>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri("/test");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    // =========================================================================
    // Weekday Conversion Tests
    // =========================================================================

    #[test]
    fn test_weekday_str_all_days() {
        use chrono::Weekday;
        let cases = [
            (Weekday::Mon, "Mon"),
            (Weekday::Tue, "Tue"),
            (Weekday::Wed, "Wed"),
            (Weekday::Thu, "Thu"),
            (Weekday::Fri, "Fri"),
            (Weekday::Sat, "Sat"),
            (Weekday::Sun, "Sun"),
        ];
        for (weekday, expected) in cases {
            assert_eq!(weekday_str(weekday), expected, "Failed for {:?}", weekday);
        }
    }

    // =========================================================================
    // Client IP Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_client_ip_from_connect_info() {
        let mut req = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 1, 100],
                12345,
            ))));
        assert_eq!(extract_client_ip(&req), "10.0.1.100");
    }

    #[test]
    fn test_extract_client_ip_ignores_xff_headers() {
        let req = make_request_with_headers(vec![("X-Forwarded-For", "10.0.1.100")]);
        assert_eq!(extract_client_ip(&req), "unknown");
    }

    #[test]
    fn test_extract_client_ip_unknown_without_connect_info() {
        let req = make_request_with_headers(vec![]);
        assert_eq!(extract_client_ip(&req), "unknown");
    }

    // =========================================================================
    // AuthContext Construction Tests
    // =========================================================================

    #[test]
    fn test_auth_context_from_request_basic() {
        let mut req = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 1, 100],
                12345,
            ))));
        let ctx = auth_context_from_request(&req);

        assert!(!ctx.now.is_empty());
        assert!(ctx.hour >= 0 && ctx.hour <= 23);
        assert!(!ctx.weekday.is_empty());
        assert_eq!(ctx.source_ip, "10.0.1.100");
        assert!(!ctx.break_glass);
        assert!(ctx.break_glass_expires.is_none());
        assert!(ctx.incident_id.is_none());
    }

    #[test]
    fn test_auth_context_from_request_ignores_break_glass_headers() {
        let req = make_request_with_headers(vec![
            ("X-Forwarded-For", "10.0.1.100"),
            ("X-Lattice-Break-Glass", "true"),
            ("X-Lattice-Break-Glass-Expires", "2024-06-01T00:00:00Z"),
            ("X-Lattice-Incident-Id", "INC-12345"),
        ]);
        let ctx = auth_context_from_request(&req);

        assert!(
            !ctx.break_glass,
            "break_glass should not be extracted from client headers"
        );
        assert!(
            ctx.break_glass_expires.is_none(),
            "break_glass_expires should not be extracted from client headers"
        );
        assert!(
            ctx.incident_id.is_none(),
            "incident_id should not be extracted from client headers"
        );
    }

    #[test]
    fn test_auth_context_default() {
        let ctx = auth_context_default();

        assert!(!ctx.now.is_empty());
        assert!(ctx.hour >= 0 && ctx.hour <= 23);
        assert!(!ctx.weekday.is_empty());
        assert_eq!(ctx.source_ip, "unknown");
        assert!(!ctx.break_glass);
        assert!(ctx.break_glass_expires.is_none());
        assert!(ctx.incident_id.is_none());
    }

    // =========================================================================
    // Cedar Context Conversion Tests
    // =========================================================================

    #[test]
    fn test_to_cedar_context_basic_fields() {
        let ctx = AuthContext::new(
            "2024-01-15T10:30:00Z".to_string(),
            10,
            "Mon".to_string(),
            "10.0.1.100".to_string(),
        );
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_with_break_glass() {
        let mut ctx = AuthContext::new(
            "2024-01-15T10:30:00Z".to_string(),
            10,
            "Mon".to_string(),
            "10.0.1.100".to_string(),
        );
        ctx.break_glass = true;
        ctx.break_glass_expires = Some("2024-06-01T00:00:00Z".to_string());
        ctx.incident_id = Some("INC-12345".to_string());
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_partial_break_glass() {
        let mut ctx = AuthContext::new(
            "2024-01-15T10:30:00Z".to_string(),
            10,
            "Mon".to_string(),
            "10.0.1.100".to_string(),
        );
        ctx.break_glass = true;
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }
}
