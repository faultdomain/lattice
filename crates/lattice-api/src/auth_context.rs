//! Authentication context for Cedar policy evaluation
//!
//! Extracts context from HTTP requests for time-based and conditional policies.
//! All times are UTC.

use axum::body::Body;
use axum::http::Request;
use cedar_policy::{Context, RestrictedExpression};
use chrono::{Datelike, Timelike, Utc};

/// Authentication context extracted from HTTP requests
///
/// Contains temporal and request metadata for Cedar policy evaluation.
/// All times are UTC for consistency.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Current UTC timestamp in ISO8601 format
    pub now: String,
    /// Current hour (0-23 UTC)
    pub hour: i64,
    /// Day of week (Mon, Tue, Wed, Thu, Fri, Sat, Sun)
    pub weekday: String,
    /// Client IP address
    pub source_ip: String,
    /// Emergency access flag (from X-Lattice-Break-Glass header)
    pub break_glass: bool,
    /// Break-glass TTL in ISO8601 format (from X-Lattice-Break-Glass-Expires header)
    pub break_glass_expires: Option<String>,
    /// Incident reference (from X-Lattice-Incident-Id header)
    pub incident_id: Option<String>,
}

impl AuthContext {
    /// Create AuthContext from an HTTP request
    ///
    /// Extracts temporal context (always present) and client IP.
    /// Break-glass fields are NOT extracted from client headers to prevent
    /// spoofing — they must be set through trusted server-side mechanisms.
    pub fn from_request(req: &Request<Body>) -> Self {
        let now = Utc::now();

        Self {
            now: now.to_rfc3339(),
            hour: i64::from(now.hour()),
            weekday: weekday_str(now.weekday()),
            source_ip: extract_client_ip(req),
            break_glass: false,
            break_glass_expires: None,
            incident_id: None,
        }
    }

    /// Create AuthContext with explicit values (for testing)
    #[cfg(test)]
    pub fn new_for_test(
        now: &str,
        hour: i64,
        weekday: &str,
        source_ip: &str,
        break_glass: bool,
        break_glass_expires: Option<&str>,
        incident_id: Option<&str>,
    ) -> Self {
        Self {
            now: now.to_string(),
            hour,
            weekday: weekday.to_string(),
            source_ip: source_ip.to_string(),
            break_glass,
            break_glass_expires: break_glass_expires.map(String::from),
            incident_id: incident_id.map(String::from),
        }
    }

    /// Convert to Cedar Context for policy evaluation
    ///
    /// Creates a Cedar Context with all available fields. Optional fields
    /// (break_glass_expires, incident_id) are only included when present.
    pub fn to_cedar_context(&self) -> Result<Context, crate::error::Error> {
        let mut pairs: Vec<(String, RestrictedExpression)> = vec![
            (
                "now".into(),
                RestrictedExpression::new_string(self.now.clone()),
            ),
            ("hour".into(), RestrictedExpression::new_long(self.hour)),
            (
                "weekday".into(),
                RestrictedExpression::new_string(self.weekday.clone()),
            ),
            (
                "sourceIp".into(),
                RestrictedExpression::new_string(self.source_ip.clone()),
            ),
            (
                "breakGlass".into(),
                RestrictedExpression::new_bool(self.break_glass),
            ),
        ];

        if let Some(ref expires) = self.break_glass_expires {
            pairs.push((
                "breakGlassExpires".into(),
                RestrictedExpression::new_string(expires.clone()),
            ));
        }
        if let Some(ref incident) = self.incident_id {
            pairs.push((
                "incidentId".into(),
                RestrictedExpression::new_string(incident.clone()),
            ));
        }

        Context::from_pairs(pairs)
            .map_err(|e| crate::error::Error::Internal(format!("cedar context: {}", e)))
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            now: now.to_rfc3339(),
            hour: i64::from(now.hour()),
            weekday: weekday_str(now.weekday()),
            source_ip: "unknown".to_string(),
            break_glass: false,
            break_glass_expires: None,
            incident_id: None,
        }
    }
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
    // Use the TCP peer address from axum's ConnectInfo — this cannot be spoofed
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
        // X-Forwarded-For must NOT be trusted — it's spoofable
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
        let ctx = AuthContext::from_request(&req);

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
        // Break-glass headers from clients are ignored to prevent spoofing.
        // They must be set through trusted server-side mechanisms.
        let req = make_request_with_headers(vec![
            ("X-Forwarded-For", "10.0.1.100"),
            ("X-Lattice-Break-Glass", "true"),
            ("X-Lattice-Break-Glass-Expires", "2024-06-01T00:00:00Z"),
            ("X-Lattice-Incident-Id", "INC-12345"),
        ]);
        let ctx = AuthContext::from_request(&req);

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
        let ctx = AuthContext::default();

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
        let ctx = AuthContext::new_for_test(
            "2024-01-15T10:30:00Z",
            10,
            "Mon",
            "10.0.1.100",
            false,
            None,
            None,
        );

        // Verifies to_cedar_context doesn't panic
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_with_break_glass() {
        let ctx = AuthContext::new_for_test(
            "2024-01-15T10:30:00Z",
            10,
            "Mon",
            "10.0.1.100",
            true,
            Some("2024-06-01T00:00:00Z"),
            Some("INC-12345"),
        );

        // Verifies to_cedar_context doesn't panic with optional fields
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_partial_break_glass() {
        // Break glass true but no expires or incident - should still work
        let ctx = AuthContext::new_for_test(
            "2024-01-15T10:30:00Z",
            10,
            "Mon",
            "10.0.1.100",
            true,
            None,
            None,
        );

        // Verifies to_cedar_context doesn't panic with partial break glass
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }
}
