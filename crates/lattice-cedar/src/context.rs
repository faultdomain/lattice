//! Authorization context for Cedar policy evaluation
//!
//! Contains temporal and request metadata used as Cedar `Context` for
//! time-based, IP-based, and break-glass policies.

use cedar_policy::{Context, RestrictedExpression};

use crate::engine::{Error, Result};

/// Authorization context for Cedar policy evaluation
///
/// Carry temporal and request metadata into Cedar policies. Constructed by
/// the HTTP layer (e.g., from an Axum request) and passed to `PolicyEngine::authorize`.
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
    /// Emergency access flag
    pub break_glass: bool,
    /// Break-glass TTL in ISO8601 format
    pub break_glass_expires: Option<String>,
    /// Incident reference
    pub incident_id: Option<String>,
}

impl AuthContext {
    /// Create an AuthContext with all fields specified explicitly.
    pub fn new(
        now: String,
        hour: i64,
        weekday: String,
        source_ip: String,
    ) -> Self {
        Self {
            now,
            hour,
            weekday,
            source_ip,
            break_glass: false,
            break_glass_expires: None,
            incident_id: None,
        }
    }

    /// Convert to Cedar Context for policy evaluation.
    ///
    /// Creates a Cedar Context with all available fields. Optional fields
    /// (break_glass_expires, incident_id) are only included when present.
    pub fn to_cedar_context(&self) -> Result<Context> {
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
            .map_err(|e| Error::Internal(format!("cedar context: {}", e)))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context(break_glass: bool, expires: Option<&str>, incident: Option<&str>) -> AuthContext {
        AuthContext {
            now: "2024-01-15T10:30:00Z".to_string(),
            hour: 10,
            weekday: "Mon".to_string(),
            source_ip: "10.0.1.100".to_string(),
            break_glass,
            break_glass_expires: expires.map(String::from),
            incident_id: incident.map(String::from),
        }
    }

    #[test]
    fn test_to_cedar_context_basic_fields() {
        let ctx = test_context(false, None, None);
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_with_break_glass() {
        let ctx = test_context(true, Some("2024-06-01T00:00:00Z"), Some("INC-12345"));
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_to_cedar_context_partial_break_glass() {
        let ctx = test_context(true, None, None);
        let _cedar_ctx = ctx.to_cedar_context().unwrap();
    }

    #[test]
    fn test_new_constructor() {
        let ctx = AuthContext::new(
            "2024-01-15T10:30:00Z".to_string(),
            10,
            "Mon".to_string(),
            "10.0.1.100".to_string(),
        );
        assert!(!ctx.break_glass);
        assert!(ctx.break_glass_expires.is_none());
        assert!(ctx.incident_id.is_none());
    }
}
