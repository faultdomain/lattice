//! JWT validation module
//!
//! FIPS-compliant JWT validation with JWKS caching.

mod jwks;
mod validator;

pub use jwks::{Jwk, JwkSet, JwksCache};
pub use validator::{Claims, JwtValidator, ValidatedToken, ValidationConfig};
