//! Browser-facing session policy. HTTP mode is deliberately limited to loopback.
use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, SameSite, time::Duration};

use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub origin: String,
    pub secure: bool,
}

impl SecurityConfig {
    pub fn development() -> Self {
        Self {
            origin: "http://127.0.0.1:3000".into(),
            secure: false,
        }
    }

    pub fn from_env() -> Result<Self, &'static str> {
        let origin = match std::env::var("AUTH_PUBLIC_ORIGIN") {
            Ok(origin) => origin,
            Err(std::env::VarError::NotPresent) => return Ok(Self::development()),
            Err(_) => return Err("AUTH_PUBLIC_ORIGIN is not valid UTF-8"),
        };
        Self::for_origin(&origin)
    }

    pub fn for_origin(raw: &str) -> Result<Self, &'static str> {
        let origin = raw.trim_end_matches('/');
        let uri: Uri = origin
            .parse()
            .map_err(|_| "AUTH_PUBLIC_ORIGIN is not an HTTP URI")?;
        let scheme = uri
            .scheme_str()
            .ok_or("AUTH_PUBLIC_ORIGIN needs a scheme")?;
        let authority = uri.authority().ok_or("AUTH_PUBLIC_ORIGIN needs a host")?;
        if authority.as_str().contains('@')
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
        {
            return Err("AUTH_PUBLIC_ORIGIN must contain only a scheme and host");
        }
        if scheme != "https" && origin != "http://127.0.0.1:3000" {
            return Err("Non-HTTPS origins are forbidden outside loopback development");
        }
        Ok(Self {
            origin: origin.to_owned(),
            secure: scheme == "https",
        })
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth_session"
        } else {
            "auth_session"
        }
    }

    pub fn issue_cookie(&self, token: String) -> Cookie<'static> {
        Cookie::build((self.cookie_name(), token))
            .http_only(true)
            .secure(self.secure)
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(Duration::hours(1))
            .build()
    }

    pub fn clear_cookie(&self) -> Cookie<'static> {
        Cookie::build((self.cookie_name(), ""))
            .http_only(true)
            .secure(self.secure)
            .same_site(SameSite::Lax)
            .path("/")
            .build()
    }
}

/// Reject state-changing browser requests without a trustworthy, exact origin.
/// SameSite=Lax is defense in depth, not the sole CSRF control.
pub async fn require_same_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|header| header.to_str().ok());
        if origin != Some(state.security.origin.as_str()) {
            return Err(StatusCode::FORBIDDEN);
        }
        // Modern browser metadata adds defense in depth.
        if request
            .headers()
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value != "same-origin" && value != "none")
        {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::SecurityConfig;

    #[test]
    fn requires_https_except_explicit_loopback_mode() {
        let dev = SecurityConfig::for_origin("http://127.0.0.1:3000").unwrap();
        assert!(!dev.secure);
        assert_eq!(dev.cookie_name(), "auth_session");
        assert!(SecurityConfig::for_origin("http://example.com").is_err());
        assert!(SecurityConfig::for_origin("http://localhost:3000").is_err());
        assert!(SecurityConfig::for_origin("https://auth.example.com/path").is_err());
        assert!(SecurityConfig::for_origin("https://attacker@auth.example.com").is_err());
        let prod = SecurityConfig::for_origin("https://auth.example.com").unwrap();
        assert!(prod.secure);
        assert_eq!(prod.cookie_name(), "__Host-auth_session");
    }

    #[test]
    fn production_cookie_is_host_scoped_and_secure() {
        let prod = SecurityConfig::for_origin("https://auth.example.com").unwrap();
        let serialized = prod.issue_cookie("test-token".into()).to_string();
        assert!(serialized.starts_with("__Host-auth_session="));
        assert!(serialized.contains("HttpOnly"));
        assert!(serialized.contains("Secure"));
        assert!(serialized.contains("Path=/"));
        assert!(serialized.contains("SameSite=Lax"));
        assert!(serialized.contains("Max-Age=3600"));
        assert!(!serialized.contains("Domain="));
    }
}
