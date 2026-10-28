//! Browser-facing session policy. HTTP mode is deliberately limited to loopback.
use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

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

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https: 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

fn attach_security_headers(response: &mut Response, secure: bool) {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Most pages suppress referrers completely. OIDC consent pages override
    // this with "origin" so native HTML POST forms send a usable Origin
    // header, without exposing authorization query parameters.
    if !headers.contains_key(header::REFERRER_POLICY) {
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
    }
    // Preserve cacheability of public signing keys and discovery metadata;
    // authenticated, sensitive responses remain uncached by default.
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    if secure {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

/// Apply defense-in-depth browser headers to every response, including errors.
/// The current local web UI embeds its script and CSS. This CSP is a staging
/// compromise: extract static assets and use nonce-/hash-based scripts and
/// styles before claiming production-grade CSP hardening.
pub async fn security_response_headers(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    attach_security_headers(&mut response, state.security.secure);
    response
}

/// Reject state-changing browser requests without a trustworthy, exact origin.
/// SameSite=Lax is defense in depth, not the sole CSRF control.
pub async fn require_same_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // /token is a back-channel OAuth call authenticated by a one-time PKCE
    // verifier, not by browser cookies. It must not require an Origin header.
    let oauth_backchannel = request.method() == Method::POST && request.uri().path() == "/token";
    if !oauth_backchannel
        && matches!(
            *request.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        )
    {
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
    use super::{SecurityConfig, attach_security_headers};
    use axum::{
        body::Body,
        http::{Response, header},
    };

    #[test]
    fn response_headers_protect_sensitive_pages_and_https() {
        let mut response = Response::new(Body::empty());
        attach_security_headers(&mut response, false);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(
            !response
                .headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );
        attach_security_headers(&mut response, true);
        assert_eq!(
            response.headers()[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000"
        );
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("style-src 'unsafe-inline'")
        );
    }

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
