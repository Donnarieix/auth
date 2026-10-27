//! Internal ID token RS256 signing with a public JWKS.
//! Private RSA material is loaded only from a local, untracked file.
use std::{collections::HashSet, fs, path::Path};

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};

use crate::{
    entities::user,
    oidc::{consent::Scopes, grants::RedeemedGrant},
    state::AppState,
};

#[derive(Clone, Debug, Serialize)]
pub struct PublicJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<PublicJwk>,
}

pub struct SigningKeys {
    issuer: String,
    active_kid: String,
    signing_key: EncodingKey,
    jwks: Jwks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: String,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IssueError {
    InvalidGrant,
    SigningFailed,
}

fn valid_kid(kid: &str) -> bool {
    (8..=64).contains(&kid.len())
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn to_jwk(kid: &str, public: &RsaPublicKey) -> Result<PublicJwk, String> {
    if !valid_kid(kid) {
        return Err("Invalid signing key ID".into());
    }
    if public.n().bits() < 2048 || public.e().to_bytes_be() != [1, 0, 1] {
        return Err("RSA keys must be at least 2048 bits with exponent 65537".into());
    }
    Ok(PublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

impl SigningKeys {
    /// Supply public-only keys for previously issued tokens. Never place their
    /// former private keys in this collection.
    pub fn from_pem(
        issuer: &str,
        active_kid: &str,
        private_pem: &str,
        previous: &[(String, String)],
    ) -> Result<Self, String> {
        if (!issuer.starts_with("https://") && issuer != "http://127.0.0.1:3000")
            || issuer.ends_with('/')
            || issuer.contains('?')
            || issuer.contains('#')
        {
            return Err("OIDC issuer must be a canonical HTTPS origin".into());
        }
        let parsed = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .map_err(|_| "Expected an RSA PKCS#8 private PEM key")?;
        let active_jwk = to_jwk(active_kid, &RsaPublicKey::from(&parsed))?;
        let signing_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|_| "Invalid RSA signing key")?;
        let mut jwks = vec![active_jwk];
        let mut kids = HashSet::from([active_kid.to_owned()]);
        for (kid, public_pem) in previous {
            if !kids.insert(kid.clone()) {
                return Err("Duplicate signing key ID".into());
            }
            let parsed = RsaPublicKey::from_public_key_pem(public_pem)
                .map_err(|_| "Invalid previous public PEM key")?;
            jwks.push(to_jwk(kid, &parsed)?);
        }
        Ok(Self {
            issuer: issuer.into(),
            active_kid: active_kid.into(),
            signing_key,
            jwks: Jwks { keys: jwks },
        })
    }

    pub fn from_env(issuer: &str) -> Result<Option<Self>, String> {
        let key_file = std::env::var("OIDC_SIGNING_KEY_FILE").ok();
        let kid = std::env::var("OIDC_SIGNING_KID").ok();
        let (key_file, kid) = match (key_file, kid) {
            (Some(file), Some(kid)) => (file, kid),
            (None, None) if std::env::var_os("OIDC_OLD_PUBLIC_KEYS_DIR").is_none() => {
                return Ok(None);
            }
            _ => return Err("OIDC signing key and key ID must be configured together".into()),
        };
        if !issuer.starts_with("https://") && issuer != "http://127.0.0.1:3000" {
            return Err(
                "OIDC signing requires HTTPS or the exact loopback development origin".into(),
            );
        }
        let path = Path::new(&key_file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .map_err(|_| "Cannot stat signing key file")?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(
                    "OIDC signing private key must not be group/world accessible (chmod 600)"
                        .into(),
                );
            }
        }
        let private = fs::read_to_string(path).map_err(|_| "Cannot read signing key file")?;
        let mut old = Vec::new();
        if let Ok(dir) = std::env::var("OIDC_OLD_PUBLIC_KEYS_DIR") {
            for entry in
                fs::read_dir(dir).map_err(|_| "Cannot open previous public-key directory")?
            {
                let entry = entry.map_err(|_| "Cannot read public-key directory entry")?;
                let path = entry.path();
                if path.extension().is_none_or(|ext| ext != "pem") || !path.is_file() {
                    return Err(
                        "Only regular .pem public key files are allowed in the key directory"
                            .into(),
                    );
                }
                let old_kid = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or("Invalid old key filename")?
                    .to_owned();
                let pem = fs::read_to_string(&path).map_err(|_| "Cannot read old public key")?;
                old.push((old_kid, pem));
            }
        }
        old.sort_by(|a, b| a.0.cmp(&b.0));
        Self::from_pem(issuer, &kid, &private, &old).map(Some)
    }

    pub fn public_jwks(&self) -> Jwks {
        Jwks {
            keys: self.jwks.keys.clone(),
        }
    }

    /// Only invoke after the authenticated, consented authorization code was
    /// redeemed successfully. This module does not authorize or redeem codes.
    pub fn sign_id_token(
        &self,
        grant: &RedeemedGrant,
        account: &user::Model,
        authenticated_at: DateTime<Utc>,
    ) -> Result<String, IssueError> {
        let now = Utc::now();
        let scopes = Scopes::parse(&grant.scope).map_err(|_| IssueError::InvalidGrant)?;
        if !account.active
            || !account.email_verified
            || account.id != grant.user_id
            || grant.client_id.is_empty()
            || grant.client_id.len() > 256
            || !(16..=256).contains(&grant.nonce.len())
            || !grant.nonce.is_ascii()
            || authenticated_at > now
            || authenticated_at < now - chrono::Duration::hours(1)
        {
            return Err(IssueError::InvalidGrant);
        }
        let claims = IdToken {
            iss: self.issuer.clone(),
            sub: account.id.to_string(),
            aud: grant.client_id.clone(),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::minutes(5)).timestamp(),
            nonce: grant.nonce.clone(),
            auth_time: authenticated_at.timestamp(),
            preferred_username: scopes.profile.then(|| account.username.clone()),
            name: if scopes.profile {
                account.display_name.clone()
            } else {
                None
            },
            picture: if scopes.profile {
                account.avatar_url.clone()
            } else {
                None
            },
            email: scopes.email.then(|| account.email.clone()),
            email_verified: scopes.email.then_some(account.email_verified),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, &claims, &self.signing_key).map_err(|_| IssueError::SigningFailed)
    }
}

/// Public metadata only; never exposes private key bytes or filenames.
pub async fn jwks(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let Some(keys) = state.oidc_keys.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(keys.public_jwks()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use rand_core::OsRng;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use uuid::Uuid;

    fn keypair() -> (String, String) {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        (
            private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
            public.to_public_key_pem(LineEnding::LF).unwrap(),
        )
    }

    fn account() -> user::Model {
        let now = Utc::now();
        user::Model {
            id: Uuid::new_v4(),
            email: "private@example.com".into(),
            email_verified: true,
            username: "tester".into(),
            display_name: Some("Test Person".into()),
            avatar_url: None,
            active: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn signed_tokens_validate_by_public_jwk_and_respect_scopes() {
        let (pem, _) = keypair();
        let keys =
            SigningKeys::from_pem("https://auth.example.test", "active-2026", &pem, &[]).unwrap();
        let user = account();
        let mut grant = RedeemedGrant {
            user_id: user.id,
            client_id: "client-1".into(),
            scope: "openid".into(),
            nonce: "unique-auth-nonce-1234".into(),
            auth_time: Utc::now(),
        };
        let token = keys.sign_id_token(&grant, &user, Utc::now()).unwrap();
        let hdr = decode_header(&token).unwrap();
        assert_eq!(hdr.alg, Algorithm::RS256);
        assert_eq!(hdr.kid.as_deref(), Some("active-2026"));
        let jwk = &keys.public_jwks().keys[0];
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.use_, "sig");
        let public = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://auth.example.test"]);
        validation.set_audience(&["client-1"]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
        validation.leeway = 0;
        let decoded = decode::<IdToken>(&token, &public, &validation).unwrap();
        assert_eq!(decoded.claims.sub, user.id.to_string());
        assert_eq!(decoded.claims.nonce, grant.nonce);
        assert!(decoded.claims.email.is_none());
        assert!(decoded.claims.preferred_username.is_none());
        validation.set_audience(&["different-client"]);
        assert!(decode::<IdToken>(&token, &public, &validation).is_err());

        grant.scope = "openid email profile".into();
        let expanded = keys.sign_id_token(&grant, &user, Utc::now()).unwrap();
        let claims = decode::<IdToken>(&expanded, &public, &{
            let mut v = Validation::new(Algorithm::RS256);
            v.set_issuer(&["https://auth.example.test"]);
            v.set_audience(&["client-1"]);
            v
        })
        .unwrap()
        .claims;
        assert_eq!(claims.email.as_deref(), Some("private@example.com"));
        assert_eq!(claims.preferred_username.as_deref(), Some("tester"));
    }

    #[test]
    fn local_issuer_only_accepts_exact_loopback_origin() {
        let (private, _) = keypair();
        assert!(SigningKeys::from_pem(
            "http://127.0.0.1:3000",
            "development-local",
            &private,
            &[],
        ).is_ok());
        assert!(SigningKeys::from_pem(
            "http://localhost:3000",
            "development-local",
            &private,
            &[],
        ).is_err());
        assert!(SigningKeys::from_pem(
            "http://192.168.1.10:3000",
            "development-local",
            &private,
            &[],
        ).is_err());
    }

    #[test]
    fn key_rotation_keeps_only_public_material_for_previous_keys() {
        let (old_private, old_public) = keypair();
        let (new_private, _) = keypair();
        let previous =
            SigningKeys::from_pem("https://auth.example.test", "old-2026", &old_private, &[])
                .unwrap();
        let rotating = SigningKeys::from_pem(
            "https://auth.example.test",
            "new-2026",
            &new_private,
            &[("old-2026".into(), old_public)],
        )
        .unwrap();
        assert_eq!(rotating.public_jwks().keys.len(), 2);
        assert!(
            SigningKeys::from_pem(
                "https://auth.example.test",
                "new-2026",
                &new_private,
                &[("new-2026".into(), "invalid".into())]
            )
            .is_err()
        );
        let user = account();
        let grant = RedeemedGrant {
            user_id: user.id,
            client_id: "client-1".into(),
            scope: "openid".into(),
            nonce: "unique-auth-nonce-1234".into(),
            auth_time: Utc::now(),
        };
        let old_token = previous.sign_id_token(&grant, &user, Utc::now()).unwrap();
        let old_jwk = rotating
            .public_jwks()
            .keys
            .into_iter()
            .find(|j| j.kid == "old-2026")
            .unwrap();
        let decoding = DecodingKey::from_rsa_components(&old_jwk.n, &old_jwk.e).unwrap();
        let mut val = Validation::new(Algorithm::RS256);
        val.set_audience(&["client-1"]);
        val.set_issuer(&["https://auth.example.test"]);
        assert!(decode::<IdToken>(&old_token, &decoding, &val).is_ok());
        assert!(!format!("{:?}", rotating.public_jwks()).contains("PRIVATE KEY"));
    }

    #[test]
    fn signer_rejects_unverified_accounts_and_mismatched_subject() {
        let (pem, _) = keypair();
        let keys =
            SigningKeys::from_pem("https://auth.example.test", "active-2026", &pem, &[]).unwrap();
        let mut user = account();
        let grant = RedeemedGrant {
            user_id: user.id,
            client_id: "client-1".into(),
            scope: "openid".into(),
            nonce: "unique-auth-nonce-1234".into(),
            auth_time: Utc::now(),
        };
        user.email_verified = false;
        assert_eq!(
            keys.sign_id_token(&grant, &user, Utc::now()).unwrap_err(),
            IssueError::InvalidGrant
        );
        user.email_verified = true;
        user.id = Uuid::new_v4();
        assert_eq!(
            keys.sign_id_token(&grant, &user, Utc::now()).unwrap_err(),
            IssueError::InvalidGrant
        );
    }

    #[tokio::test]
    async fn jwks_route_is_public_only_when_keys_are_configured() {
        use std::sync::Arc;

        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode, header},
        };
        use sea_orm::Database;
        use tower::ServiceExt;

        use crate::{router, state::AppState};

        let db = Database::connect("sqlite::memory:").await.unwrap();
        let mut state = AppState::with_db(db);
        let url = "/.well-known/jwks.json";
        let missing = router(state.clone())
            .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let (private, _) = keypair();
        let configured =
            SigningKeys::from_pem("https://auth.example.test", "example-2026", &private, &[])
                .unwrap();
        state.oidc_keys = Some(Arc::new(configured));
        let response = router(state)
            .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=300"
        );
        let json = to_bytes(response.into_body(), 8192).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let key = &data["keys"][0];
        assert_eq!(key["kid"], "example-2026");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "RS256");
        assert!(key["n"].as_str().unwrap().len() > 300);
        assert_eq!(key["e"], "AQAB");
        assert!(key.get("d").is_none());
        assert!(!std::str::from_utf8(&json).unwrap().contains("PRIVATE KEY"));
    }
}
