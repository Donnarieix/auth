use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    entities::{session, user},
    oidc::{
        s256_challenge,
        signing::{IdToken, SigningKeys},
    },
    router, schema,
    security::SecurityConfig,
    services::{
        client::{ClientType, register_client},
        session::generate_token,
    },
    state::AppState,
};

const ORIGIN: &str = "https://auth.example.test";
const REDIRECT: &str = "http://127.0.0.1:4000/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn fixture() -> (Router, String, String) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let public_client = register_client(
        &db,
        "Test Client",
        ClientType::Desktop,
        &[REDIRECT.to_owned()],
    )
    .await
    .unwrap();

    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    user::ActiveModel {
        id: Set(user_id),
        email: Set("verified@example.test".into()),
        email_verified: Set(true),
        username: Set("tester".into()),
        display_name: Set(Some("Test User".into())),
        avatar_url: Set(None),
        active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let (raw_cookie, cookie_hash) = generate_token();
    session::ActiveModel {
        id: Set(session_id),
        user_id: Set(user_id),
        token_hash: Set(cookie_hash),
        created_at: Set(now),
        expires_at: Set(now + chrono::Duration::hours(1)),
        last_use: Set(now),
        active: Set(true),
    }
    .insert(&db)
    .await
    .unwrap();

    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let keys = SigningKeys::from_pem(ORIGIN, "integration-2026", &pem, &[]).unwrap();
    let mut state = AppState::with_db(db);
    state.security = SecurityConfig::for_origin(ORIGIN).unwrap();
    state.oidc_keys = Some(Arc::new(keys));

    (
        router(state),
        public_client,
        format!("__Host-auth_session={raw_cookie}"),
    )
}

fn authorization_form(client: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid profile email")
        .append_pair("state", "opaque-unique-state-value-1234")
        .append_pair("nonce", "opaque-unique-nonce-value-1234")
        .append_pair("code_challenge", &s256_challenge(VERIFIER).unwrap())
        .append_pair("code_challenge_method", "S256")
        .finish()
}

fn token_form(client: &str, code: &str, verifier: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("code", code)
        .append_pair("code_verifier", verifier)
        .finish()
}

#[tokio::test]
async fn complete_code_pkce_consent_jwks_userinfo_and_replay_protection() {
    let (app, client, cookie) = fixture().await;
    let form = authorization_form(&client);
    let page = request(
        &app,
        Method::GET,
        &format!("/authorize?{form}"),
        String::new(),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = to_bytes(page.into_body(), 100_000).await.unwrap();
    assert!(
        std::str::from_utf8(&html)
            .unwrap()
            .contains("Allow this application")
    );

    // A GET must never issue a code. Approval requires an explicit POST.
    let approval = request(
        &app,
        Method::POST,
        "/authorize/approve",
        form,
        &[
            ("cookie", &cookie),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;
    assert_eq!(approval.status(), StatusCode::SEE_OTHER);
    let location = approval
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let redirect = url::Url::parse(location).unwrap();
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert_eq!(redirect.port(), Some(4000));
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1,
        "opaque-unique-state-value-1234"
    );

    // PKCE failure must not consume the code.
    let bad = request(
        &app,
        Method::POST,
        "/token",
        token_form(&client, &code, &"a".repeat(43)),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let good_body = token_form(&client, &code, VERIFIER);
    let ok = request(
        &app,
        Method::POST,
        "/token",
        good_body.clone(),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let parsed: serde_json::Value =
        serde_json::from_slice(&to_bytes(ok.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(parsed["token_type"], "Bearer");
    let jwt = parsed["id_token"].as_str().unwrap();
    let bearer = parsed["access_token"].as_str().unwrap();

    let public = request(
        &app,
        Method::GET,
        "/.well-known/jwks.json",
        String::new(),
        &[],
    )
    .await;
    assert_eq!(public.status(), StatusCode::OK);
    let jwks: serde_json::Value =
        serde_json::from_slice(&to_bytes(public.into_body(), 100_000).await.unwrap()).unwrap();
    let key = &jwks["keys"][0];
    let public_key =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ORIGIN]);
    validation.set_audience(&[client.as_str()]);
    let identity = decode::<IdToken>(jwt, &public_key, &validation)
        .unwrap()
        .claims;
    assert_eq!(identity.email.as_deref(), Some("verified@example.test"));
    assert_eq!(identity.nonce, "opaque-unique-nonce-value-1234");

    let userinfo = request(
        &app,
        Method::GET,
        "/userinfo",
        String::new(),
        &[("authorization", &format!("Bearer {bearer}"))],
    )
    .await;
    assert_eq!(userinfo.status(), StatusCode::OK);
    let info: serde_json::Value = serde_json::from_slice(&to_bytes(userinfo.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(info["sub"], identity.sub);
    assert_eq!(info["email"], "verified@example.test");

    let replay = request(
        &app,
        Method::POST,
        "/token",
        good_body,
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_clients_and_missing_browser_sessions_never_receive_codes() {
    let (app, client, _) = fixture().await;
    let form = authorization_form(&client);
    let response = request(
        &app,
        Method::POST,
        "/authorize/approve",
        form,
        &[
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
