use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, DatabaseConnection, DbBackend,
    Statement,
};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    entities::{password_credential, session, user},
    oidc::{
        s256_challenge,
        signing::{IdToken, SigningKeys},
    },
    router, schema,
    security::SecurityConfig,
    services::{
        client::{ClientType, register_client, rotate_web_client_secret},
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

async fn fixture_for(
    kind: ClientType,
    redirect: &str,
) -> (Router, String, String, Option<String>, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let public_client = register_client(&db, "Test Client", kind, &[redirect.to_owned()])
        .await
        .unwrap();

    let secret = if kind == ClientType::Web {
        Some(rotate_web_client_secret(&db, &public_client).await.unwrap())
    } else {
        None
    };

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

    password_credential::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set("original-hash".into()),
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
    let mut state = AppState::with_db(db.clone());
    state.security = SecurityConfig::for_origin(ORIGIN).unwrap();
    state.oidc_keys = Some(Arc::new(keys));

    (
        router(state),
        public_client,
        format!("__Host-auth_session={raw_cookie}"),
        secret,
        db,
    )
}

async fn fixture() -> (Router, String, String) {
    let (app, client, cookie, _, _) = fixture_for(ClientType::Desktop, REDIRECT).await;
    (app, client, cookie)
}

fn authorization_form_for(client: &str, redirect: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client)
        .append_pair("redirect_uri", redirect)
        .append_pair("scope", "openid profile email")
        .append_pair("state", "opaque-unique-state-value-1234")
        .append_pair("nonce", "opaque-unique-nonce-value-1234")
        .append_pair("code_challenge", &s256_challenge(VERIFIER).unwrap())
        .append_pair("code_challenge_method", "S256")
        .finish()
}

fn authorization_form(client: &str) -> String {
    authorization_form_for(client, REDIRECT)
}

fn token_form_for(client: &str, redirect: &str, code: &str, verifier: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client)
        .append_pair("redirect_uri", redirect)
        .append_pair("code", code)
        .append_pair("code_verifier", verifier)
        .finish()
}

fn token_form(client: &str, code: &str, verifier: &str) -> String {
    token_form_for(client, REDIRECT, code, verifier)
}

#[tokio::test]
async fn confidential_web_client_requires_secret_and_pkce() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let redirect = "https://web.example.test/oauth/callback";
    let (app, client, cookie, secret, _) = fixture_for(ClientType::Web, redirect).await;
    let form = authorization_form_for(&client, redirect);
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
    let location = approval.headers()[header::LOCATION].to_str().unwrap();
    let callback = url::Url::parse(location).unwrap();
    assert_eq!(callback.host_str(), Some("web.example.test"));
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();
    let payload = token_form_for(&client, redirect, &code, VERIFIER);
    let no_credentials = request(
        &app,
        Method::POST,
        "/token",
        payload.clone(),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(no_credentials.status(), StatusCode::UNAUTHORIZED);
    let incorrect = STANDARD.encode(format!("{client}:{}", "z".repeat(43)));
    let rejected = request(
        &app,
        Method::POST,
        "/token",
        payload.clone(),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {incorrect}")),
        ],
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let basic = STANDARD.encode(format!("{client}:{}", secret.unwrap()));
    let success = request(
        &app,
        Method::POST,
        "/token",
        payload.clone(),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
    )
    .await;
    assert_eq!(success.status(), StatusCode::OK);
    let issued: serde_json::Value =
        serde_json::from_slice(&to_bytes(success.into_body(), 100_000).await.unwrap()).unwrap();
    let access = issued["access_token"].as_str().unwrap();
    let introspection_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", access)
        .finish();
    let check = request(
        &app,
        Method::POST,
        "/introspect",
        introspection_form.clone(),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
    )
    .await;
    assert_eq!(check.status(), StatusCode::OK);
    let status: serde_json::Value =
        serde_json::from_slice(&to_bytes(check.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(status["active"], true);
    assert_eq!(status["client_id"], client);
    assert_eq!(status["token_type"], "Bearer");

    let forbidden = request(
        &app,
        Method::POST,
        "/introspect",
        introspection_form,
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::UNAUTHORIZED);

    let replay = request(
        &app,
        Method::POST,
        "/token",
        payload,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
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
    let csp = page.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("form-action 'self' http://127.0.0.1:4000;"));
    assert!(csp.contains("frame-ancestors 'none'"));
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
    let info: serde_json::Value =
        serde_json::from_slice(&to_bytes(userinfo.into_body(), 100_000).await.unwrap()).unwrap();
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
    let (app, client, cookie) = fixture().await;
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

    let csrf = request(
        &app,
        Method::POST,
        "/authorize/approve",
        authorization_form(&client),
        &[
            ("cookie", &cookie),
            ("origin", "https://evil.example"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;
    assert_eq!(csrf.status(), StatusCode::FORBIDDEN);

    let malformed = request(
        &app,
        Method::GET,
        "/authorize?response_type=code&client_id=unregistered",
        String::new(),
        &[],
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audience_bound_access_can_be_revoked_without_affecting_other_resources() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    let redirect = "https://rp.example.test/callback";
    let (app, client, cookie, secret, db) = fixture_for(ClientType::Web, redirect).await;
    let resource_a = "https://api-a.example.test";
    let resource_b = "https://api-b.example.test";
    let server_secret = "r".repeat(43);

    for resource in [resource_a, resource_b] {
        let id = Uuid::new_v4().to_string();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_resources(id,audience,name,secret_hash,active) VALUES(?,?,?,?,1)",
            [
                id.clone().into(),
                resource.to_owned().into(),
                "API".into(),
                Sha256::digest(server_secret.as_bytes()).to_vec().into(),
            ],
        ))
        .await
        .unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_client_resources(client_id,resource_id) SELECT id,? FROM clients WHERE client_id=?",
            [id.clone().into(),client.clone().into()],
        )).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_resource_scopes(resource_id,scope) VALUES(?,?)",
            [id.clone().into(), "records:read".into()],
        ))
        .await
        .unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_client_resource_scopes(client_id,resource_id,scope) SELECT id,?,? FROM clients WHERE client_id=?",
            [id.into(),"records:read".into(),client.clone().into()],
        )).await.unwrap();
    }
    let form = format!(
        "{}&resource={}&resource_scope=records%3Aread",
        authorization_form_for(&client, redirect),
        url::form_urlencoded::byte_serialize(resource_a.as_bytes()).collect::<String>()
    );
    let approve = request(
        &app,
        Method::POST,
        "/authorize/approve",
        form,
        &[
            ("origin", ORIGIN),
            ("cookie", &cookie),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;
    assert_eq!(approve.status(), StatusCode::SEE_OTHER);
    let destination =
        url::Url::parse(approve.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let code = destination
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();
    let secret = secret.unwrap();
    let basic = STANDARD.encode(format!("{client}:{secret}"));
    let exchange = request(
        &app,
        Method::POST,
        "/token",
        token_form_for(&client, redirect, &code, VERIFIER),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
    )
    .await;
    assert_eq!(exchange.status(), StatusCode::OK);
    let issued: serde_json::Value =
        serde_json::from_slice(&to_bytes(exchange.into_body(), 100_000).await.unwrap()).unwrap();
    let token = issued["access_token"].as_str().unwrap();
    let inspect_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .finish();
    for (audience, expected) in [(resource_a, true), (resource_b, false)] {
        let resource_basic = STANDARD.encode(format!("{audience}:{server_secret}"));
        let inspect = request(
            &app,
            Method::POST,
            "/introspect",
            inspect_form.clone(),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &format!("Basic {resource_basic}")),
            ],
        )
        .await;
        assert_eq!(inspect.status(), StatusCode::OK);
        let data: serde_json::Value =
            serde_json::from_slice(&to_bytes(inspect.into_body(), 100_000).await.unwrap()).unwrap();
        assert_eq!(data["active"], expected);
        if expected {
            assert_eq!(data["aud"], resource_a);
            assert_eq!(data["resource_scope"], "records:read");
        }
    }
    let revoked = request(
        &app,
        Method::POST,
        &format!("/account/consents/{client}/revoke"),
        String::new(),
        &[("origin", ORIGIN), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let resource_basic = STANDARD.encode(format!("{resource_a}:{server_secret}"));
    let inspect = request(
        &app,
        Method::POST,
        "/introspect",
        inspect_form,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {resource_basic}")),
        ],
    )
    .await;
    let data: serde_json::Value =
        serde_json::from_slice(&to_bytes(inspect.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(data["active"], false);
    let feed = request(
        &app,
        Method::POST,
        "/session/events",
        "after=0".into(),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
    )
    .await;
    assert_eq!(feed.status(), StatusCode::OK);
    let events: serde_json::Value =
        serde_json::from_slice(&to_bytes(feed.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(events["events"][0]["reason"], "consent_revoked");
}
