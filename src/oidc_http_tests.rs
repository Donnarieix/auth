use std::sync::Arc;

use axum::{body::{Body, to_bytes}, http::{Method, Request, StatusCode, header}};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rand_core::OsRng;
use rsa::{RsaPrivateKey, pkcs8::{EncodePrivateKey, LineEnding}};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait};
use serde_json::Value;
use tower::ServiceExt;
use url::{Url, form_urlencoded};
use uuid::Uuid;

use crate::{entities::user, oidc::{consent, signing::{IdToken, SigningKeys}},
    router, schema, security::SecurityConfig,
    services::{client::{ClientType, get_client, register_client}, session::create_session},
    state::AppState};

const ISSUER: &str = "https://auth.example.test";
const REDIRECT: &str = "http://127.0.0.1:4000/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn form(values: &[(&str, &str)]) -> String {
    let mut encoder = form_urlencoded::Serializer::new(String::new());
    for (k,v) in values { encoder.append_pair(k,v); }
    encoder.finish()
}
async fn send(app: &axum::Router, method: Method, uri: &str, body: String, cookie: Option<&str>, origin: bool) -> axum::response::Response {
    let mut r = Request::builder().method(method).uri(uri);
    if origin { r = r.header(header::ORIGIN, ISSUER); }
    if let Some(value) = cookie { r = r.header(header::COOKIE, value); }
    if !body.is_empty() { r = r.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"); }
    app.clone().oneshot(r.body(Body::from(body)).unwrap()).await.unwrap()
}
async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

#[tokio::test]
async fn consent_code_token_and_userinfo_flow() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let mut state = AppState::with_db(db);
    state.security = SecurityConfig::for_origin(ISSUER).unwrap();
    let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    state.oidc_keys = Some(Arc::new(SigningKeys::from_pem(ISSUER, "test-2026", pem.as_str(), &[]).unwrap()));
    let now = Utc::now();
    let id = Uuid::new_v4();
    user::ActiveModel {
        id: Set(id), email: Set("known@example.com".into()), email_verified: Set(true),
        username: Set("known".into()), display_name: Set(None), avatar_url: Set(None),
        active: Set(true), created_at: Set(now), updated_at: Set(now),
    }.insert(&state.db).await.unwrap();
    let client_id = register_client(&state.db, "SSO test", ClientType::Desktop, &[REDIRECT.into()]).await.unwrap();
    let client = get_client(&state.db, &client_id).await.unwrap().unwrap();
    let raw_session = create_session(&state, user::Entity::find_by_id(id).one(&state.db).await.unwrap().unwrap()).await.unwrap();
    let browser_cookie = format!("__Host-auth_session={raw_session}");
    let app = router(state.clone());
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let params = [
        ("response_type","code"),("client_id",&client_id),("redirect_uri",REDIRECT),
        ("scope","openid email"),("state","state-value-123456789"),
        ("nonce","nonce-value-123456789"),("code_challenge",challenge),
        ("code_challenge_method","S256")
    ];
    let base = form(&params);
    let metadata = json(send(&app,Method::GET,"/.well-known/openid-configuration",String::new(),None,false).await).await;
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(metadata["token_endpoint_auth_methods_supported"][0],"none");
    let pending = send(&app,Method::GET,&format!("/authorize?{base}"),String::new(),Some(&browser_cookie),false).await;
    assert_eq!(pending.status(),StatusCode::OK);
    let page = String::from_utf8(to_bytes(pending.into_body(),65536).await.unwrap().to_vec()).unwrap();
    assert!(page.contains("Authorize SSO test"));
    // Browser is protected against cross-origin consent submission.
    let data = format!("{base}&decision=approve");
    assert_eq!(send(&app,Method::POST,"/authorize/consent",data.clone(),Some(&browser_cookie),false).await.status(),StatusCode::FORBIDDEN);
    let response = send(&app,Method::POST,"/authorize/consent",data,Some(&browser_cookie),true).await;
    assert_eq!(response.status(),StatusCode::SEE_OTHER);
    let location = Url::parse(response.headers().get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
    assert_eq!(location.path(),"/callback");
    let code = location.query_pairs().find(|(k,_)| k=="code").unwrap().1.to_string();
    assert_eq!(location.query_pairs().find(|(k,_)| k=="state").unwrap().1,"state-value-123456789");
    let grant = form(&[("grant_type","authorization_code"),("client_id",&client_id),
        ("redirect_uri",REDIRECT),("code",&code),("code_verifier",VERIFIER)]);
    let exchanged = send(&app,Method::POST,"/token",grant.clone(),None,false).await;
    assert_eq!(exchanged.status(),StatusCode::OK);
    let response = json(exchanged).await;
    assert_eq!(response["token_type"],"Bearer");
    let jwks = json(send(&app,Method::GET,"/.well-known/jwks.json",String::new(),None,false).await).await;
    let public = &jwks["keys"][0];
    let verify = DecodingKey::from_rsa_components(public["n"].as_str().unwrap(),public["e"].as_str().unwrap()).unwrap();
    let mut validate = Validation::new(Algorithm::RS256);
    validate.set_issuer(&[ISSUER]);
    validate.set_audience(&[client_id.as_str()]);
    let claims = decode::<IdToken>(response["id_token"].as_str().unwrap(),&verify,&validate).unwrap().claims;
    assert_eq!(claims.nonce,"nonce-value-123456789");
    assert_eq!(claims.email.as_deref(),Some("known@example.com"));
    let bearer = format!("Bearer {}",response["access_token"].as_str().unwrap());
    let info = app.clone().oneshot(Request::builder().uri("/userinfo").header(header::AUTHORIZATION,&bearer).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(info.status(),StatusCode::OK);
    assert_eq!(json(info).await["sub"],id.to_string());
    assert_eq!(send(&app,Method::POST,"/token",grant,None,false).await.status(),StatusCode::BAD_REQUEST);
    // Revocation of the central session invalidates the access token.
    assert_eq!(send(&app,Method::POST,"/logout",String::new(),Some(&browser_cookie),true).await.status(),StatusCode::NO_CONTENT);
    let info = app.oneshot(Request::builder().uri("/userinfo").header(header::AUTHORIZATION,bearer).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(info.status(),StatusCode::UNAUTHORIZED);
    let _ = client;
    let _ = consent::Scopes::parse("openid email").unwrap();
}
