use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post},
};
use tokio::net::TcpListener;

use crate::{
    middleware::auth,
    oidc::authorization::{approve, authorization_page, deny},
    oidc::discovery::discovery,
    oidc::signing::jwks,
    oidc::token::{token, userinfo},
    routes::account::{confirm_reset, confirm_verification, request_reset, request_verification},
    routes::{health::health, login::login, logout::logout, me::me, register::register},
    security::{require_same_origin, security_response_headers},
    state::AppState,
};

mod admin;
mod developer;
mod developer_manage;
mod developer_session;
mod entities;
mod middleware;
#[expect(
    dead_code,
    reason = "OIDC request validation is staged until token issuance is implemented"
)]
mod oidc;
mod routes;
mod schema;
mod security;
mod services;
mod state;

#[cfg(test)]
mod developer_session_tests;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod oidc_flow_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod session_tests;

fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth));

    let mut app = Router::new()
        .route("/health", get(health))
        .route(
            "/developer/clients",
            get(developer::list_clients).post(developer_manage::create),
        )
        .route("/developer/new-client", get(developer_manage::create_page))
        .route(
            "/developer/clients/{id}/disable",
            post(developer_manage::disable),
        )
        .route("/developer", get(developer_session::page))
        .route("/developer/login", post(developer_session::login))
        .route("/developer/logout", post(developer_session::logout))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/email/verification/request", post(request_verification))
        .route("/email/verification/confirm", post(confirm_verification))
        .route("/password/reset/request", post(request_reset))
        .route("/password/reset/confirm", post(confirm_reset))
        .merge(protected);
    if state.oidc_keys.is_some() {
        app = app
            .route("/.well-known/jwks.json", get(jwks))
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/authorize", get(authorization_page))
            .route("/authorize/approve", post(approve))
            .route("/authorize/deny", post(deny))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo));
    }
    // Apply security layers AFTER adding conditional OIDC routes; otherwise
    // newly registered routes would bypass the common Origin/CSRF policy.
    app.layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_same_origin,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            security_response_headers,
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        if let Err(err) = admin::run(&args).await {
            eprintln!("{err}");
            std::process::exit(2);
        }
        return;
    }

    let state = AppState::new().await;
    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, router(state)).await.unwrap();
}
