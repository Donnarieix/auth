use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post},
};
use tokio::net::TcpListener;

use crate::{
    middleware::auth,
    oidc::signing::jwks,
    oidc::{browser, endpoints},
    routes::account::{confirm_reset, confirm_verification, request_reset, request_verification},
    routes::{health::health, login::login, logout::logout, me::me, register::register},
    security::require_same_origin,
    state::AppState,
};

mod admin;
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
mod integration_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod oidc_http_tests;

fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth));

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/email/verification/request", post(request_verification))
        .route("/email/verification/confirm", post(confirm_verification))
        .route("/password/reset/request", post(request_reset))
        .route("/password/reset/confirm", post(confirm_reset))
        .merge(protected)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_same_origin,
        ));
    if state.oidc_keys.is_some() {
        app = app
            .route("/.well-known/jwks.json", get(jwks))
            .route(
                "/.well-known/openid-configuration",
                get(endpoints::discovery),
            )
            .route("/authorize", get(browser::authorize))
            .route("/authorize/login", post(browser::login))
            .route("/authorize/consent", post(browser::consent))
            .route("/token", post(endpoints::token))
            .route("/userinfo", get(endpoints::userinfo));
    }
    app.with_state(state)
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
