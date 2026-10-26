use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post},
};
use tokio::net::TcpListener;

use crate::{
    middleware::auth,
    routes::{health::health, login::login, logout::logout, me::me, register::register},
    state::AppState,
};

mod entities;
mod middleware;
mod routes;
mod schema;
mod services;
mod state;

#[cfg(test)]
mod integration_tests;

fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth));

    Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login))
        .merge(protected)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let state = AppState::new().await;
    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, router(state)).await.unwrap();
}
