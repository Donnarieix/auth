use axum::{
    Router, middleware as axum_middleware,
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

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let state = AppState::new().await;

    let protected = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth));

    let app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login))
        .merge(protected)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
