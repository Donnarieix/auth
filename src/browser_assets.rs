//! First-party browser scripts served with an explicit JavaScript media type.
use axum::http::header;

pub async fn developer() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../assets/developer.js"),
    )
}

pub async fn register_client() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../assets/register-client.js"),
    )
}

pub async fn manage_client() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../assets/manage-client.js"),
    )
}

pub async fn account() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../assets/account.js"),
    )
}

pub async fn authorize_login() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../assets/authorize-login.js"),
    )
}
