use axum::Extension;

use crate::entities;

pub async fn me(
    Extension(user): Extension<entities::user::Model>,
) -> String {
    format!("Hello, {}", user.username)
}