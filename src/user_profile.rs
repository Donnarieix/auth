//! Authenticated self-service profile. Updates never allow changing user ID,
//! verified email, account status or administrative privileges.
use axum::{Extension, Json, extract::State, http::StatusCode};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{entities::user, state::AppState};

#[derive(Serialize)]
pub struct ProfileView {
    id: String,
    email: String,
    email_verified: bool,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

impl From<user::Model> for ProfileView {
    fn from(account: user::Model) -> Self {
        Self {
            id: account.id.to_string(),
            email: account.email,
            email_verified: account.email_verified,
            username: account.username,
            display_name: account.display_name,
            avatar_url: account.avatar_url,
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateProfile {
    display_name: Option<String>,
    avatar_url: Option<String>,
}

fn checked_profile(mut patch: UpdateProfile) -> Result<UpdateProfile, StatusCode> {
    patch.display_name = patch.display_name.map(|name| name.trim().to_owned());
    patch.avatar_url = patch.avatar_url.map(|uri| uri.trim().to_owned());
    if patch
        .display_name
        .as_deref()
        .is_some_and(|v| v.chars().count() > 64 || v.chars().any(char::is_control))
        || patch
            .avatar_url
            .as_deref()
            .is_some_and(|v| v.len() > 512 || v.chars().any(char::is_control))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(uri) = patch.avatar_url.as_deref().filter(|uri| !uri.is_empty()) {
        let parsed = url::Url::parse(uri).map_err(|_| StatusCode::BAD_REQUEST)?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.host_str().is_none()
            || parsed.fragment().is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(patch)
}

pub async fn show(Extension(account): Extension<user::Model>) -> Json<ProfileView> {
    Json(account.into())
}

pub async fn update(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
    Json(patch): Json<UpdateProfile>,
) -> Result<Json<ProfileView>, StatusCode> {
    if !state
        .abuse
        .allow("profile_update", &account.id.to_string(), 60, 15)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let patch = checked_profile(patch)?;
    let mut model: user::ActiveModel = account.into();
    model.display_name = Set(patch.display_name.filter(|s| !s.is_empty()));
    model.avatar_url = Set(patch.avatar_url.filter(|s| !s.is_empty()));
    model.updated_at = Set(Utc::now());
    let updated = model
        .update(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(updated.into()))
}

#[cfg(test)]
mod tests {
    use super::{UpdateProfile, checked_profile};
    #[test]
    fn profile_fields_are_bounded_and_https_only() {
        assert!(checked_profile(UpdateProfile {display_name:Some("  Camille  ".into()),avatar_url:Some("https://example.com/p.png".into())}).is_ok());
        assert!(checked_profile(UpdateProfile {display_name:Some("a".repeat(65)),avatar_url:None}).is_err());
        assert!(checked_profile(UpdateProfile {display_name:None,avatar_url:Some("javascript:alert(1)".into())}).is_err());
        assert!(
            checked_profile(UpdateProfile {
                display_name: None,
                avatar_url: Some("http://localhost/a.png".into())
            })
            .is_err()
        );
    }
}
