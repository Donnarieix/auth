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
}

// Images are managed by /account/avatar. This endpoint cannot set an arbitrary
// third-party URL (which would disclose visitor IP addresses to the image host).
fn checked_profile(mut patch: UpdateProfile) -> Result<UpdateProfile, StatusCode> {
    patch.display_name = patch.display_name.map(|name| name.trim().to_owned());
    if patch.display_name.as_deref().is_some_and(|v| {
        v.chars().count() > 64 || v.chars().any(char::is_control)
    }) {
        return Err(StatusCode::BAD_REQUEST);
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
    model.updated_at = Set(Utc::now());
    let updated = model
        .update(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(updated.into()))
}

#[cfg(test)]
mod tests {
    use super::{checked_profile, UpdateProfile};
    #[test]
    fn display_name_is_bounded_and_trimmed() {
        assert_eq!(checked_profile(UpdateProfile { display_name: Some("  Camille  ".into()) }).unwrap().display_name.as_deref(), Some("Camille"));
        assert!(checked_profile(UpdateProfile { display_name: Some("a".repeat(65)) }).is_err());
        assert!(checked_profile(UpdateProfile { display_name: Some("bad\\nname".into()) }).is_err());
    }
}
