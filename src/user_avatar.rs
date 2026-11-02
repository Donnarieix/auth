//! Server-owned, opaque WebP avatars. An image is not an authentication token.
//! The returned public URL may be shared by OIDC clients after profile consent.
use std::{io::Cursor, path::PathBuf};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use image::{DynamicImage, ImageFormat, ImageReader};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use crate::{entities::user, state::AppState, user_profile::ProfileView};

fn directory() -> PathBuf {
    std::env::var_os("AUTH_AVATAR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/avatars"))
}

fn avatar_path(id: Uuid) -> PathBuf {
    directory().join(format!("{id}.webp"))
}

fn stored_avatar_id(url: &str, origin: &str) -> Option<Uuid> {
    let prefix = format!("{origin}/media/avatars/");
    let filename = url.strip_prefix(&prefix)?.strip_suffix(".webp")?;
    let id = Uuid::parse_str(filename).ok()?;
    (id.to_string() == filename).then_some(id)
}

/// Require the exact square size produced by the editor. Do not retain
/// untrusted metadata: decode and re-encode the pixel data on the server.
fn normalize(source: &[u8]) -> Result<Vec<u8>, StatusCode> {
    if source.is_empty() || source.len() > 1024 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let dimensions = ImageReader::with_format(Cursor::new(source), ImageFormat::WebP)
        .into_dimensions()
        .map_err(|_| StatusCode::UNSUPPORTED_MEDIA_TYPE)?;
    if dimensions != (256, 256) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let image = image::load_from_memory_with_format(source, ImageFormat::WebP)
        .map_err(|_| StatusCode::UNSUPPORTED_MEDIA_TYPE)?;
    let mut out = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image.to_rgba8())
        .write_to(&mut out, ImageFormat::WebP)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(out.into_inner())
}

pub async fn upload(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ProfileView>, StatusCode> {
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some("image/webp") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if !state.abuse.allow("avatar_upload", &account.id.to_string(), 60, 6).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let encoded = tokio::task::spawn_blocking(move || normalize(&body))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    tokio::fs::create_dir_all(directory())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id = Uuid::new_v4();
    let path = avatar_path(id);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if file.write_all(&encoded).await.is_err() || file.sync_all().await.is_err() {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    drop(file);

    let old_url = account.avatar_url.clone();
    let mut model: user::ActiveModel = account.into();
    model.avatar_url = Set(Some(format!(
        "{}/media/avatars/{id}.webp", state.security.origin
    )));
    model.updated_at = Set(Utc::now());
    let updated = match model.update(&state.db).await {
        Ok(row) => row,
        Err(_) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if let Some(old_id) = old_url.as_deref()
        .and_then(|url| stored_avatar_id(url, &state.security.origin))
    {
        if old_id != id {
            let _ = tokio::fs::remove_file(avatar_path(old_id)).await;
        }
    }
    Ok(Json(updated.into()))
}

pub async fn remove(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
) -> Result<Json<ProfileView>, StatusCode> {
    if !state.abuse.allow("avatar_delete", &account.id.to_string(), 60, 12).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let old_url = account.avatar_url.clone();
    let mut model: user::ActiveModel = account.into();
    model.avatar_url = Set(None);
    model.updated_at = Set(Utc::now());
    let updated = model.update(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(old_id) = old_url.as_deref()
        .and_then(|url| stored_avatar_id(url, &state.security.origin))
    {
        let _ = tokio::fs::remove_file(avatar_path(old_id)).await;
    }
    Ok(Json(updated.into()))
}

pub async fn image(Path(file): Path<String>) -> Result<Response, StatusCode> {
    let stem = file.strip_suffix(".webp").ok_or(StatusCode::NOT_FOUND)?;
    let id = Uuid::parse_str(stem).map_err(|_| StatusCode::NOT_FOUND)?;
    if id.to_string() != stem {
        return Err(StatusCode::NOT_FOUND);
    }
    let bytes = tokio::fs::read(avatar_path(id))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(([(header::CONTENT_TYPE, "image/webp")], bytes).into_response())
}

#[cfg(test)]
mod tests {
    use super::{normalize, stored_avatar_id};
    use image::{DynamicImage, ImageFormat};
    use std::io::Cursor;

    #[test]
    fn only_server_owned_canonical_uuids_are_removable() {
        let id = uuid::Uuid::new_v4();
        let valid = format!("https://auth.example.test/media/avatars/{id}.webp");
        assert_eq!(stored_avatar_id(&valid, "https://auth.example.test"), Some(id));
        assert_eq!(stored_avatar_id(&valid, "https://other.example.test"), None);
        assert_eq!(stored_avatar_id("https://auth.example.test/media/avatars/../../bad.webp", "https://auth.example.test"), None);
    }

    #[test]
    fn corrupted_and_wrong_sized_images_are_rejected() {
        assert!(normalize(b"not an image").is_err());
        let mut encoded = Cursor::new(Vec::new());
        DynamicImage::new_rgba8(32, 32).write_to(&mut encoded, ImageFormat::WebP).unwrap();
        assert!(normalize(&encoded.into_inner()).is_err());
        let mut valid = Cursor::new(Vec::new());
        DynamicImage::new_rgba8(256, 256).write_to(&mut valid, ImageFormat::WebP).unwrap();
        assert!(normalize(&valid.into_inner()).is_ok());
    }
}
