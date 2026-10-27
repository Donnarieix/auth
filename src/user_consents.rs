//! End-user, self-service view and revocation of previously approved OIDC clients.
//! The user is set by the existing session-authentication middleware, never
//! supplied by a request body or query parameter.
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, TransactionTrait, sea_query::Expr};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    entities::{client, oidc_access_token, oidc_consent, user},
    state::AppState,
};

#[derive(Serialize)]
pub struct ConsentView {
    client_id: String,
    name: String,
    scope: String,
    approved_at: chrono::DateTime<Utc>,
}

pub async fn list(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
) -> Result<Json<Vec<ConsentView>>, StatusCode> {
    let consents = oidc_consent::Entity::find()
        .filter(oidc_consent::COLUMN.user_id.eq(account.id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut entries = Vec::with_capacity(consents.len());
    for consent in consents {
        if let Some(app) = client::Entity::find_by_id(consent.client_id)
            .one(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            entries.push(ConsentView {
                client_id: app.client_id,
                name: app.name,
                scope: consent.scope,
                approved_at: consent.approved_at,
            });
        }
    }
    Ok(Json(entries))
}

/// Immediately invalidate the consent and every outstanding access token for
/// that user/client. Only the authenticated user's own grants can be revoked.
pub async fn revoke(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
    Path(public_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let app = client::Entity::find()
        .filter(client::COLUMN.client_id.eq(&public_id))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = Utc::now();
    let affected = oidc_consent::Entity::update_many()
        .col_expr(oidc_consent::COLUMN.revoked_at, Expr::value(now))
        .filter(oidc_consent::COLUMN.user_id.eq(account.id))
        .filter(oidc_consent::COLUMN.client_id.eq(app.id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if affected.rows_affected == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    oidc_access_token::Entity::update_many()
        .col_expr(oidc_access_token::COLUMN.revoked, Expr::value(true))
        .filter(oidc_access_token::COLUMN.user_id.eq(account.id))
        .filter(oidc_access_token::COLUMN.client_id.eq(app.id))
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use chrono::{Duration, Utc};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait};
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        entities::{oidc_consent, session, user},
        oidc::consent,
        router, schema,
        services::{
            client::{ClientType, get_client, register_client},
            session::generate_token,
        },
        state::AppState,
    };

    #[tokio::test]
    async fn consent_controls_are_user_scoped_and_require_same_origin() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let now = Utc::now();
        let uid = Uuid::new_v4();
        user::ActiveModel {
            id: Set(uid),
            email: Set("owner@example.test".into()),
            email_verified: Set(true),
            username: Set("owner".into()),
            display_name: Set(None),
            avatar_url: Set(None),
            active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .unwrap();
        let (token, hash) = generate_token();
        session::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(uid),
            token_hash: Set(hash),
            created_at: Set(now),
            expires_at: Set(now + Duration::minutes(30)),
            last_use: Set(now),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();
        let client_id = register_client(
            &db,
            "Consent Fixture",
            ClientType::Desktop,
            &["http://127.0.0.1:44220/callback".into()],
        )
        .await
        .unwrap();
        let app_row = get_client(&db, &client_id).await.unwrap().unwrap();
        consent::approve(&db, uid, app_row.id, "openid profile")
            .await
            .unwrap();

        let router = router(AppState::with_db(db.clone()));
        let cookie = format!("auth_session={token}");
        let listed = router.clone().oneshot(
            Request::builder().uri("/account/consents")
                .header(header::COOKIE, &cookie)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let blocked = router.clone().oneshot(
            Request::builder().method(Method::POST)
                .uri(format!("/account/consents/{client_id}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://evil.example")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let revoked = router.clone().oneshot(
            Request::builder().method(Method::POST)
                .uri(format!("/account/consents/{client_id}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1:3000")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let stored = oidc_consent::Entity::find().one(&db).await.unwrap().unwrap();
        assert!(stored.revoked_at.is_some());
        assert!(!consent::approved(&db, uid, app_row.id, "openid").await.unwrap());
        let second = router.oneshot(
            Request::builder().method(Method::POST)
                .uri(format!("/account/consents/{client_id}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1:3000")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
    }
}
