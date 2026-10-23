use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    pub email_verified: bool,
    #[sea_orm(unique)]
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub active: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,

    #[sea_orm(has_many)]
    pub password_credentials: HasMany<super::password_credential::Entity>,
    #[sea_orm(has_many)]
    pub sessions: HasMany<super::session::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
