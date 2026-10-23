use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub user_id: Uuid,

    pub token_hash: Vec<u8>,

    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
    pub last_use: DateTimeUtc,
    pub active: bool,

    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: BelongsTo<super::user::Entity>
}

impl ActiveModelBehavior for ActiveModel {}