use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "authorization_codes")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub code_hash: Vec<u8>,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub audience: Option<String>,
    pub resource_scope: Option<String>,
    pub nonce: String,
    pub code_challenge: String,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
    pub consumed_at: Option<DateTimeUtc>,

    #[sea_orm(belongs_to, from = "client_id", to = "id")]
    pub client: BelongsTo<super::client::Entity>,
    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: BelongsTo<super::user::Entity>,
    #[sea_orm(belongs_to, from = "session_id", to = "id")]
    pub session: BelongsTo<super::session::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
