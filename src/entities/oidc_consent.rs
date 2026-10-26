use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "oidc_consents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scope: String,
    pub approved_at: DateTimeUtc,
    pub revoked_at: Option<DateTimeUtc>,

    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: BelongsTo<super::user::Entity>,
    #[sea_orm(belongs_to, from = "client_id", to = "id")]
    pub client: BelongsTo<super::client::Entity>,
}
impl ActiveModelBehavior for ActiveModel {}
