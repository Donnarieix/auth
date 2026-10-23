use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "clients")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub client_id: String,
    pub name: String,
    pub created_at: DateTimeUtc,
    pub active: bool,

    #[sea_orm(has_many)]
    pub redirect_uris: HasMany<super::client_redirect_uri::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}