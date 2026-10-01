use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "client_redirect_uris")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub client_id: Uuid,
    pub redirect_uri: String,
    
    #[sea_orm(belongs_to, from = "client_id", to = "id")]
    pub client: BelongsTo<super::client::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}