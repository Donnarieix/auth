use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub username: String,
    pub password: String,

    #[sea_orm(has_many)]
    pub sessions: HasMany<super::session::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}