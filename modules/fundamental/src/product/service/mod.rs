use crate::Error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::product;

use super::model::ProductSummary;

pub struct ProductService {
    db: Database,
}

impl ProductService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn fetch_products<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        search: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<ProductSummary>, Error> {
        let connection = self.db.connection(&tx);
    
        let limiter = product::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );
    
        let total = limiter.total().await?;
    
        Ok(PaginatedResults {
            total,
            items: ProductSummary::from_entities(&limiter.fetch().await?, &connection).await?,
        })
    }

    // pub async fn fetch_organization<TX: AsRef<Transactional> + Sync + Send>(
    //     &self,
    //     id: i32,
    //     tx: TX,
    // ) -> Result<Option<OrganizationDetails>, Error> {
    //     let connection = self.db.connection(&tx);

    //     if let Some(organization) = organization::Entity::find()
    //         .filter(organization::Column::Id.eq(id))
    //         .one(&connection)
    //         .await?
    //     {
    //         Ok(Some(
    //             OrganizationDetails::from_entity(&organization, &connection).await?,
    //         ))
    //     } else {
    //         Ok(None)
    //     }
    // }
}

#[cfg(test)]
mod test;