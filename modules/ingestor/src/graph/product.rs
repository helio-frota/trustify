use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use trustify_common::db::Transactional;
use trustify_entity::product;

use crate::graph::{error::Error, Graph};

pub struct ProductContext<'g> {
    graph: &'g Graph,
    pub product: product::Model,
}

impl<'g> ProductContext<'g> {
    pub fn new(graph: &'g Graph, product: product::Model) -> Self {
        Self { graph, product }
    }
}

#[derive(Clone, Default)]
pub struct ProductInformation {
    pub vendor: Option<String>,
}

impl ProductInformation {
    pub fn has_data(&self) -> bool {
        self.vendor.is_some()
    }
}

impl From<()> for ProductInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

impl super::Graph {
    pub async fn ingest_product<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String>,
        information: impl Into<ProductInformation>,
        tx: TX,
    ) -> Result<ProductContext, Error> {
        let name = name.into();
        let information = information.into();

        let vendor = if let Some(vendor) = information.vendor {
            Some(self.ingest_organization(vendor, (), &tx).await?)
        } else {
            None
        };

        let entity = product::ActiveModel {
            id: Default::default(),
            name: Set(name),
            vendor_id: Set(vendor.map(|org| org.organization.id)),
        };

        Ok(ProductContext::new(
            self,
            entity.insert(&self.connection(&tx)).await?,
        ))
    }

    pub async fn get_product_by_name<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String>,
        tx: TX,
    ) -> Result<Option<ProductContext>, Error> {
        Ok(product::Entity::find()
            .filter(product::Column::Name.eq(name.into()))
            .one(&self.connection(&tx))
            .await?
            .map(|product| ProductContext::new(self, product)))
    }    
}


#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::{test::TrustifyContext, Transactional};

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(actix_web::test)]
    async fn all_products(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);
    
        system
            .ingest_product("Trusted Profile Analyzer", (),).await?;
    
        Ok(())
    }    
}