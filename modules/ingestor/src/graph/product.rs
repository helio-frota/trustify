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

impl super::Graph {
    pub async fn ingest_product<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String>,
        tx: TX,
    ) -> Result<ProductContext, Error> {
        let name = name.into();
        let entity = product::ActiveModel {
            id: Default::default(),
            name: Set(name),
        };

        Ok(ProductContext::new(
            self,
            entity.insert(&self.connection(&tx)).await?,
        ))
    }
}
