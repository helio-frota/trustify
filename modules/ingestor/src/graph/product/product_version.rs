use std::fmt::{Debug, Formatter};

use trustify_entity as entity;
//use trustify_entity::product_version;

use super::ProductContext;

/// Live context for a product version.
#[derive(Clone)]
pub struct ProductVersionContext<'g> {
    pub product: ProductContext<'g>,
    pub product_version: entity::product_version::Model,
}

impl Debug for ProductVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.product_version.fmt(f)
    }
}

impl<'g> ProductVersionContext<'g> {
    pub fn new(product: &ProductContext<'g>, product_version: entity::product_version::Model) -> Self {
        Self {
            product: product.clone(),
            product_version,
        }
    }
}
