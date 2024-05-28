use actix_web::cookie::time::OffsetDateTime;
use trustify_module_ingestor::graph::product::ProductInformation;
use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::db::test::TrustifyContext;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_products(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    let service = crate::product::service::ProductService::new(db);

    let prods = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, prods.total);
    assert_eq!(1, prods.items.len());

    Ok(())
}
