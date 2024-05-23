use actix_web::cookie::time::OffsetDateTime;
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
        .ingest_product("Red Hat Trusted Profile Analyzer", (),).await?;

    Ok(())
}
