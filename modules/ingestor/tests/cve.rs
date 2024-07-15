#![allow(clippy::expect_used)]

use anyhow::bail;
use test_context::test_context;
use test_log::test;
use trustify_common::id::Id;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_cve(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // ingest once

    let result = ctx.ingest_document("cve/CVE-2021-32714.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let adv = ctx
        .graph
        .get_advisory_by_id(id, ())
        .await?
        .expect("must be found");
    let vuln = ctx
        .graph
        .get_vulnerability("CVE-2021-32714", ())
        .await?
        .expect("Must be found");

    let descriptions = vuln.descriptions("en", ()).await?;

    assert_eq!(descriptions.len(), 1);
    assert_eq!(adv.vulnerabilities(()).await?.len(), 1);

    // ingest second time

    let result = ctx.ingest_document("cve/CVE-2021-32714.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let adv = ctx
        .graph
        .get_advisory_by_id(id, ())
        .await?
        .expect("must be found");
    let vuln = ctx
        .graph
        .get_vulnerability("CVE-2021-32714", ())
        .await?
        .expect("Must be found");

    let descriptions = vuln.descriptions("en", ()).await?;

    // must still be one

    assert_eq!(descriptions.len(), 1);
    assert_eq!(adv.vulnerabilities(()).await?.len(), 1);

    // done

    Ok(())
}