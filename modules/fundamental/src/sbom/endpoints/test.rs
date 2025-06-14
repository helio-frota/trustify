use crate::{
    sbom::model::{SbomPackage, SbomSummary},
    test::{caller, label::Api},
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use std::io::Read;
use test_context::test_context;
use test_log::test;
use trustify_common::{id::Id, model::PaginatedResults};
use trustify_module_ingestor::{model::IngestResult, service::Format};
use trustify_test_context::{
    TrustifyContext, call::CallService, document_bytes, subset::ContainsSubset,
};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn fetch_unique_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/all-license-ids");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    let expected_result = &vec![
        "Apache-2.0".to_string(),
        "BSD-2-Clause".to_string(),
        "BSD-2-Clause-Views".to_string(),
        "BSD-3-Clause".to_string(),
        "BSD-3-Clause-Clear".to_string(),
        "CC-BY-SA-4.0".to_string(),
        "CC0-1.0".to_string(),
        "CDDL-1.0".to_string(),
        "CDDL-1.1".to_string(),
        "EPL-1.0".to_string(),
        "GPL-2.0-only".to_string(),
        "ISC".to_string(),
        "JSON".to_string(),
        "LGPL-3.0-or-later".to_string(),
        "MIT".to_string(),
        "MPL-1.0".to_string(),
        "MPL-2.0".to_string(),
        "NOASSERTION".to_string(),
        "Python-2.0".to_string(),
        "Sendmail".to_string(),
        "Unlicense".to_string(),
        "WTFPL".to_string(),
        "Zlib".to_string(),
    ];
    match response {
        Value::Array(ref list) => {
            assert_eq!(expected_result, list);
        }
        _ => panic!("Incorrect response"),
    }
    log::debug!("{response:#?}");

    let id = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/all-license-ids");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    let expected_result = &vec![
        "Apache-2.0".to_string(),
        "BSD-2-Clause".to_string(),
        "BSD-3-Clause".to_string(),
        "CC0-1.0".to_string(),
        "EPL-1.0".to_string(),
        "EPL-2.0".to_string(),
        "GPL-2.0-with-classpath-exception".to_string(),
        "LGPL-2.1-only".to_string(),
        "MIT".to_string(),
        "MPL-2.0".to_string(),
        "Openfont-1.1".to_string(),
    ];
    match response {
        Value::Array(ref list) => {
            assert_eq!(expected_result, list);
        }
        _ => panic!("Incorrect response"),
    }
    log::debug!("{response:#?}");

    // properly formatted but not existent Id
    let req = TestRequest::get().uri("/api/v2/sbom/sha256:e5c850b67868563002801668950832278f8093308b3a3c57931f591442ed3160/all-license-ids").to_request();
    let response = app.call_service(req).await;
    assert_eq!(StatusCode::NOT_FOUND, response.status());

    // badly formatted Id
    let req = TestRequest::get()
        .uri("/api/v2/sbom/sha123:1234/all-license-ids")
        .to_request();
    let response = app.call_service(req).await;
    assert_eq!(StatusCode::BAD_REQUEST, response.status());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_packages_sbom_by_query(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?
        .id
        .to_string();

    async fn query_value(app: &impl CallService, id: &str, q: &str) -> Value {
        let uri = format!("/api/v2/sbom/{id}/packages?q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }

    let result: Value = query_value(&app, &id, "name~logback-core").await;
    let expected_result = json!({
        "items": [
            {
                "id": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                "name": "logback-core",
                "group": null,
                "version": "1.2.13",
                "purl": [
                    {
                        "uuid": "d09e1b8f-493c-5bf2-9bf9-e2b2bfe03c65",
                        "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                        "base": {
                            "uuid": "0bf904de-68cb-5c1b-910d-2fdc905dca4c",
                            "purl": "pkg:maven/ch.qos.logback/logback-core"
                        },
                        "version": {
                            "uuid": "35ebe249-9e92-58ea-b99c-70f451533bd7",
                            "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13",
                            "version": "1.2.13"
                        },
                        "qualifiers": {
                            "type": "jar"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "EPL-1.0"},
                    {"license_type": "declared", "license_name": "GNU Lesser General Public License"}
                ]
            }
        ],
        "total": 1
    });

    assert!(result.contains_subset(expected_result));
    let result: Value = query_value(&app, &id, "name~logback-cor&Text~EPL").await;
    let expected_result = json!({
        "items": [
            {
                "id": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                "name": "logback-core",
                "group": null,
                "version": "1.2.13",
                "purl": [
                    {
                        "uuid": "d09e1b8f-493c-5bf2-9bf9-e2b2bfe03c65",
                        "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                        "base": {
                            "uuid": "0bf904de-68cb-5c1b-910d-2fdc905dca4c",
                            "purl": "pkg:maven/ch.qos.logback/logback-core"
                        },
                        "version": {
                            "uuid": "35ebe249-9e92-58ea-b99c-70f451533bd7",
                            "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13",
                            "version": "1.2.13"
                        },
                        "qualifiers": {
                            "type": "jar"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "EPL-1.0"}
                ]
            }
        ],
        "total": 1
    });
    assert!(result.contains_subset(expected_result));

    let id = ctx
        .ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?
        .id
        .to_string();

    let result = query_value(&app, &id, "name=rubygem-coffee-script").await;
    let expected_result = json!({
        "items": [
            {
                "id": "SPDXRef-02be9b35-a6ca-47b5-9c9e-9098c00ae212",
                "name": "rubygem-coffee-script",
                "group": null,
                "version": "2.4.1-5.el8sat",
                "purl": [
                    {
                        "uuid": "2ecff62f-9726-50fc-84b6-d191df754b21",
                        "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat?arch=noarch",
                        "base": {
                            "uuid": "4b2847bd-1178-5394-9cda-7c0c5229eaba",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script"
                        },
                        "version": {
                            "uuid": "b39cd776-c23d-597f-a2e6-4d49f8216e1e",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat",
                            "version": "2.4.1-5.el8sat"
                        },
                        "qualifiers": {
                            "arch": "noarch"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "MIT"},
                    {"license_type": "concluded", "license_name": "MIT"}
                ]
            },
            {
                "id": "SPDXRef-9fe51d0d-aec8-4a70-9bf0-70b60606632d",
                "name": "rubygem-coffee-script",
                "group": null,
                "version": "2.4.1-5.el8sat",
                "purl": [
                    {
                        "uuid": "ebfe4205-23c4-56b3-8c94-473bfe70cc81",
                        "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat?arch=src",
                        "base": {
                            "uuid": "4b2847bd-1178-5394-9cda-7c0c5229eaba",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script"
                        },
                        "version": {
                            "uuid": "b39cd776-c23d-597f-a2e6-4d49f8216e1e",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat",
                            "version": "2.4.1-5.el8sat"
                        },
                        "qualifiers": {
                            "arch": "src"
                        }
                    }
                ],
                "cpe": [
                    "cpe:/a:redhat:satellite:6.15:*:el8:*",
                    "cpe:/a:redhat:satellite:6.11:*:el8:*",
                    "cpe:/a:redhat:satellite:6.14:*:el8:*",
                    "cpe:/a:redhat:satellite:6.12:*:el8:*",
                    "cpe:/a:redhat:satellite:6.13:*:el8:*"
                ],
                "licenses": [
                    {"license_type": "declared", "license_name": "MIT"},
                    {"license_type": "concluded", "license_name": "MIT"}
                ]
            }
        ],
        "total": 2
    });
    assert!(result.contains_subset(expected_result));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn license_export(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/license-export");
    let req = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(req).await;

    assert!(response.status().is_success());
    let content_type = response
        .headers()
        .get("Content-Type")
        .expect("Content-Type header missing");
    assert_eq!(content_type, "application/gzip");

    let body = actix_web::test::read_body(response).await;
    let mut decoder = GzDecoder::new(&body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    assert!(decompressed.contains("spring-petclinic_license_ref.csv"));
    assert!(decompressed.contains("spring-petclinic_sbom_licenses.csv"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v2/sbom")
        .set_payload(document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    log::debug!("ID: {result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("spdx/quarkus-bom-3.2.11.Final-redhat-00001.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v2/sbom/{id}");
    let req = TestRequest::get().uri(&uri).to_request();
    let sbom: Value = app.call_and_read_body_json(req).await;
    log::debug!("{sbom:#?}");

    // assert expected fields
    assert_eq!(sbom["id"], id);
    assert_eq!(sbom["number_of_packages"], 1053);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn filter_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?
        .id
        .to_string();

    async fn query(app: &impl CallService, id: &str, q: &str) -> PaginatedResults<SbomPackage> {
        let uri = format!("/api/v2/sbom/{id}/packages?q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }

    let result = query(&app, &id, "").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "netty-common").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].name, "netty-common");

    let result = query(&app, &id, r"type\=jar").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "version=4.1.105.Final").await;
    assert_eq!(result.total, 9);

    Ok(())
}

/// Test updating labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels(
        ctx,
        Api::Sbom,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        "spdx",
    )
    .await
}

/// Test updating labels, for a document that does not exist
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels_not_found(
        ctx,
        Api::Sbom,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
    )
    .await
}

/// Test deleting an sbom
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/sbom/{}", result.id.clone()))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // We get the old sbom back when a delete succeeds
    let doc: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(doc["id"], result.id.to_string().as_ref());

    // If we try again, we should get a 404 since it was deleted.
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/sbom/{}", result.id.clone()))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

/// Test fetching an sbom
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const FILE: &str = "quarkus-bom-2.13.8.Final-redhat-00004.json";
    let app = caller(ctx).await?;
    let bytes = document_bytes(FILE).await?;
    let result = ctx.ingest_document(FILE).await?;
    let id = result.id.to_string();

    let req = TestRequest::get()
        .uri(&format!("/api/v2/sbom/{id}"))
        .to_request();

    let sbom = app.call_and_read_body_json::<SbomSummary>(req).await;
    assert_eq!(Id::Uuid(sbom.head.id), result.id);

    assert!(sbom.source_document.is_some());
    let doc = sbom.source_document.unwrap();

    let hashes = vec![doc.sha256, doc.sha384, doc.sha512];

    // Verify we can download by all hashes
    for hash in hashes {
        let req = TestRequest::get()
            .uri(&format!("/api/v2/sbom/{hash}/download"))
            .to_request();
        let body = app.call_and_read_body(req).await;
        assert_eq!(bytes, body);
    }

    // Verify we can download by uuid
    let req = TestRequest::get()
        .uri(&format!("/api/v2/sbom/{id}/download"))
        .to_request();
    let body = app.call_and_read_body(req).await;
    assert_eq!(bytes, body);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let id = ctx
        .ingest_documents([
            "quarkus-bom-2.13.8.Final-redhat-00004.json",
            "csaf/cve-2023-0044.json",
        ])
        .await?[0]
        .id
        .to_string();

    let app = caller(ctx).await?;
    let v: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v2/sbom/{id}/advisory"))
                .to_request(),
        )
        .await;

    log::debug!("{v:#?}");

    // assert expected fields
    assert_eq!(v[0]["identifier"], "https://www.redhat.com/#CVE-2023-0044");
    assert_eq!(v[0]["status"][0]["average_severity"], "medium");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_ingested_time(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn query(app: &impl CallService, q: &str) -> Value {
        let uri = format!(
            "/api/v2/sbom?q={}&sort={}",
            urlencoding::encode(q),
            urlencoding::encode("ingested:desc")
        );
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }
    let app = caller(ctx).await?;

    // Ingest 2 sbom's, capturing the time between each ingestion
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
    let t = chrono::Local::now().to_rfc3339();
    ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let all = query(&app, "ingested>yesterday").await;
    let ubi = query(&app, &format!("ingested<{t}")).await;
    let zoo = query(&app, &format!("ingested>{t}")).await;

    log::debug!("{all:#?}");

    // assert expected fields
    assert_eq!(all["total"], 2);
    assert_eq!(all["items"][0]["name"], json!("zookeeper"));
    assert_eq!(all["items"][1]["name"], json!("ubi9-container"));
    assert_eq!(ubi["total"], 1);
    assert_eq!(ubi["items"][0]["name"], json!("ubi9-container"));
    assert_eq!(zoo["total"], 1);
    assert_eq!(zoo["items"][0]["name"], json!("zookeeper"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_label(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |total, q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/sbom?q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        assert_eq!(total, response["total"], "for {q}");
    };
    ctx.ingest_document_as(
        "zookeeper-3.9.2-cyclonedx.json",
        Format::CycloneDX,
        [
            ("type", "cyclonedx"),
            ("source", "test"),
            ("importer", "none"),
            ("file", "zoo.json"),
            ("datasetFile", "none"),
            ("foo", "bar"),
        ],
    )
    .await?;
    ctx.ingest_document_as(
        "spdx/openssl-3.0.7-18.el9_2.spdx.json",
        Format::SPDX,
        [
            ("type", "spdx"),
            ("source", "test"),
            ("importer", "some"),
            ("file", "openssl.json"),
            ("datasetFile", "zilch"),
            ("foo", "baz"),
        ],
    )
    .await?;

    query(0, "labels:type=spdx&labels:type=cyclonedx").await;
    query(0, "labels:type!=spdx&labels:type!=cyclonedx").await;
    query(0, "labels:type!=spdx|cyclonedx").await;
    query(2, "labels:type=spdx|cyclonedx").await;
    query(1, "labels:type!=spdx").await;
    query(1, "labels:type~clone").await;
    query(1, "labels:type=cyclonedx").await;
    query(1, "labels:type=cyclonedx&labels:source=test").await;
    query(
        1,
        "labels:type=cyclonedx&labels:source=test&labels:importer=none",
    )
    .await;
    query(
        1,
        "labels:type=cyclonedx&labels:source=test&labels:importer=none&labels:file=zoo.json",
    )
    .await;
    query(1, "labels:type=cyclonedx&labels:source=test&labels:importer=none&labels:file=zoo.json&labels:datasetFile=none").await;
    query(2, "labels:file>foo.json").await;
    query(1, "labels:file>poo.json").await;
    query(1, "labels:datasetFile<zilch").await;
    query(1, "label:foo=bar").await;
    query(1, "label:type=cyclonedx").await;
    query(2, "label:importer=some|none").await;
    query(1, "label:type!=spdx").await;
    query(1, "labels:type~one&labels:foo>aah").await;
    query(1, "labels:importer~one&label:file~zoo").await;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |purl, sort| {
        let app = caller(ctx).await.unwrap();
        let uri = format!(
            "/api/v2/sbom/by-package?purl={}&sort={}",
            encode(purl),
            encode(sort)
        );
        let request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");
        response
    };

    // Ingest 2 SBOM's that depend on the same purl
    ctx.ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;

    assert_eq!(
        2,
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "").await["total"]
    );
    assert_eq!(
        "simple-a",
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "name:asc").await["items"][0]["name"]
    );
    assert_eq!(
        "simple-b",
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "name:desc").await["items"][0]["name"]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_array_values(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        "spdx/rhelai1_binary.json",
    ])
    .await?;

    let query = async |expected_count, q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/sbom?q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(expected_count, response["total"], "for {q}");
    };

    query(1, "authors~syft").await;
    query(1, "authors~Product").await;
    query(2, "authors~Product|Tool").await;
    query(1, "suppliers~Red Hat&authors~Red Hat").await;
    query(1, "suppliers=Organization: Red Hat").await;
    query(1, "suppliers!=Organization: Red Hat&authors~syft").await;
    query(0, "authors<ZZZ").await;
    query(2, "authors>ZZZ").await;
    query(2, "organization").await;
    query(1, "tool: syft").await;

    Ok(())
}

async fn test_label(
    ctx: &TrustifyContext,
    query: &str,
    limit: impl Into<Option<u64>>,
    result: Value,
) -> anyhow::Result<()> {
    let app = caller(ctx).await.unwrap();

    let _id = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?
        .id
        .to_string();

    let mut uri = format!("/api/v2/sbom-labels?filter_text={}", encode(query));

    if let Some(limit) = limit.into() {
        uri.push_str(&format!("&limit={limit}"));
    }

    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(response, result,);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_label(
        ctx,
        "",
        None,
        json!([
            { "key": "source", "value": "TrustifyContext"},
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "spdx",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "pd",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "yp",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(ctx, "%", None, json!([])).await?;

    test_label(
        ctx,
        "",
        1u64,
        json!([
            { "key": "source", "value": "TrustifyContext"},
        ]),
    )
    .await?;

    Ok(())
}
