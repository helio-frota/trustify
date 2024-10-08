use crate::{
    graph::Graph,
    service::{Error, IngestorService},
};
use actix_web::{post, web, HttpResponse, Responder};
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::{IntoParams, OpenApi};

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// Limit of a single content entry (after decompression).
    pub dataset_entry_limit: usize,
}

/// mount the "ingestor" module
pub fn configure(
    svc: &mut web::ServiceConfig,
    config: Config,
    db: Database,
    storage: impl Into<DispatchBackend>,
) {
    let ingestor_service = IngestorService::new(Graph::new(db.clone()), storage);

    svc.app_data(web::Data::new(ingestor_service))
        .app_data(web::Data::new(config))
        .service(web::scope("/v1/dataset").service(upload));
}

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
}

#[derive(OpenApi)]
#[openapi(
    paths(upload),
    components(schemas(
        crate::common::Deprecation,
        crate::model::IngestResult,
        crate::service::dataset::DatasetIngestResult,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "advisory",
    operation_id = "uploadDataset",
    context_path = "/api/v1/dataset",
    request_body = Vec<u8>,
    params(UploadParams),
    responses(
        (status = 201, description = "Uploaded the dataset"),
        (status = 400, description = "The file could not be parsed as an dataset"),
    )
)]
#[post("")]
/// Upload a new dataset
pub async fn upload(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    web::Query(UploadParams { labels }): web::Query<UploadParams>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let result = service
        .ingest_dataset(&bytes, labels, config.dataset_entry_limit)
        .await?;
    Ok(HttpResponse::Created().json(result))
}
