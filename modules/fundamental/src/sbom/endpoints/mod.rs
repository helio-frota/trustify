mod label;
#[cfg(test)]
mod test;

use crate::sbom::model::{SbomPackageReference, Which};
use crate::sbom::service::SbomService;
use crate::Error;
use actix_web::{get, post, web, HttpResponse, Responder};
use futures_util::TryStreamExt;
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use tokio_util::io::ReaderStream;
use trustify_auth::authenticator::user::UserInformation;
use trustify_auth::authorizer::Authorizer;
use trustify_auth::Permission;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::error::ErrorInformation;
use trustify_common::id::Id;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_entity::relationship::Relationship;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::StorageBackend;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let sbom_service = SbomService::new(db);

    config
        .app_data(web::Data::new(sbom_service))
        .service(all)
        .service(all_related)
        .service(get)
        .service(packages)
        .service(related)
        .service(upload)
        .service(download)
        .service(label::set)
        .service(label::update);
}

#[derive(OpenApi)]
#[openapi(
    paths(
        all,
        all_related,
        get,
        packages,
        related,
        upload,
        download,
        label::set,
        label::update,
    ),
    components(schemas(
        crate::sbom::model::PaginatedSbomPackage,
        crate::sbom::model::PaginatedSbomPackageRelation,
        crate::sbom::model::PaginatedSbomSummary,
        crate::sbom::model::SbomPackage,
        crate::sbom::model::SbomPackageRelation,
        crate::sbom::model::SbomSummary,
        crate::sbom::model::Which,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::purl::Purl,
        trustify_common::id::Id,
        trustify_entity::relationship::Relationship,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/v1/sbom")]
pub async fn all(
    fetch: web::Data<SbomService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch.fetch_sboms(search, paginated, (), ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct AllRelatedQuery {
    /// Find by PURL
    #[serde(default)]
    pub purl: Option<Purl>,
    /// Find by a ID of a package
    #[serde(default)]
    pub id: Option<Uuid>,
}

/// Find all SBOMs containing the provided package.
///
/// The package can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        Query,
        Paginated,
        AllRelatedQuery,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/v1/sbom/by-package")]
pub async fn all_related(
    sbom: web::Data<SbomService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(all_related): web::Query<AllRelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = match (&all_related.purl, &all_related.id) {
        (Some(purl), None) => purl.qualifier_uuid(),
        (None, Some(id)) => *id,
        _ => {
            return Ok(HttpResponse::BadRequest().json(ErrorInformation {
                error: "IdOrPurl".into(),
                message: "Requires either `purl` or `id`".to_string(),
                details: Some(format!(
                    "Received - PURL: {:?}, ID: {:?}",
                    all_related.purl, all_related.id
                )),
            }));
        }
    };

    let result = sbom.find_related_sboms(id, paginated, search, ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        ("id" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[get("/v1/sbom/{id}")]
pub async fn get(
    fetcher: web::Data<SbomService>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = Id::from_str(&id).map_err(Error::HashKey)?;
    match fetcher.fetch_sbom(id, ()).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

/// Search for packages of an SBOM
#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackage),
    ),
)]
#[get("/v1/sbom/{id}/packages")]
pub async fn packages(
    fetch: web::Data<SbomService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, ())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Option<String>,
    /// Which side the reference should be on
    #[serde(default)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        ("id", Path, description = "ID of SBOM to search packages in"),
        RelatedQuery,
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackageRelation),
    ),
)]
#[get("/v1/sbom/{id}/related")]
pub async fn related(
    fetch: web::Data<SbomService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = id.into_inner();

    let result = fetch
        .fetch_related_packages(
            id,
            search,
            paginated,
            related.which,
            match &related.reference {
                None => SbomPackageReference::Root,
                Some(id) => SbomPackageReference::Package(id),
            },
            related.relationship,
            (),
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    request_body = Vec <u8>,
    params(
        ("location" = String, Query, description = "Source the document came from"),
    ),
    responses(
        (status = 201, description = "Upload an SBOM"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/v1/sbom")]
/// Upload a new SBOM
pub async fn upload(
    service: web::Data<IngestorService>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let fmt = Format::from_bytes(&bytes)?;
    let payload = ReaderStream::new(&*bytes);

    let result = service
        .ingest(("source", "rest-api"), None, fmt, payload)
        .await?;
    Ok(HttpResponse::Created().json(result))
}

#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    params(
        ("key" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>'"),
    ),
    responses(
        (status = 200, description = "Download a an SBOM", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v1/sbom/{key}/download")]
pub async fn download(
    ingestor: web::Data<IngestorService>,
    sbom: web::Data<SbomService>,
    key: web::Path<String>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&key).map_err(Error::HashKey)?;

    let Some(sbom) = sbom.fetch_sbom(id, ()).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let stream = ingestor
        .storage()
        .clone()
        .retrieve(sbom.hashes.try_into()?)
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}
