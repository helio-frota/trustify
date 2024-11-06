use crate::graph::purl::creator::PurlCreator;
use crate::graph::sbom::{LicenseCreator, LicenseInfo, SbomContext, SbomInformation};
use sea_orm::{EntityTrait, Set};
use sea_query::OnConflict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_common::purl::Purl;
use trustify_entity::purl_license_assertion;

impl SbomContext {
    #[instrument(skip(tx, curation), err)]
    pub async fn ingest_clearly_defined_curation<TX: AsRef<Transactional>>(
        &self,
        curation: Curation,
        tx: TX,
    ) -> Result<(), anyhow::Error> {
        let db = &self.graph.db.connection(&tx);

        let mut purls = PurlCreator::new();
        let mut licenses = LicenseCreator::new();

        let mut assertions = Vec::new();

        for (purl, license) in curation.iter() {
            let license_info = LicenseInfo {
                license: license.clone(),
                refs: Default::default(),
            };

            assertions.push(purl_license_assertion::ActiveModel {
                id: Default::default(),
                license_id: Set(license_info.uuid()),
                versioned_purl_id: Set(purl.version_uuid()),
                sbom_id: Set(self.sbom.sbom_id),
            });

            purls.add(purl);
            licenses.add(&license_info);
        }

        purls.create(db).await?;
        licenses.create(db).await?;

        purl_license_assertion::Entity::insert_many(assertions)
            .on_conflict(
                OnConflict::columns([
                    purl_license_assertion::Column::SbomId,
                    purl_license_assertion::Column::LicenseId,
                    purl_license_assertion::Column::VersionedPurlId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .do_nothing()
            .exec(db)
            .await?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Curation {
    pub coordinates: Coordinates,
    pub revisions: HashMap<String, Revision>,
}

impl Curation {
    pub fn document_id(&self) -> String {
        self.coordinates.document_id()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Purl, String)> + '_ {
        self.revisions.iter().flat_map(|(version, details)| {
            if let Some(licensed) = &details.licensed {
                let mut purl = self.coordinates.base_purl();
                purl.version = Some(version.clone());
                Some((purl, licensed.declared.clone()))
            } else {
                None
            }
        })
    }
}

#[allow(clippy::from_over_into)]
impl Into<SbomInformation> for &Curation {
    fn into(self) -> SbomInformation {
        SbomInformation {
            node_id: self.document_id(),
            name: self.coordinates.base_purl().to_string(),
            published: None,
            authors: vec!["ClearlyDefined: Community-Curated".to_string()],
            data_licenses: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Coordinates {
    pub provider: String,
    pub name: String,
    pub namespace: Option<String>,
    pub r#type: String,
}

impl Coordinates {
    pub fn base_purl(&self) -> Purl {
        Purl {
            ty: self.r#type.clone(),
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            version: None,
            qualifiers: Default::default(),
        }
    }

    pub fn document_id(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.r#type,
            self.provider,
            self.namespace.as_ref().unwrap_or(&"-".to_string()),
            self.name
        )
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Revision {
    pub licensed: Option<Licensed>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Licensed {
    pub declared: String,
}