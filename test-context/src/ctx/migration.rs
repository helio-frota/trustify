use crate::{TrustifyTestContext, migration::Migration};
use anyhow::Context;
use std::ops::Deref;
use tar::Archive;
use test_context::AsyncTestContext;
use trustify_db::embedded::{Options, Source, default_settings};
use trustify_module_storage::service::fs::FileSystemBackend;

/// Creates a database and imports the previous DB and storage dump.
pub struct TrustifyMigrationContext(pub(crate) TrustifyTestContext);

impl Deref for TrustifyMigrationContext {
    type Target = TrustifyTestContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TrustifyMigrationContext {
    pub async fn new() -> anyhow::Result<Self> {
        let migration = Migration::new().expect("failed to create migration manager");
        let base = migration.provide().await?;

        // create storage

        let (storage, tmp) = FileSystemBackend::for_test()
            .await
            .expect("Unable to create storage backend");

        let mut archive = Archive::new(
            std::fs::File::open(base.join("dump.tar")).context("failed to open storage dump")?,
        );
        archive
            .unpack(tmp.path())
            .context("failed to unpack storage dump")?;

        // create DB

        let settings = default_settings().context("unable to create default settings")?;

        let (db, postgresql) = trustify_db::embedded::create_for(
            settings,
            Options {
                source: Source::Import(base.join("dump.sql.xz")),
            },
        )
        .await
        .context("failed to create an embedded database")?;

        Ok(Self(
            TrustifyTestContext::new(db, storage, tmp, postgresql).await,
        ))
    }
}

impl AsyncTestContext for TrustifyMigrationContext {
    async fn setup() -> Self {
        TrustifyMigrationContext::new()
            .await
            .expect("failed to create migration context")
    }
}
