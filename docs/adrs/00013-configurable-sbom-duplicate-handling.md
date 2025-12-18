# 00011. Configurable SBOM Duplicate Handling

## Status

PROPOSED

## Context

### Problem Statement

Trustify currently uses hash-based deduplication (SHA256/384/512) to detect duplicate SBOMs. However, SBOM documents have stable identifiers (`documentNamespace` for SPDX, `serialNumber` for CycloneDX) that uniquely identify them regardless of minor content changes.

**Current Limitation**: When an SBOM is regenerated with the same identifier but different content (e.g., updated timestamps), it's ingested as a new document.

### Use Cases

Different scenarios require different duplicate handling behaviors:

1. **Audit/Compliance**: Keep all versions for historical tracking
2. **Latest-only**: Replace old versions to save storage and show current state
3. **Deduplication**: Ignore re-ingestion of documents with the same identifier

## Decision

Add configurable duplicate handling with three modes based on SBOM document identifiers:

### Duplicate Handling Modes

**`onDuplicate=ingest`** (default)
- Ingest as new document (current behavior)
- Hash-based deduplication still applies
- Backward compatible

**`onDuplicate=ignore`**
- Skip ingestion if SBOM with same document_id already exists
- Return existing SBOM information
- Useful for preventing re-ingestion of unchanged documents

**`onDuplicate=replace`**
- Delete existing SBOM with same document_id
- Ingest new version
- Maintains latest-only view

## Configuration

### 1. API Upload (Per-Request)

Add optional `onDuplicate` query parameter to SBOM upload endpoint:

```bash
# Ignore duplicates - skip if already exists
cat sbom.json | http POST localhost:8080/api/v2/sbom onDuplicate=ignore

# Replace existing - delete old, ingest new
cat sbom-v2.json | http POST localhost:8080/api/v2/sbom onDuplicate=replace

# Ingest as new (default) - current behavior
cat sbom.json | http POST localhost:8080/api/v2/sbom
```

### 2. Importer Configuration (Per-Importer)

Add `onDuplicate` field to SBOM importer configuration:

```bash
# Ignore duplicates during scheduled imports
http POST localhost:8080/api/v2/importer/my-sbom-source \
  sbom[source]=https://example.com/sboms/ \
  sbom[onDuplicate]=ignore \
  sbom[period]=1d

# Replace with latest version
http POST localhost:8080/api/v2/importer/internal-builds \
  sbom[source]=https://builds.internal/sboms/ \
  sbom[onDuplicate]=replace \
  sbom[period]=1h
```

## How It Works

### Duplicate Detection

1. Extract document identifier from SBOM:
   - **SPDX**: `documentNamespace` field
   - **CycloneDX**: `serialNumber` field

2. Check database for existing SBOM with same identifier

3. Apply configured behavior:
   - **`ingest`**: Continue normal ingestion (hash-based dedup still applies)
   - **`ignore`**: Skip ingestion, return existing SBOM info
   - **`replace`**: Delete old SBOM and storage, then ingest new version

### Implementation Scope

**Core Components**:
- IngestorService: Add `onDuplicate` parameter to `ingest()` method
- Graph layer: Add `get_sbom_by_document_id()` lookup function
- API endpoints: Add `onDuplicate` query parameter
- Importer config: Add `onDuplicate` field to SbomImporter

## Benefits

- ✓ Flexible handling for different use cases (audit, latest-only, deduplication)
- ✓ Backward compatible (defaults to current behavior)
- ✓ Configurable per-importer and per-upload
- ✓ Works for both SPDX and CycloneDX formats
- ✓ Prevents storage waste from duplicate documents

## Considerations

**Logging**: All duplicate handling actions are logged for audit trail

**Atomicity**: Replace operations should ensure atomicity

## Open Questions

1. Should `replace` mode preserve user-added labels from the old SBOM?
