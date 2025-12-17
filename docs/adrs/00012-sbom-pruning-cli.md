# 00010. SBOM Pruning CLI Tool

## Status

PROPOSED

## Context

### Problem Statement

Production Trustify deployments contain millions of SBOMs, causing significant storage and database cost concerns. Currently, Trustify lacks:
- Bulk deletion capabilities
- Automated pruning mechanisms
- Tools for lifecycle management of SBOMs

### Current State

- **Delete API**: `DELETE /v2/sbom/{id}` supports single SBOM deletion only
- **Search API**: Supports date filtering (`ingested<30 days ago`) and label filtering
- **Gaps**: No batch operations, no CLI tooling, no automation

### Requirements

**Immediate need**: Manual tool for bulk SBOM deletion to reduce storage costs

**Future needs** (subsequent ADRs):
- Automated/scheduled pruning (Phase 2)
- Soft-delete and restore capabilities (Phase 3+)
- Policy-based lifecycle management (Phase 4+)

## Decision

### Create Separate CLI Binary: `trustify`

A new standalone binary for client-side operations, starting with SBOM pruning functionality.

### Architecture

**Binary Name:** `trustify`

**Initial Subcommand:** `trustify prune`

**Communication Pattern:**
- HTTP REST API calls to Trustify server
- Uses existing endpoints: `GET /v2/sbom`, `DELETE /v2/sbom/{id}`
- OIDC token authentication
- No direct database access

**Usage Examples:**
```bash
# Basic pruning
trustify prune --endpoint https://trustify.example.com \
  --filter "ingested<90 days ago&label:env=staging" \
  --token $TRUSTIFY_TOKEN

# Dry run mode
trustify prune --filter "ingested<90 days ago" --dry-run

# With logging
trustify prune --filter "..." --log-file pruning-$(date +%Y%m%d).log

# Batch control
trustify prune --filter "..." --batch-size 500 --max-concurrent 10
```

### Key Design Principles

1. **Client-Server Separation**: CLI is a thin client, all logic remains in server
2. **HTTP-Only Communication**: No direct database access, uses REST APIs
3. **Standard Authentication**: OIDC tokens via `Authorization` header
4. **Idempotent Operations**: Safe to retry, handles failures gracefully
5. **User Safety**: Dry-run by default, explicit confirmation for large deletions

## Consequences

### Benefits

1. **Immediate Value**: Solves storage cost problem without server changes
2. **Lightweight**: Users can install CLI without full trustd server
3. **Flexible Deployment**: Can run from any machine with API access
4. **Safe**: Dry-run mode and explicit confirmation prevent accidents
5. **Familiar Pattern**: Follows industry standards (kubectl, docker CLI)
6. **Future-Proof**: Foundation for additional client-side commands
7. **Testable**: Easy to test HTTP API integration

### Trade-offs

1. **Network Dependency**: Requires connectivity to Trustify server
2. **Performance**: HTTP calls slower than direct database access
3. **Authentication Burden**: Users must manage tokens
4. **No Atomic Batch**: Deletes SBOMs one-by-one (mitigated in Phase 3 with batch API)

### Risks and Mitigations

**Risk**: Accidental mass deletion
- **Mitigation**: Dry-run by default, require explicit `--yes` flag for operations >100 SBOMs

**Risk**: Network failures during long-running operations
- **Mitigation**: Implement retry logic, idempotent deletes, checkpoint progress

**Risk**: Token expiration during operation
- **Mitigation**: Token refresh support, clear error messages

## Implementation Details

### File Structure

```
trustify/                  # New binary
├── Cargo.toml
└── src/
    ├── main.rs           # CLI entry point with clap
    ├── commands/
    │   └── prune.rs      # Prune command implementation
    ├── client.rs         # HTTP client for Trustify API
    └── auth.rs           # OIDC token handling
```

### Command-Line Interface

```rust
// trustify/src/commands/prune.rs
#[derive(clap::Args)]
pub struct PruneArgs {
    /// Trustify API endpoint
    #[arg(long, env = "TRUSTIFY_ENDPOINT")]
    endpoint: String,

    /// Authentication token
    #[arg(long, env = "TRUSTIFY_TOKEN")]
    token: Option<String>,

    /// Filter query (e.g., "ingested<90 days ago")
    #[arg(long)]
    filter: String,

    /// Dry run - preview without deleting
    #[arg(long)]
    dry_run: bool,

    /// Skip confirmation prompt
    #[arg(long)]
    yes: bool,

    /// Log file path
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Batch size for pagination
    #[arg(long, default_value = "100")]
    batch_size: usize,

    /// Max concurrent deletions
    #[arg(long, default_value = "5")]
    max_concurrent: usize,
}
```

### Core Algorithm

1. Authenticate with Trustify API using OIDC token
2. Query SBOMs using filter: `GET /v2/sbom?q={filter}&limit={batch_size}&offset={offset}`
3. For dry-run: Display list of SBOMs that would be deleted, exit
4. If not dry-run and count > 100: Prompt for confirmation (unless `--yes`)
5. Delete SBOMs concurrently (up to max_concurrent): `DELETE /v2/sbom/{id}`
6. Track progress, log operations, handle errors
7. Display final summary

**Progress Tracking:**
- Use `indicatif` crate for progress bar
- Track: total found, deleted, failed, in-progress
- Write all operations to log file if specified

**Error Handling:**
- Retry transient HTTP errors (500, 502, 503, 504) with exponential backoff
- Continue on individual SBOM delete errors, collect for final report
- Checkpoint progress periodically for resume capability (future enhancement)

## Implementation Steps

1. **Project Setup** (`trustify/` directory)
   - Create binary structure
   - Add to workspace Cargo.toml
   - Setup clap CLI framework

2. **HTTP Client** (`client.rs`)
   - Implement Trustify API client
   - Authentication with Bearer tokens
   - Error handling and retries

3. **Prune Command** (`commands/prune.rs`)
   - Argument parsing
   - Query logic (`GET /v2/sbom`)
   - Delete logic (`DELETE /v2/sbom/{id}`)
   - Progress tracking
   - Logging

4. **Testing**
   - Unit tests
   - Integration tests with local trustd
   - Manual testing at scale

5. **Documentation**
   - README for trustify binary
   - Upstream documentation with usage examples
   - Troubleshooting guide

## Success Criteria

- [ ] Binary builds and runs on Linux, macOS, Windows
- [ ] Successfully authenticates to Trustify API
- [ ] Can query SBOMs with complex filters
- [ ] Dry-run mode shows accurate preview
- [ ] Can delete thousands of SBOMs reliably
- [ ] Progress tracking works correctly
- [ ] Handles errors gracefully with retry
- [ ] Log file contains complete audit trail
- [ ] Integration tests pass

## Future Work (Subsequent ADRs)

**Phase 2: Background Service**
- REST API for configuring pruning jobs: `/v2/sbom-pruning/`
- Background service with scheduling (following importer pattern)
- Database-backed job configuration
- Runs as `trustd prune-service`

**Phase 3: Batch Delete API**
- Server-side batch delete endpoint: `POST /v2/sbom/batch-delete`
- Improves performance vs individual deletes
- CLI can use this endpoint when available

**Phase 4+: Advanced Features**
- Soft-delete with restore capability
- Grace period (14 days, like Quay)
- Audit logging table
- Policy-based lifecycle management

## Related ADRs

- Future: ADR for Background Pruning Service (Phase 2)
- Future: ADR for Batch Delete API (Phase 3)
- Future: ADR for Soft Delete and Restore (Phase 4)
