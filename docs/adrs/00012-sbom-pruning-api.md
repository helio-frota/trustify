# 00012. SBOM Prune API Endpoint

## Status

PROPOSED

## Context

### Problem Statement

Production Trustify deployments contain millions of SBOMs, causing significant storage and database cost concerns. An external CLI tool ([Mobster](https://github.com/konflux-ci/mobster)) exists for bulk operations, but it requires:
- Direct server access or token management
- Manual execution
- No server-side tracking or logging

### Current State

- **External CLI**: Bulk pruning implemented in [Mobster](https://github.com/konflux-ci/mobster) (external project)
- **Delete API**: `DELETE /v2/sbom/{id}` supports single SBOM deletion only
- **Search API**: Supports date filtering (`ingested<30 days ago`) and label filtering
- **Gap**: No server-side bulk prune operation with tracking

### Requirements

- Server-side API endpoint for bulk SBOM pruning
- Reuse existing filter query syntax
- Safety by default (dry run mode)
- Audit logging for compliance
- Foundation for future scheduled pruning service

## Decision

Add a `POST /v2/sbom/prune` endpoint that executes pruning logic server-side.

## API Specification

### Endpoint

```
POST /v2/sbom/prune
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `q` | string | Yes | - | Filter query (e.g., `ingested<90 days ago&label:env=staging`) |
| `limit` | integer | No | 1000 | Maximum SBOMs to delete (safety limit) |
| `dry_run` | boolean | No | true | Preview mode - report without deleting |

### Response

```json
{
  "matched": 1523,
  "deleted": 1000,
  "failed": 0,
  "dry_run": false,
  "errors": []
}
```

In dry run mode, include preview of matched SBOMs (limited to first N items).

### Permission

Requires `DeleteSbom` permission (reuses existing permission).

## Usage Examples

```bash
# Preview SBOMs older than 90 days
http POST localhost:8080/api/v2/sbom/prune q=="ingested<90 days ago"

# Delete staging SBOMs older than 30 days
http POST localhost:8080/api/v2/sbom/prune \
  q=="ingested<30 days ago&label:env=staging" \
  dry_run:=false \
  limit:=5000

# Delete SBOMs with specific label
http POST localhost:8080/api/v2/sbom/prune \
  q=="label:temporary=true" \
  dry_run:=false
```

## Safety Features

1. **Dry run default**: `dry_run=true` prevents accidental deletions
2. **Limit cap**: Server-enforced maximum per request
3. **Filter required**: No "delete all" without explicit filter
4. **Permission check**: Requires `DeleteSbom` permission

## Logging

All prune operations should be logged for audit purposes using `target: "prune"` to enable separate audit file configuration at deployment time.

**Log on operation start:**
```
INFO [prune]: Prune operation started | user={user_id} | filter="{query}" | dry_run={bool} | limit={n}
```

**Log on each deletion (when not dry run):**
```
INFO [prune]: SBOM deleted | sbom_id={uuid} | name="{name}" | ingested={timestamp}
```

**Log on operation complete:**
```
INFO [prune]: Prune operation completed | user={user_id} | matched={n} | deleted={n} | failed={n} | duration={ms}
```

**Log on failure:**
```
WARN [prune]: SBOM deletion failed | sbom_id={uuid} | error="{message}"
```

These logs provide:
- Audit trail for compliance (can be routed to separate file via log configuration)
- Debugging information for failures
- Metrics for monitoring prune operations

## Design Considerations

### Reusable Logic

The pruning logic should be implemented in the service layer so it can be called by:
1. This REST endpoint (`POST /v2/sbom/prune`)
2. Future scheduled pruner background service (Next phase)

### Synchronous Execution

Initial implementation is synchronous - client waits for completion. This is suitable for batches up to a few thousand SBOMs. Asynchronous execution with job tracking will be addressed in the scheduled pruner phase.

## Success Criteria

- [ ] Endpoint accepts filter query and limit parameters
- [ ] Dry run mode returns accurate preview
- [ ] Actual pruning deletes matching SBOMs
- [ ] Failed deletions are tracked and reported
- [ ] All operations logged with user context
- [ ] Permission check enforced
- [ ] OpenAPI spec updated

## Next Phase: Scheduled Pruning Service

This phase will add a background pruning service following the importer pattern:
- Database-backed job configuration
- REST API for managing scheduled prune jobs (`/v2/pruner`)
- Period-based scheduling
- Reuses the prune service logic from this phase

## Related

- **External**: [Mobster](https://github.com/konflux-ci/mobster) - CLI tool for bulk SBOM operations
- **Future ADR**: SBOM Pruning Background Service (Next phase)
