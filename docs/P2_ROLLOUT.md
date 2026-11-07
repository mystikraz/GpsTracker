# P2 rollout order

P2 rollout is staged and approval-gated:

1. Apply reviewed role SQL and migrations on a disposable PostGIS database.
2. On the Neon staging branch, create `fleet_api`, `fleet_ingest`, and
   `fleet_worker` separately with unique passwords for that branch.
3. Apply the same reviewed changes on that Neon staging database only after explicit approval.
4. Verify the API role, ingestion role, worker role, RLS, partition functions,
   and audit protections on staging.
5. Configure each service with only its own pooled role URL: API uses
   `FLEET_API_DATABASE_URL`, ingestion uses `FLEET_INGEST_DATABASE_URL`, and
   worker uses `FLEET_WORKER_DATABASE_URL`. The direct owner URL is used only
   by the explicit guarded migration command.
6. Replay the real-device fixtures through the `fleet_ingest` runtime role and
   confirm telemetry persistence and tenant isolation.
7. Treat successful staging replay through `fleet_ingest` as a gate before main.
8. Obtain explicit approval before any main-database migration or role change.
9. On main, create the three runtime roles again with different passwords;
   roles and passwords are per Neon branch/database and are not copied from staging.
10. Apply to main through the guarded direct-URL migration command.

No migration or role change is automatic. The operator must confirm the printed
database host and database name. Neon branches are never labeled by the tooling.

The existing `neondb_owner` role can bypass RLS as a database owner/superuser.
Therefore tenant enforcement begins only after the API, ingestion, and worker
services switch to their dedicated runtime roles.

## Phase B local verification

Phase B authentication tests use only disposable PostGIS databases. The
Linux equivalent of `scripts/run_p2_rls_staging.ps1` is
`scripts/run_p2_rls_staging.sh`; it requires `--confirm-host`, checks the host
against `TEST_DATABASE_URL`, prints only host and database, and never labels a
branch. It does not create roles; the operator creates roles per branch using
reviewed SQL and generates each password with `openssl rand -hex 24`.

Users and organizations are never hard-deleted by the application. Audit foreign
keys are non-cascading and do not use `ON DELETE SET NULL`, because either would
mutate or remove append-only audit history. Account and organization retirement
must use disabled/archived status and a separately approved retention process.
