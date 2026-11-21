# P3 web application

The P3 web application is a same-origin React/TypeScript/Vite build served by
Caddy. It uses the P2 `__Host-fleet_session` cookie and never stores bearer
tokens or session identifiers in browser storage.

## Local development

```text
cd web
npm install
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. The tile URL is configurable
with `VITE_MAP_STYLE_URL`; it is not a secret. OpenFreeMap attribution is
provided by MapLibre. Public OpenStreetMap tiles must not
be treated as an unlimited production service.

## Authentication flows

- Login obtains a short-lived pre-session CSRF cookie and posts the CSRF token
  in the request body. The pre-session cookie is HttpOnly and is not read by
  JavaScript.
- State-changing requests use the in-memory CSRF token and `X-CSRF-Token`.
- Invitation and reset pages read their one-time token from the URL fragment,
  immediately clear the fragment, and post the token in the request body.
- Tokens are never placed in a path or query string.

## Fleet API additions

| Method | Path | Scope |
|---|---|---|
| GET | `/api/v1/orgs/{org_id}/vehicles/latest-state` | visible vehicles |
| GET | `/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/latest-state` | one visible vehicle |
| GET | `/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/history` | visible vehicle, max 31 days |
| GET | `/api/v1/orgs/{org_id}/vehicles/stream` | visible vehicles via SSE |

Latest-state rows are maintained by owner-owned database triggers on accepted
raw messages and positions. This keeps `fleet_ingest` insert-only for telemetry.
The API applies group scope in the query layer and PostgreSQL RLS applies the
organization boundary.

SSE polls the latest-state projection every 1.5 seconds. It supports
`Last-Event-ID`, emits heartbeat comments, and is capped at 16 concurrent
streams by default. The cap is process-local and assumes one API instance.

Status defaults: `offline` means no authenticated message for five minutes;
`no_fix` means authenticated traffic exists but no current position fix;
`moving` means valid speed is at least 1 km/h; otherwise the status is
`stopped`. Configure these with `VEHICLE_OFFLINE_AFTER_SECONDS`,
`VEHICLE_MOVING_SPEED_KMH`, and `SSE_MAX_STREAMS`.

## Deployment

Compose services use separate pooled runtime URLs: `api` uses
`FLEET_API_DATABASE_URL`, `ingestion` uses `FLEET_INGEST_DATABASE_URL`, and
`worker` uses `FLEET_WORKER_DATABASE_URL`. The `migrate` job alone receives the
direct owner URL. The web container contains only Caddy and static assets; it
proxies `/api/*` to the API service and does not access the database.

Configured memory limits on the four-GB host are API 512 MB, ingestion 256 MB,
worker 256 MB, Caddy 64 MB, and the explicit migration job 256 MB. Neon owns
database memory. Compose never runs migrations automatically on `up`.

## Verification

```text
npm run build
npm test
npm run test:e2e
```

Backend API tests run against disposable PostGIS. Authenticated browser flows
require a disposable API fixture environment with seeded users and organizations.
