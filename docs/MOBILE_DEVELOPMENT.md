# Mobile development guide

This guide is for Android and iOS developers integrating with the GPS Tracker
HTTP API. Mobile clients do not need the JT/T 808 ingestion service or the
database to use the production API.

## Choose an API environment

For normal development, use the deployed HTTPS API:

```text
https://tracker.goastralabs.com
```

The interactive documentation and machine-readable contract are available at:

- Swagger UI: `https://tracker.goastralabs.com/api/docs`
- ReDoc: `https://tracker.goastralabs.com/api/redoc`
- OpenAPI JSON: `https://tracker.goastralabs.com/api/openapi.json`

For backend development on the same computer, the API is available at
`http://127.0.0.1:8000` after starting the Compose stack. A phone cannot use
`127.0.0.1` to reach the developer computer; use the computer's LAN IP, such
as `http://192.168.1.20:8000`, and allow port 8000 through the local firewall.
Do not use plain HTTP with real credentials outside a trusted local network.

## Mobile project configuration

Keep the base URL environment-specific and do not hard-code it in API calls:

```text
Development: http://192.168.1.20:8000
Production:  https://tracker.goastralabs.com
```

Every endpoint path in the OpenAPI document already begins with `/api`.
For example, the full production URL for the vehicle list is:

```text
GET https://tracker.goastralabs.com/api/v1/orgs/{org_id}/vehicles
```

Use a cookie-aware HTTP client. The API uses an HttpOnly session cookie rather
than a bearer token, so the mobile client must persist and resend cookies for
the session. Never log or expose the session cookie.

## Login flow

1. Call `GET /api/v1/auth/login/csrf`.
2. Preserve the returned `__Host-fleet_login` cookie and read `csrf_token` from
   the JSON response.
3. Call `POST /api/v1/auth/login` with:

   ```json
   {
     "email": "developer@example.com",
     "password": "your-password",
     "csrf_token": "token-from-step-1"
   }
   ```

4. Preserve the returned `__Host-fleet_session` cookie and the `X-CSRF-Token`
   response header.
5. Call `GET /api/v1/auth/me` to verify the session.
6. Before a state-changing request, call `GET /api/v1/auth/csrf` if a current
   CSRF token is not already available. Send that token as `X-CSRF-Token` on
   every `POST`, `PATCH`, `PUT`, and `DELETE` request.

The login CSRF cookie is intentionally HttpOnly; the HTTP client must manage
it as a cookie and must not try to read it from application code. On logout,
call `POST /api/v1/auth/logout` with the session cookie and CSRF header, then
clear the client's cookie store.

## First authenticated requests

After login:

1. Call `GET /api/v1/orgs` to list organizations available to the user.
2. Select an `org_id`.
3. Call `GET /api/v1/orgs/{org_id}/vehicles`.
4. Use latest-state, history, and stream endpoints from Swagger UI.

The account must be an active member of the organization, and the requested
operation must be allowed by its role and group scope.

## Live vehicle updates

Use the server-sent events endpoint for live updates:

```text
GET /api/v1/orgs/{org_id}/vehicles/stream
```

The connection must include the session cookie. Parse `event: vehicle_state`
messages and reconnect if the connection closes. Send `Last-Event-ID` when
resuming a stream if the client retained the last event ID. The stream is
read-only and does not require a CSRF header.

## Running the backend locally

This is normally needed only by backend developers or integration testers.
The repository requires Docker and a configured Neon database. Copy
`.env.example` to `.env`, fill in the pooled runtime database URLs and secret
values, then start the stack:

```text
docker compose up --build
```

The API is bound to `127.0.0.1:8000` by default. The Compose stack does not
run migrations automatically; follow the migration instructions in the root
README before using a newly created database. Seed a test user, organization,
and vehicle through the project’s approved provisioning process. Do not use
production credentials or production data for local mobile testing.

## Troubleshooting

- `401`: the session cookie is missing, expired, or not being persisted.
- `403` on a state-changing request: refresh the session CSRF token and send
  it as `X-CSRF-Token`.
- `403` or an empty organization response: check organization membership and
  role/group scope.
- Phone cannot connect locally: use the computer's LAN IP, ensure both devices
  are on the same network, and allow TCP port 8000 through the firewall.
- Swagger works but the app fails: compare the app's base URL, cookie jar,
  redirects, and TLS certificate handling with the OpenAPI request.

## Security requirements

- Use HTTPS in production.
- Do not store session cookies in logs, analytics, crash reports, or URLs.
- Do not put credentials, cookies, or CSRF tokens in query parameters.
- Use separate development and production configurations.
- Ask the project administrator for test credentials and organization access.
