# GPS Tracker API

The production API documentation is served by FastAPI:

- Swagger UI: `https://tracker.goastralabs.com/api/docs`
- ReDoc: `https://tracker.goastralabs.com/api/redoc`
- OpenAPI JSON: `https://tracker.goastralabs.com/api/openapi.json`

## Mobile authentication flow

1. `GET /api/v1/auth/login/csrf` to obtain a login CSRF token and pre-session cookie.
2. `POST /api/v1/auth/login` with `email`, `password`, and `csrf_token`.
3. Persist the returned `__Host-fleet_session` cookie in the mobile HTTP client.
4. `GET /api/v1/auth/csrf` to obtain the authenticated CSRF token.
5. Send `X-CSRF-Token` on every state-changing request (`POST`, `PATCH`, `PUT`, and `DELETE`).

Authenticated reads use the session cookie. Organization-scoped endpoints require
the user to be an active organization member with the appropriate role and scope.

## Fleet endpoints

The OpenAPI document includes vehicle lists, latest state, position history,
device management, and the live vehicle-state SSE stream. The history endpoint
accepts ISO-8601 `from` and `to` timestamps and supports cursor pagination.
