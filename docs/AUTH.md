# Phase B authentication

When the database has no users, the login page exposes a first-run account
setup link. The first account is created as an owner of an automatically
created `My organization` organization. The endpoint is protected by the
login CSRF flow and a database advisory lock; after the first user exists,
the setup endpoint is closed and normal invite-based account creation applies.

P2 uses invite-only email/password authentication. The bootstrap CLI creates
the first Owner and organization; it reads `BOOTSTRAP_OWNER_PASSWORD` or a
hidden stdin prompt and never accepts a password argument.

Passwords use Argon2id with `time_cost=3`, `memory_cost=65536` KiB (64 MiB),
`parallelism=1`, and a bounded application hashing semaphore. This is a
deliberate 2 GB-host calibration starting point; benchmark it on the target
host and keep `PASSWORD_HASH_MAX_CONCURRENCY` low enough to avoid concurrent
64 MiB allocations. Passwords require 12 characters and are checked against
the offline breached/common-password list; composition rules are not used.

Sessions store only SHA-256 hashes of random server-side IDs. They have idle
and absolute expiry, shorter defaults for Owner/Admin, and rotate after login,
password changes, and privilege changes. The cookie is host-only,
`__Host-fleet_session`, HttpOnly, Secure, SameSite=Lax, and Path=/.

Cookie-authenticated writes require the session synchronizer token and a
matching HTTPS Origin/Host. Login itself requires a short-lived pre-session
CSRF token, consumed once. Reject missing or mismatched Origin/Host and CSRF
tokens with generic errors. Manual reset links are one-time SHA-256-hashed
tokens, expire after one hour, revoke every session, and are returned only
once with `Cache-Control: no-store`; tokens are sent in POST bodies and never
logged. The manual-link provider is the default; SMTP and SES are optional.

Login failures use the same response for unknown accounts, wrong passwords,
locked accounts, and throttled requests. Per-IP and per-account rate limits
and lockout are process-local. This is a documented single-API-instance
limitation; do not scale the API horizontally until the limiter is moved to a
shared store.

Recent re-authentication means password re-entry within `REAUTH_WINDOW_SECONDS`
(default 600). Authorization retains its assurance input so MFA can be added
later without changing endpoint contracts.

Run the bootstrap only against the reviewed direct database URL:

```text
printf '%s\n' 'a-long-password-from-a-secret-manager' | \
  BOOTSTRAP_OWNER_PASSWORD= fleet-tracker --database-url "$DIRECT_DATABASE_URL" \
  bootstrap-owner --email owner@example.invalid --name "Example Fleet"
```

The example password is illustrative only; never use it or any repository
credential. Generate role passwords with `openssl rand -hex 24`.

## HTTP endpoints

Authentication endpoints are implemented in the injectable ASGI app factory:

| Method | Path |
|---|---|
| GET | `/api/v1/auth/login/csrf` |
| POST | `/api/v1/auth/login` |
| POST | `/api/v1/auth/logout` |
| GET | `/api/v1/auth/me` |
| POST | `/api/v1/auth/password/change` |
| POST | `/api/v1/auth/reset/request` |
| POST | `/api/v1/auth/reset/consume` |
| GET | `/api/v1/auth/sessions` |
| POST | `/api/v1/auth/sessions/{session_id}/revoke` |
| POST | `/api/v1/auth/reauthenticate` |

Organization and fleet endpoints are listed in `docs/PERMISSIONS.md` and all
carry the organization ID in the path. Manual invitation/reset tokens are
POST-body values and manual-link responses are `no-store`.

Authentication records are additionally protected by user-scoped RLS:
`sessions`, `password_tokens`, and `reauthentications` require the validated
`app.user_id` transaction setting. Session lookup and reset-token lookup use
short-lived transaction settings containing the presented value only to locate
that record. The API role cannot read another user's rows; this is proven by
`tests/test_auth_rls.py` with a real runtime-role connection.

## Coverage map

| Case | Test |
|---|---|
| Argon2id policy, breached password, bounded hashing | `PhaseBSecurityTests.test_argon2id_hashing_policy_and_bounded_service` |
| Token hashing and constant-time comparison | `PhaseBSecurityTests.test_token_hash_is_one_way_and_constant_time_comparison` |
| Per-IP and per-account limits | `PhaseBSecurityTests.test_process_limiter_is_per_ip_and_account` |
| Cookie flags and origin rejection | `PhaseBSecurityTests.test_origin_and_host_cookie` |
| Login CSRF, generic errors, reset no-store, cookie flags | `PhaseBHttpTests.test_auth_endpoints_cookie_csrf_login_csrf_and_generic_errors` |
| Login, rotation, CSRF, reset single-use, session revocation | `PhaseBAuthIntegrationTests.test_login_session_rotation_csrf_lockout_and_reset` |
| Cross-user auth-row isolation | `AuthRlsTests.test_api_user_context_cannot_read_another_users_sessions_or_tokens` |
| Invitation, role lifecycle, last-owner protection, suspension revocation | `PhaseCOrganizationTests.test_invitation_accept_role_lifecycle_last_owner_and_session_revoke` |
| Concurrent last-owner protection | `LastOwnerConcurrencyTests.test_simultaneous_owner_suspend_requests_have_one_success_and_one_owner_remains` |
| Generated action matrix and route coverage | `GeneratedPermissionMatrixHttpTests.test_every_role_action_pair_has_real_route_and_policy_allow_deny` |
| Restricted vehicle/device/position policy denial | `GeneratedPermissionMatrixHttpTests.test_restricted_dispatcher_and_viewer_have_no_unscoped_read_route` |
| Idle and absolute session expiry | `PhaseBAuthIntegrationTests.test_idle_and_absolute_expiry` |
| Real-fixture telemetry deduplication without SELECT | `P2RlsIntegrationTests.test_fleet_ingest_replays_registration_auth_position_and_batch_without_context` |

Privilege-change rotation is covered by the role-change route and
`AuthService.rotate_after_privilege_change`. Approved-plan routes now include
organization list/detail, settings update, audit read, invitation acceptance,
admin reset, and organization-data deletion. Reset expiry/tampering and timing
distribution checks remain documented limitations of this test phase.
