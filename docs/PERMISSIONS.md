# P2 permissions and tenant scope

The application uses one authorization function, `authorize(principal, action,
resource, assurance)`. Handlers do not contain independent role checks.

The permission matrix is generated from the policy module and tested for every
role/action pair. Owner and Admin sensitive actions require recent password
reauthentication. Group restrictions are application-enforced: the central
policy receives the resource group and denies an out-of-scope resource before
the repository query is executed. PostgreSQL RLS remains the defense-in-depth
tenant boundary, but it does not encode per-user group membership.

A restricted Dispatcher cannot create vehicles because a new vehicle would not
have a valid group scope. Dispatchers without group restrictions may create and
update vehicles. Restricted Dispatchers may view/update only vehicles,
positions, and non-secret device metadata associated with an allowed group.

Deleting organization data is Owner-only. Updating organization settings is
Owner-only and requires recent password reauthentication. All users may view
and revoke their own sessions; Owner/Admin may additionally revoke a member's
sessions where the member-management policy permits it.

Suspending or removing a membership immediately revokes all sessions for that
user through a database trigger. Users and organizations are disabled/archived,
not hard-deleted; audit foreign keys are non-cascading.

The scoped actions tested by `tests/test_authorization_matrix.py` are:

- view vehicles;
- update vehicles;
- view devices;
- view positions.

Each is tested with both an in-scope group and no/out-of-scope group. Every
organization route must call the same policy before loading the resource, so an
out-of-scope ID returns the same generic 404 as a nonexistent ID.
## Phase C route surface

| Method | Path |
|---|---|
| GET/POST | `/api/v1/orgs/{org_id}/members` |
| GET | `/api/v1/orgs` |
| GET | `/api/v1/orgs/{org_id}` |
| PATCH | `/api/v1/orgs/{org_id}/settings` |
| GET | `/api/v1/orgs/{org_id}/audit` |
| POST | `/api/v1/orgs/{org_id}/invitations` |
| POST | `/api/v1/auth/invitations/accept` |
| POST | `/api/v1/orgs/{org_id}/members/{user_id}/reset` |
| POST | `/api/v1/orgs/{org_id}/invitations/{invitation_id}/revoke` |
| POST | `/api/v1/orgs/{org_id}/invitations/{invitation_id}/resend` |
| PATCH | `/api/v1/orgs/{org_id}/members/{user_id}/role` |
| POST | `/api/v1/orgs/{org_id}/members/{user_id}/{active|suspended|removed}` |
| GET/POST | `/api/v1/orgs/{org_id}/groups` |
| DELETE | `/api/v1/orgs/{org_id}/groups/{group_id}` |
| POST | `/api/v1/orgs/{org_id}/groups/{group_id}/vehicles/{vehicle_id}` |
| PUT | `/api/v1/orgs/{org_id}/members/{user_id}/groups` |
| GET/POST | `/api/v1/orgs/{org_id}/vehicles` |
| GET | `/api/v1/orgs/{org_id}/devices` |
| POST | `/api/v1/orgs/{org_id}/devices` |
| POST | `/api/v1/orgs/{org_id}/devices/{device_id}/assign` |
| POST | `/api/v1/orgs/{org_id}/devices/{device_id}/rotate-secret` |
| GET | `/api/v1/orgs/{org_id}/positions` |
| DELETE | `/api/v1/orgs/{org_id}/data` |

Group scope is enforced in the repository query layer, after membership is
looked up and before the transaction-local organization context is set. RLS
continues to enforce organization isolation. Restricted members receive only
vehicles, devices, and positions whose vehicles belong to their scoped groups.
