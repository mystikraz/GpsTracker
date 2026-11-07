"""Central P2 authorization matrix.

Handlers must call this module instead of implementing role checks locally.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    DISPATCHER = "dispatcher"
    VIEWER = "viewer"


class Assurance(StrEnum):
    PASSWORD = "password"
    RECENT_REAUTHENTICATION = "recent_reauthentication"


class Action(StrEnum):
    VIEW_ORGANIZATION = "view_organization"
    VIEW_MEMBERS = "view_members"
    INVITE_DISPATCHER_VIEWER = "invite_dispatcher_viewer"
    INVITE_ADMIN = "invite_admin"
    INVITE_OWNER = "invite_owner"
    CHANGE_NON_OWNER_ROLE = "change_non_owner_role"
    CHANGE_OWNER_ROLE = "change_owner_role"
    SUSPEND_REMOVE_NON_OWNER = "suspend_remove_non_owner"
    SUSPEND_REMOVE_OWNER = "suspend_remove_owner"
    VIEW_VEHICLES = "view_vehicles"
    CREATE_VEHICLE = "create_vehicle"
    UPDATE_VEHICLE = "update_vehicle"
    DELETE_VEHICLE = "delete_vehicle"
    VIEW_DEVICES = "view_devices"
    PROVISION_DEVICE = "provision_device"
    ASSIGN_DEVICE = "assign_device"
    ROTATE_DEVICE_SECRET = "rotate_device_secret"
    VIEW_POSITIONS = "view_positions"
    MANAGE_GROUPS = "manage_groups"
    ASSIGN_VEHICLES_TO_GROUPS = "assign_vehicles_to_groups"
    SET_MEMBER_GROUP_SCOPE = "set_member_group_scope"
    READ_AUDIT_LOG = "read_audit_log"
    CHANGE_OWN_PASSWORD = "change_own_password"
    REQUEST_SELF_RESET = "request_self_reset"
    ADMIN_RESET_DISPATCHER_VIEWER = "admin_reset_dispatcher_viewer"
    ADMIN_RESET_OWNER_ADMIN = "admin_reset_owner_admin"
    DELETE_ORGANIZATION_DATA = "delete_organization_data"
    UPDATE_ORGANIZATION_SETTINGS = "update_organization_settings"
    VIEW_SESSIONS = "view_sessions"
    REVOKE_SESSIONS = "revoke_sessions"


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    organization_id: UUID
    role: Role
    group_scope_mode: str = "all"
    assurance: Assurance = Assurance.PASSWORD


@dataclass(frozen=True, slots=True)
class Resource:
    organization_id: UUID
    group_id: UUID | None = None
    target_role: Role | None = None
    target_is_last_owner: bool = False
    target_user_id: UUID | None = None


_REAUTH = frozenset(
    {
        Action.INVITE_ADMIN,
        Action.INVITE_OWNER,
        Action.CHANGE_NON_OWNER_ROLE,
        Action.CHANGE_OWNER_ROLE,
        Action.SUSPEND_REMOVE_NON_OWNER,
        Action.SUSPEND_REMOVE_OWNER,
        Action.DELETE_VEHICLE,
        Action.PROVISION_DEVICE,
        Action.ASSIGN_DEVICE,
        Action.ROTATE_DEVICE_SECRET,
        Action.SET_MEMBER_GROUP_SCOPE,
        Action.ADMIN_RESET_DISPATCHER_VIEWER,
        Action.ADMIN_RESET_OWNER_ADMIN,
        Action.DELETE_ORGANIZATION_DATA,
        Action.UPDATE_ORGANIZATION_SETTINGS,
    }
)


_ROLE_ACTIONS: dict[Role, frozenset[Action]] = {
    Role.OWNER: frozenset(Action),
    Role.ADMIN: frozenset(
        {
            Action.VIEW_ORGANIZATION,
            Action.VIEW_MEMBERS,
            Action.INVITE_DISPATCHER_VIEWER,
            Action.INVITE_ADMIN,
            Action.CHANGE_NON_OWNER_ROLE,
            Action.SUSPEND_REMOVE_NON_OWNER,
            Action.VIEW_VEHICLES,
            Action.CREATE_VEHICLE,
            Action.UPDATE_VEHICLE,
            Action.DELETE_VEHICLE,
            Action.VIEW_DEVICES,
            Action.PROVISION_DEVICE,
            Action.ASSIGN_DEVICE,
            Action.ROTATE_DEVICE_SECRET,
            Action.VIEW_POSITIONS,
            Action.MANAGE_GROUPS,
            Action.ASSIGN_VEHICLES_TO_GROUPS,
            Action.SET_MEMBER_GROUP_SCOPE,
            Action.READ_AUDIT_LOG,
            Action.CHANGE_OWN_PASSWORD,
            Action.REQUEST_SELF_RESET,
            Action.ADMIN_RESET_DISPATCHER_VIEWER,
            Action.VIEW_SESSIONS,
            Action.REVOKE_SESSIONS,
        }
    ),
    Role.DISPATCHER: frozenset(
        {
            Action.VIEW_ORGANIZATION,
            Action.VIEW_VEHICLES,
            Action.CREATE_VEHICLE,
            Action.UPDATE_VEHICLE,
            Action.VIEW_DEVICES,
            Action.VIEW_POSITIONS,
            Action.CHANGE_OWN_PASSWORD,
            Action.REQUEST_SELF_RESET,
            Action.VIEW_SESSIONS,
            Action.REVOKE_SESSIONS,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Action.VIEW_ORGANIZATION,
            Action.VIEW_VEHICLES,
            Action.VIEW_POSITIONS,
            Action.CHANGE_OWN_PASSWORD,
            Action.REQUEST_SELF_RESET,
            Action.VIEW_SESSIONS,
            Action.REVOKE_SESSIONS,
        }
    ),
}


def permission_matrix() -> dict[Role, dict[Action, bool]]:
    return {role: {action: action in allowed for action in Action} for role, allowed in _ROLE_ACTIONS.items()}


def authorize(principal: Principal, action: Action, resource: Resource) -> bool:
    if principal.organization_id != resource.organization_id:
        return False
    if action not in _ROLE_ACTIONS[principal.role]:
        return False
    if action in _REAUTH and principal.assurance is not Assurance.RECENT_REAUTHENTICATION:
        return False
    if action is Action.DELETE_ORGANIZATION_DATA and principal.role is not Role.OWNER:
        return False
    if action is Action.UPDATE_ORGANIZATION_SETTINGS and principal.role is not Role.OWNER:
        return False
    if action in {Action.VIEW_SESSIONS, Action.REVOKE_SESSIONS}:
        return principal.role in {Role.OWNER, Role.ADMIN, Role.DISPATCHER, Role.VIEWER}
    if action is Action.CREATE_VEHICLE and principal.role is Role.DISPATCHER:
        return principal.group_scope_mode == "all"
    if principal.group_scope_mode == "restricted" and action in {
        Action.VIEW_VEHICLES,
        Action.UPDATE_VEHICLE,
        Action.VIEW_DEVICES,
        Action.VIEW_POSITIONS,
    }:
        return resource.group_id is not None
    if action is Action.INVITE_OWNER and principal.role is not Role.OWNER:
        return False
    if action in {Action.CHANGE_OWNER_ROLE, Action.SUSPEND_REMOVE_OWNER}:
        return principal.role is Role.OWNER and not resource.target_is_last_owner
    if action is Action.ADMIN_RESET_OWNER_ADMIN:
        return principal.role is Role.OWNER and resource.target_role in {Role.OWNER, Role.ADMIN}
    if action is Action.ADMIN_RESET_DISPATCHER_VIEWER:
        return principal.role in {Role.OWNER, Role.ADMIN} and resource.target_role in {
            Role.DISPATCHER,
            Role.VIEWER,
        }
    if action is Action.CHANGE_NON_OWNER_ROLE:
        return resource.target_role is not Role.OWNER
    return True
