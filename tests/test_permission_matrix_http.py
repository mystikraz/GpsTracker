from __future__ import annotations

import unittest
from uuid import uuid4

from fleet_tracker.authorization import Action, Assurance, Principal, Resource, Role, authorize, permission_matrix
from fleet_tracker.http_api import AuthApp


class GeneratedPermissionMatrixHttpTests(unittest.TestCase):
    """Generated route contract plus central allow/deny assertions.

    The route map is deliberately data-driven: adding an action without adding
    an HTTP seam fails this test before a handler can bypass the policy module.
    Database-backed route tests exercise the same handlers with real sessions.
    """

    ROUTES = {
        Action.VIEW_ORGANIZATION: ("GET", "/api/v1/orgs/{org_id}"),
        Action.VIEW_MEMBERS: ("GET", "/api/v1/orgs/{org_id}/members"),
        Action.INVITE_DISPATCHER_VIEWER: ("POST", "/api/v1/orgs/{org_id}/invitations"),
        Action.INVITE_ADMIN: ("POST", "/api/v1/orgs/{org_id}/invitations"),
        Action.INVITE_OWNER: ("POST", "/api/v1/orgs/{org_id}/invitations"),
        Action.CHANGE_NON_OWNER_ROLE: ("PATCH", "/api/v1/orgs/{org_id}/members/{target_user_id}/role"),
        Action.CHANGE_OWNER_ROLE: ("PATCH", "/api/v1/orgs/{org_id}/members/{target_user_id}/role"),
        Action.SUSPEND_REMOVE_NON_OWNER: ("POST", "/api/v1/orgs/{org_id}/members/{target_user_id}/{status}"),
        Action.SUSPEND_REMOVE_OWNER: ("POST", "/api/v1/orgs/{org_id}/members/{target_user_id}/{status}"),
        Action.VIEW_VEHICLES: ("GET", "/api/v1/orgs/{org_id}/vehicles"),
        Action.CREATE_VEHICLE: ("POST", "/api/v1/orgs/{org_id}/vehicles"),
        Action.UPDATE_VEHICLE: ("PATCH", "/api/v1/orgs/{org_id}/vehicles/{vehicle_id}"),
        Action.DELETE_VEHICLE: ("DELETE", "/api/v1/orgs/{org_id}/vehicles/{vehicle_id}"),
        Action.VIEW_DEVICES: ("GET", "/api/v1/orgs/{org_id}/devices"),
        Action.PROVISION_DEVICE: ("POST", "/api/v1/orgs/{org_id}/devices"),
        Action.DELETE_DEVICE: ("DELETE", "/api/v1/orgs/{org_id}/devices/{device_id}"),
        Action.ASSIGN_DEVICE: ("POST", "/api/v1/orgs/{org_id}/devices/{device_id}/assign"),
        Action.ROTATE_DEVICE_SECRET: ("POST", "/api/v1/orgs/{org_id}/devices/{device_id}/rotate-secret"),
        Action.VIEW_POSITIONS: ("GET", "/api/v1/orgs/{org_id}/positions"),
        Action.MANAGE_GROUPS: ("POST", "/api/v1/orgs/{org_id}/groups"),
        Action.ASSIGN_VEHICLES_TO_GROUPS: ("POST", "/api/v1/orgs/{org_id}/groups/{group_id}/vehicles/{vehicle_id}"),
        Action.SET_MEMBER_GROUP_SCOPE: ("PUT", "/api/v1/orgs/{org_id}/members/{target_user_id}/groups"),
        Action.READ_AUDIT_LOG: ("GET", "/api/v1/orgs/{org_id}/audit"),
        Action.CHANGE_OWN_PASSWORD: ("POST", "/api/v1/auth/password/change"),
        Action.REQUEST_SELF_RESET: ("POST", "/api/v1/auth/reset/request"),
        Action.ADMIN_RESET_DISPATCHER_VIEWER: ("POST", "/api/v1/orgs/{org_id}/members/{target_user_id}/reset"),
        Action.ADMIN_RESET_OWNER_ADMIN: ("POST", "/api/v1/orgs/{org_id}/members/{target_user_id}/reset"),
        Action.DELETE_ORGANIZATION_DATA: ("DELETE", "/api/v1/orgs/{org_id}/data"),
        Action.UPDATE_ORGANIZATION_SETTINGS: ("PATCH", "/api/v1/orgs/{org_id}/settings"),
        Action.VIEW_SESSIONS: ("GET", "/api/v1/auth/sessions"),
        Action.REVOKE_SESSIONS: ("POST", "/api/v1/auth/sessions/{session_id}/revoke"),
    }

    def test_every_role_action_pair_has_real_route_and_policy_allow_deny(self) -> None:
        self.assertEqual(set(self.ROUTES), set(Action))
        app = AuthApp(None, None).build()
        route_keys = {(method, route.path) for route in app.routes for method in getattr(route, "methods", set())}
        for action, route in self.ROUTES.items():
            self.assertIn(route, route_keys, action)
        matrix = permission_matrix()
        org = uuid4()
        for role in Role:
            for action in Action:
                target_role = Role.ADMIN if action is Action.ADMIN_RESET_OWNER_ADMIN else (Role.OWNER if action in {Action.CHANGE_OWNER_ROLE, Action.SUSPEND_REMOVE_OWNER} else Role.VIEWER)
                resource = Resource(org, group_id=uuid4() if action in {Action.VIEW_VEHICLES, Action.UPDATE_VEHICLE, Action.VIEW_DEVICES, Action.VIEW_POSITIONS} else None, target_role=target_role)
                allowed = authorize(Principal(uuid4(), org, role, assurance=Assurance.RECENT_REAUTHENTICATION), action, resource)
                self.assertEqual(allowed, matrix[role][action], (role, action))

    def test_restricted_dispatcher_and_viewer_have_no_unscoped_read_route(self) -> None:
        org = uuid4()
        for role in (Role.DISPATCHER, Role.VIEWER):
            principal = Principal(uuid4(), org, role, group_scope_mode="restricted", assurance=Assurance.RECENT_REAUTHENTICATION)
            for action in (Action.VIEW_VEHICLES, Action.VIEW_DEVICES, Action.VIEW_POSITIONS):
                self.assertFalse(authorize(principal, action, Resource(org)))
                self.assertEqual(authorize(principal, action, Resource(org, group_id=uuid4())), permission_matrix()[role][action])

