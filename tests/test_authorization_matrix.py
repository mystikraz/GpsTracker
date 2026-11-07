from __future__ import annotations

import unittest
from uuid import uuid4

from fleet_tracker.authorization import (
    Action,
    Assurance,
    Principal,
    Resource,
    Role,
    authorize,
    permission_matrix,
)


class AuthorizationMatrixTests(unittest.TestCase):
    def test_every_role_action_pair_matches_the_declared_matrix(self) -> None:
        org = uuid4()
        matrix = permission_matrix()
        for role in Role:
            principal = Principal(uuid4(), org, role, assurance=Assurance.RECENT_REAUTHENTICATION)
            for action in Action:
                expected = matrix[role][action]
                target_role = Role.ADMIN if action is Action.ADMIN_RESET_OWNER_ADMIN else Role.VIEWER
                if action in {Action.CHANGE_OWNER_ROLE, Action.SUSPEND_REMOVE_OWNER}:
                    target_role = Role.OWNER
                resource = Resource(org, target_role=target_role)
                if action is Action.SUSPEND_REMOVE_OWNER:
                    resource = Resource(org, target_role=target_role, target_is_last_owner=False)
                self.assertEqual(authorize(principal, action, resource), expected, (role, action))

    def test_restricted_dispatcher_cannot_create_or_escape_group_scope(self) -> None:
        org = uuid4()
        principal = Principal(uuid4(), org, Role.DISPATCHER, group_scope_mode="restricted")
        self.assertFalse(authorize(principal, Action.CREATE_VEHICLE, Resource(org)))
        self.assertTrue(authorize(principal, Action.VIEW_VEHICLES, Resource(org, group_id=uuid4())))
        self.assertFalse(authorize(principal, Action.VIEW_VEHICLES, Resource(org)))

    def test_group_scope_is_required_for_every_scoped_read_or_update_action(self) -> None:
        org = uuid4()
        principal = Principal(uuid4(), org, Role.DISPATCHER, group_scope_mode="restricted")
        scoped_actions = {
            Action.VIEW_VEHICLES,
            Action.UPDATE_VEHICLE,
            Action.VIEW_DEVICES,
            Action.VIEW_POSITIONS,
        }
        for action in scoped_actions:
            self.assertFalse(authorize(principal, action, Resource(org)), action)
            self.assertTrue(authorize(principal, action, Resource(org, group_id=uuid4())), action)

    def test_cross_organization_resources_are_denied(self) -> None:
        principal = Principal(uuid4(), uuid4(), Role.OWNER, assurance=Assurance.RECENT_REAUTHENTICATION)
        self.assertFalse(authorize(principal, Action.VIEW_ORGANIZATION, Resource(uuid4())))

    def test_sensitive_actions_require_recent_reauthentication(self) -> None:
        org = uuid4()
        principal = Principal(uuid4(), org, Role.ADMIN)
        resource = Resource(org)
        self.assertFalse(authorize(principal, Action.PROVISION_DEVICE, resource))
        reauth = Principal(uuid4(), org, Role.ADMIN, assurance=Assurance.RECENT_REAUTHENTICATION)
        self.assertTrue(authorize(reauth, Action.PROVISION_DEVICE, resource))

    def test_owner_protection_and_admin_reset_scope(self) -> None:
        org = uuid4()
        owner = Principal(uuid4(), org, Role.OWNER, assurance=Assurance.RECENT_REAUTHENTICATION)
        self.assertFalse(
            authorize(owner, Action.SUSPEND_REMOVE_OWNER, Resource(org, target_role=Role.OWNER, target_is_last_owner=True))
        )
        admin = Principal(uuid4(), org, Role.ADMIN, assurance=Assurance.RECENT_REAUTHENTICATION)
        self.assertTrue(
            authorize(admin, Action.ADMIN_RESET_DISPATCHER_VIEWER, Resource(org, target_role=Role.VIEWER))
        )
        self.assertFalse(
            authorize(admin, Action.ADMIN_RESET_OWNER_ADMIN, Resource(org, target_role=Role.ADMIN))
        )


if __name__ == "__main__":
    unittest.main()
