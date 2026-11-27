"""Allow users to read the names of their own organizations."""

from alembic import op


revision = "0013_organization_names"
down_revision = "0012_create_organizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY organizations_api_membership_read_policy ON organizations
        FOR SELECT TO fleet_api
        USING (
            id = NULLIF(current_setting('app.organization_id', true), '')::uuid
            OR EXISTS (
                SELECT 1
                FROM organization_memberships
                WHERE organization_memberships.organization_id = organizations.id
                  AND organization_memberships.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                  AND organization_memberships.status = 'active'
            )
        );
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS organizations_api_membership_read_policy ON organizations")
