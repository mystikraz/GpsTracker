"""Allow authenticated users to create organizations and become owners."""

from alembic import op


revision = "0012_create_organizations"
down_revision = "0011_vehicle_identity_colors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY organizations_api_create_policy ON organizations
        FOR INSERT TO fleet_api
        WITH CHECK (NULLIF(current_setting('app.user_id', true), '') IS NOT NULL);
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS organizations_api_create_policy ON organizations")
