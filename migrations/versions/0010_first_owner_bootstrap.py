"""Allow the API to create the initial default organization once."""

from alembic import op


revision = "0010_first_owner_bootstrap"
down_revision = "0009_p3_latest_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY organizations_first_bootstrap_policy ON organizations
        FOR INSERT TO fleet_api
        WITH CHECK (NOT EXISTS (SELECT 1 FROM users));
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS organizations_first_bootstrap_policy ON organizations")
