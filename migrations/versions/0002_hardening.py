"""P2 hardening: assignment exclusion and a safe default position partition."""

from alembic import op

revision = "0002_hardening"
down_revision = "0001_p1_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
    op.execute(
        """
        ALTER TABLE device_vehicle_assignments
        ADD CONSTRAINT device_assignments_no_overlap
        EXCLUDE USING gist (
            device_id WITH =,
            tstzrange(effective_from, effective_to, '[)') WITH &&
        )
        """
    )
    op.execute(
        """
        CREATE TABLE positions_default PARTITION OF positions DEFAULT
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_positions_default_org_device_time
        ON positions_default (organization_id, device_id, gps_timestamp DESC)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS positions_default")
    op.execute("ALTER TABLE device_vehicle_assignments DROP CONSTRAINT IF EXISTS device_assignments_no_overlap")
