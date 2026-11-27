"""Persist identity colors for vehicles."""

from alembic import op


revision = "0011_vehicle_identity_colors"
down_revision = "0010_first_owner_bootstrap"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE vehicles ADD COLUMN color TEXT NOT NULL DEFAULT '#0f766e'")
    op.execute(
        """
        WITH ranked AS (
            SELECT id, ((row_number() OVER (PARTITION BY organization_id ORDER BY id) - 1) % 12) AS color_index
            FROM vehicles
        )
        UPDATE vehicles AS vehicle
        SET color = (ARRAY[
            '#0f766e', '#c2410c', '#6d28d9', '#0369a1', '#be123c', '#4d7c0f',
            '#a16207', '#0e7490', '#7e22ce', '#b91c1c', '#166534', '#9d174d'
        ])[ranked.color_index + 1]
        FROM ranked
        WHERE vehicle.id = ranked.id
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE vehicles DROP COLUMN IF EXISTS color")
