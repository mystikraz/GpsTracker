"""Phase B password authentication and lockout state."""

from alembic import op

revision = "0005_phase_b_authentication"
down_revision = "0004_p2_identity_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
        CREATE INDEX IF NOT EXISTS ix_users_login_lock
            ON users (email, locked_until);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS ix_users_login_lock;
        ALTER TABLE users
            DROP COLUMN IF EXISTS locked_until,
            DROP COLUMN IF EXISTS failed_login_count;
        """
    )
