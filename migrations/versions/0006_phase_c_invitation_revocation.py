"""Phase C invitation revocation state."""

from alembic import op

revision = "0006_invitation_revoke"
down_revision = "0005_phase_b_authentication"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE organization_invitations ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("ALTER TABLE organization_invitations DROP COLUMN IF EXISTS revoked_at")
