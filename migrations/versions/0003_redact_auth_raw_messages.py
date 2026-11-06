"""Prevent raw registration/auth frames from retaining device secrets."""

from alembic import op

revision = "0003_redact_auth_raw_messages"
down_revision = "0002_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE raw_messages ADD COLUMN redacted_body_length INTEGER")
    op.execute("ALTER TABLE raw_messages ADD COLUMN redacted_body_hash BYTEA")
    # Existing sensitive rows cannot safely retain their original frame. The
    # frame/body are intentionally cleared while a digest and length remain.
    op.execute(
        """
        UPDATE raw_messages
        SET redacted_body_length = octet_length(body),
            redacted_body_hash = digest(body, 'sha256'),
            body = ''::bytea,
            raw_frame = ''::bytea
        WHERE message_id IN (256, 258)
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE raw_messages DROP COLUMN IF EXISTS redacted_body_hash")
    op.execute("ALTER TABLE raw_messages DROP COLUMN IF EXISTS redacted_body_length")
