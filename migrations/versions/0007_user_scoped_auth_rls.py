"""User-scoped RLS for authentication records."""

from alembic import op

revision = "0007_auth_rls"
down_revision = "0006_invitation_revoke"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
        ALTER TABLE password_tokens ENABLE ROW LEVEL SECURITY;
        ALTER TABLE password_tokens FORCE ROW LEVEL SECURITY;
        ALTER TABLE reauthentications ENABLE ROW LEVEL SECURITY;
        ALTER TABLE reauthentications FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS sessions_api_user_policy ON sessions;
        DROP POLICY IF EXISTS password_tokens_api_user_policy ON password_tokens;
        DROP POLICY IF EXISTS reauthentications_api_user_policy ON reauthentications;
        CREATE POLICY sessions_api_user_policy ON sessions TO fleet_api
            USING (
                user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                OR session_hash = digest(current_setting('app.session_id', true), 'sha256')
            )
            WITH CHECK (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
        CREATE POLICY password_tokens_api_user_policy ON password_tokens TO fleet_api
            USING (
                user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                OR token_hash = digest(current_setting('app.reset_token', true), 'sha256')
            )
            WITH CHECK (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
        CREATE POLICY reauthentications_api_user_policy ON reauthentications TO fleet_api
            USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
            WITH CHECK (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP POLICY IF EXISTS sessions_api_user_policy ON sessions;
        DROP POLICY IF EXISTS password_tokens_api_user_policy ON password_tokens;
        DROP POLICY IF EXISTS reauthentications_api_user_policy ON reauthentications;
        ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;
        ALTER TABLE password_tokens NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE password_tokens DISABLE ROW LEVEL SECURITY;
        ALTER TABLE reauthentications NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE reauthentications DISABLE ROW LEVEL SECURITY;
        """
    )
