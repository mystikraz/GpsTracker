"""P2 identity, organization authorization, groups, sessions, and audit."""

from __future__ import annotations

from alembic import op

revision = "0004_p2_identity_authorization"
down_revision = "0003_redact_auth_raw_messages"
branch_labels = None
depends_on = None


TENANT_TABLES = (
    "vehicles",
    "devices",
    "device_vehicle_assignments",
    "raw_messages",
    "positions",
    "outbox_events",
    "organization_memberships",
    "organization_invitations",
    "user_groups",
    "vehicle_group_memberships",
    "membership_group_scopes",
    "audit_events",
)

ORGANIZATION_ROOT_TABLE = "organizations"


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    op.execute(
        """
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email CITEXT UNIQUE,
            password_hash TEXT NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE organization_memberships (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'admin', 'dispatcher', 'viewer')),
            status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'removed')),
            group_scope_mode VARCHAR(16) NOT NULL DEFAULT 'all' CHECK (group_scope_mode IN ('all', 'restricted')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            suspended_at TIMESTAMPTZ,
            removed_at TIMESTAMPTZ,
            UNIQUE (organization_id, user_id),
            UNIQUE (organization_id, id)
        );
        CREATE TABLE organization_invitations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            email CITEXT,
            role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'admin', 'dispatcher', 'viewer')),
            token_hash BYTEA NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            accepted_at TIMESTAMPTZ,
            invited_by UUID NOT NULL REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE user_groups (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (organization_id, name),
            UNIQUE (organization_id, id)
        );
        CREATE TABLE vehicle_group_memberships (
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            group_id UUID NOT NULL,
            vehicle_id UUID NOT NULL,
            PRIMARY KEY (group_id, vehicle_id),
            FOREIGN KEY (organization_id, group_id) REFERENCES user_groups(organization_id, id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id, vehicle_id) REFERENCES vehicles(organization_id, id) ON DELETE CASCADE
        );
        CREATE TABLE membership_group_scopes (
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            membership_id UUID NOT NULL,
            group_id UUID NOT NULL,
            PRIMARY KEY (membership_id, group_id),
            FOREIGN KEY (organization_id, membership_id) REFERENCES organization_memberships(organization_id, id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id, group_id) REFERENCES user_groups(organization_id, id) ON DELETE CASCADE
        );
        CREATE TABLE sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_hash BYTEA NOT NULL UNIQUE,
            csrf_token_hash BYTEA NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            idle_expires_at TIMESTAMPTZ NOT NULL,
            absolute_expires_at TIMESTAMPTZ NOT NULL,
            rotated_from_hash BYTEA,
            revoked_at TIMESTAMPTZ,
            revoke_reason VARCHAR(64),
            last_reauthenticated_at TIMESTAMPTZ,
            ip_address VARCHAR(64),
            user_agent_redacted TEXT
        );
        CREATE TABLE password_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash BYTEA NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            consumed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE reauthentications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            completed_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            purpose VARCHAR(64) NOT NULL
        );
        CREATE TABLE audit_events (
            id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            actor_user_id UUID REFERENCES users(id),
            organization_id UUID REFERENCES organizations(id),
            action VARCHAR(128) NOT NULL,
            target_type VARCHAR(64) NOT NULL,
            target_id VARCHAR(128),
            result VARCHAR(16) NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
            ip_address VARCHAR(64),
            user_agent_redacted TEXT,
            request_id VARCHAR(128) NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        );
        """
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_api_tenant_policy ON {table}
            TO fleet_api
            USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
            WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
            CREATE POLICY {table}_ingest_tenant_policy ON {table}
            TO fleet_ingest
            USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
            WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
            CREATE POLICY {table}_worker_tenant_policy ON {table}
            TO fleet_worker
            USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
            WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
            """
        )
    op.execute(
        """
        DO $$
        DECLARE table_name TEXT;
        BEGIN
            FOREACH table_name IN ARRAY ARRAY[
                'vehicles', 'devices', 'device_vehicle_assignments',
                'raw_messages', 'positions', 'outbox_events',
                'organization_memberships', 'organization_invitations',
                'user_groups', 'vehicle_group_memberships',
                'membership_group_scopes', 'audit_events'
            ] LOOP
                EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_ingest_tenant_policy', table_name);
                EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_worker_tenant_policy', table_name);
            END LOOP;
        END;
        $$;
        DROP POLICY raw_messages_api_tenant_policy ON raw_messages;
        DROP POLICY outbox_events_api_tenant_policy ON outbox_events;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit events are append-only';
        END;
        $$;
        CREATE TRIGGER audit_events_no_update
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
        CREATE INDEX ix_memberships_user ON organization_memberships (user_id, status);
        CREATE INDEX ix_invitations_pending ON organization_invitations (organization_id, expires_at)
            WHERE accepted_at IS NULL;
        CREATE INDEX ix_sessions_user_active ON sessions (user_id, revoked_at, absolute_expires_at);
        CREATE INDEX ix_password_tokens_active ON password_tokens (user_id, expires_at)
            WHERE consumed_at IS NULL;
        CREATE INDEX ix_audit_org_time ON audit_events (organization_id, occurred_at DESC);
        CREATE OR REPLACE FUNCTION revoke_member_sessions() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' OR NEW.status IN ('suspended', 'removed') THEN
                UPDATE sessions
                SET revoked_at = COALESCE(revoked_at, now()),
                    revoke_reason = COALESCE(revoke_reason, 'membership_' || lower(TG_OP))
                WHERE user_id = COALESCE(NEW.user_id, OLD.user_id)
                  AND revoked_at IS NULL;
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER organization_memberships_revoke_sessions
            AFTER INSERT OR UPDATE OF status OR DELETE ON organization_memberships
            FOR EACH ROW EXECUTE FUNCTION revoke_member_sessions();
        """
    )
    op.execute(
        """
        DO $$
        DECLARE role_name TEXT;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['fleet_api', 'fleet_ingest', 'fleet_worker'] LOOP
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    RAISE EXCEPTION 'required runtime role % does not exist; review and run the P2 role SQL first', role_name;
                END IF;
            END LOOP;
        END;
        $$;
        """
    )
    op.execute(
        """
        -- Ingestion discovers the organization from the globally unique
        -- terminal ID, then uses the transaction organization context.
        ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
        CREATE POLICY organizations_api_tenant_policy ON organizations
        TO fleet_api
        USING (id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
        WITH CHECK (id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY organizations_ingest_tenant_policy ON organizations
        TO fleet_ingest
        USING (id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
        WITH CHECK (id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY organizations_worker_tenant_policy ON organizations
        TO fleet_worker
        USING (id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
        WITH CHECK (id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

        DROP POLICY IF EXISTS devices_ingest_tenant_policy ON devices;
        CREATE POLICY devices_ingest_terminal_lookup_policy ON devices
        FOR SELECT TO fleet_ingest
        USING (terminal_id = NULLIF(current_setting('app.device_terminal_id', true), ''));

        DROP POLICY IF EXISTS device_vehicle_assignments_ingest_tenant_policy
            ON device_vehicle_assignments;
        CREATE POLICY device_assignments_ingest_tenant_policy
        ON device_vehicle_assignments
        FOR SELECT TO fleet_ingest
        USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

        DROP POLICY IF EXISTS raw_messages_ingest_tenant_policy ON raw_messages;
        DROP POLICY IF EXISTS positions_ingest_tenant_policy ON positions;
        DROP POLICY IF EXISTS outbox_events_ingest_tenant_policy ON outbox_events;
        CREATE POLICY raw_messages_ingest_insert_policy ON raw_messages
        FOR INSERT TO fleet_ingest
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY positions_ingest_insert_policy ON positions
        FOR INSERT TO fleet_ingest
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY outbox_events_ingest_insert_policy ON outbox_events
        FOR INSERT TO fleet_ingest
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

        DROP POLICY IF EXISTS organizations_api_tenant_policy ON organizations;
        DROP POLICY IF EXISTS organizations_ingest_tenant_policy ON organizations;
        DROP POLICY IF EXISTS organizations_worker_tenant_policy ON organizations;
        CREATE POLICY organizations_api_tenant_policy ON organizations
        FOR SELECT TO fleet_api
        USING (id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY organizations_worker_retention_policy ON organizations
        FOR SELECT TO fleet_worker
        USING (true);

        DROP POLICY IF EXISTS organization_memberships_api_tenant_policy
            ON organization_memberships;
        CREATE POLICY memberships_api_read_policy ON organization_memberships
        FOR SELECT TO fleet_api
        USING (
            user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
            OR organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
        );
        CREATE POLICY memberships_api_write_policy ON organization_memberships
        FOR INSERT TO fleet_api
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY memberships_api_update_delete_policy ON organization_memberships
        FOR ALL TO fleet_api
        USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

        DROP POLICY IF EXISTS audit_events_api_tenant_policy ON audit_events;
        DROP POLICY IF EXISTS audit_events_ingest_tenant_policy ON audit_events;
        DROP POLICY IF EXISTS audit_events_worker_tenant_policy ON audit_events;
        CREATE POLICY audit_events_api_read_policy ON audit_events
        FOR SELECT TO fleet_api
        USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        CREATE POLICY audit_events_api_insert_policy ON audit_events
        FOR INSERT TO fleet_api
        WITH CHECK (
            organization_id IS NULL
            OR organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
        );

        DROP POLICY IF EXISTS raw_messages_worker_tenant_policy ON raw_messages;
        DROP POLICY IF EXISTS positions_worker_tenant_policy ON positions;
        DROP POLICY IF EXISTS outbox_events_worker_tenant_policy ON outbox_events;
        CREATE POLICY raw_messages_worker_read_policy ON raw_messages
        FOR SELECT TO fleet_worker USING (true);
        CREATE POLICY raw_messages_worker_delete_policy ON raw_messages
        FOR DELETE TO fleet_worker USING (true);
        CREATE POLICY positions_worker_read_policy ON positions
        FOR SELECT TO fleet_worker USING (true);
        CREATE POLICY positions_worker_delete_policy ON positions
        FOR DELETE TO fleet_worker USING (true);
        CREATE POLICY outbox_events_worker_read_policy ON outbox_events
        FOR SELECT TO fleet_worker USING (true);
        CREATE POLICY outbox_events_worker_delete_policy ON outbox_events
        FOR DELETE TO fleet_worker USING (true);
        """
    )
    op.execute(
        """
        DO $$
        DECLARE child_name TEXT;
        BEGIN
            FOR child_name IN
                SELECT c.relname
                FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                WHERE i.inhparent = 'positions'::regclass
            LOOP
                EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', child_name);
                EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', child_name);
                EXECUTE format(
                    'CREATE POLICY %I ON %I TO fleet_api USING (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid) WITH CHECK (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid)',
                    child_name || '_api_tenant_policy', child_name
                );
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR INSERT TO fleet_ingest WITH CHECK (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid)',
                    child_name || '_ingest_insert_policy', child_name
                );
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR SELECT TO fleet_worker USING (true)',
                    child_name || '_worker_read_policy', child_name
                );
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR DELETE TO fleet_worker USING (true)',
                    child_name || '_worker_delete_policy', child_name
                );
            END LOOP;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION fleet_create_position_partition(
            p_start DATE,
            p_end DATE
        ) RETURNS TEXT
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
        DECLARE
            partition_name TEXT := format('positions_%s', to_char(p_start, 'YYYY_MM'));
        BEGIN
            IF p_start <> date_trunc('month', p_start)::date THEN
                RAISE EXCEPTION 'position partition start must be the first day of a month';
            END IF;
            IF p_end <> (p_start + INTERVAL '1 month')::date THEN
                RAISE EXCEPTION 'position partitions must cover exactly one month';
            END IF;
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF positions FOR VALUES FROM (%L) TO (%L)',
                partition_name, p_start, p_end
            );
            EXECUTE format(
                'CREATE UNIQUE INDEX IF NOT EXISTS %I ON %I (device_id, gps_timestamp)',
                partition_name || '_device_gps_time_uq', partition_name
            );
            EXECUTE format(
                'CREATE INDEX IF NOT EXISTS %I ON %I (organization_id, vehicle_id, gps_timestamp DESC)',
                partition_name || '_vehicle_time_ix', partition_name
            );
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', partition_name);
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public' AND tablename = partition_name
                  AND policyname = partition_name || '_api_tenant_policy'
            ) THEN
                EXECUTE format(
                    'CREATE POLICY %I ON %I TO fleet_api USING (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid) WITH CHECK (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid)',
                    partition_name || '_api_tenant_policy', partition_name
                );
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public' AND tablename = partition_name
                  AND policyname = partition_name || '_ingest_insert_policy'
            ) THEN
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR INSERT TO fleet_ingest WITH CHECK (organization_id = NULLIF(current_setting(''app.organization_id'', true), '''')::uuid)',
                    partition_name || '_ingest_insert_policy', partition_name
                );
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public' AND tablename = partition_name
                  AND policyname = partition_name || '_worker_read_policy'
            ) THEN
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR SELECT TO fleet_worker USING (true)',
                    partition_name || '_worker_read_policy', partition_name
                );
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public' AND tablename = partition_name
                  AND policyname = partition_name || '_worker_delete_policy'
            ) THEN
                EXECUTE format(
                    'CREATE POLICY %I ON %I FOR DELETE TO fleet_worker USING (true)',
                    partition_name || '_worker_delete_policy', partition_name
                );
            END IF;
            RETURN partition_name;
        END;
        $$;

        CREATE OR REPLACE FUNCTION fleet_drop_position_partition(p_partition_name TEXT)
        RETURNS VOID
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
        BEGIN
            IF p_partition_name !~ '^positions_[0-9]{4}_[0-9]{2}$' THEN
                RAISE EXCEPTION 'invalid position partition name';
            END IF;
            IF to_regclass(p_partition_name) IS NULL THEN
                RETURN;
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM pg_inherits AS i
                JOIN pg_class AS child ON child.oid = i.inhrelid
                WHERE i.inhparent = 'positions'::regclass
                  AND child.relname = p_partition_name
            ) THEN
                RAISE EXCEPTION 'not a positions partition';
            END IF;
            EXECUTE format('DROP TABLE %I', p_partition_name);
        END;
        $$;

        REVOKE ALL ON FUNCTION fleet_create_position_partition(DATE, DATE) FROM PUBLIC;
        REVOKE ALL ON FUNCTION fleet_drop_position_partition(TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION fleet_create_position_partition(DATE, DATE) TO fleet_worker;
        GRANT EXECUTE ON FUNCTION fleet_drop_position_partition(TEXT) TO fleet_worker;
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS organizations_worker_tenant_policy ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_ingest_tenant_policy ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_api_tenant_policy ON organizations")
    op.execute("ALTER TABLE organizations DISABLE ROW LEVEL SECURITY")
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {table}_worker_tenant_policy ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_ingest_tenant_policy ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_api_tenant_policy ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TRIGGER IF EXISTS organization_memberships_revoke_sessions ON organization_memberships")
    op.execute("DROP FUNCTION IF EXISTS revoke_member_sessions()")
    op.execute("DROP FUNCTION IF EXISTS fleet_drop_position_partition(TEXT)")
    op.execute("DROP FUNCTION IF EXISTS fleet_create_position_partition(DATE, DATE)")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_mutation()")
    for table in (
        "audit_events", "reauthentications", "password_tokens", "sessions",
        "membership_group_scopes", "vehicle_group_memberships", "user_groups",
        "organization_invitations", "organization_memberships", "users",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
