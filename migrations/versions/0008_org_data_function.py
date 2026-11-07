"""Owner-controlled organization telemetry deletion function."""

from alembic import op

revision = "0008_org_data_delete"
down_revision = "0007_auth_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION fleet_delete_organization_data(target_org uuid)
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            DELETE FROM public.positions WHERE organization_id = target_org;
            DELETE FROM public.raw_messages WHERE organization_id = target_org;
            DELETE FROM public.outbox_events WHERE organization_id = target_org;
        END;
        $$;
        REVOKE ALL ON FUNCTION fleet_delete_organization_data(uuid) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION fleet_delete_organization_data(uuid) TO fleet_api;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS fleet_delete_organization_data(uuid)")
