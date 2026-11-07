"""P3 vehicle latest-state projection for map and live updates."""

from alembic import op


revision = "0009_p3_latest_state"
down_revision = "0008_org_data_delete"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE vehicle_latest_state (
            organization_id UUID NOT NULL,
            vehicle_id UUID NOT NULL,
            device_id UUID NOT NULL,
            last_authenticated_message_at TIMESTAMPTZ,
            last_position_at TIMESTAMPTZ,
            gps_timestamp TIMESTAMPTZ,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            speed_kmh DOUBLE PRECISION,
            course INTEGER,
            status BIGINT,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (organization_id, vehicle_id),
            FOREIGN KEY (organization_id, vehicle_id)
                REFERENCES vehicles(organization_id, id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id, device_id)
                REFERENCES devices(organization_id, id) ON DELETE CASCADE,
            CHECK (latitude IS NULL OR latitude BETWEEN -90 AND 90),
            CHECK (longitude IS NULL OR longitude BETWEEN -180 AND 180),
            CHECK (speed_kmh IS NULL OR speed_kmh >= 0),
            CHECK (course IS NULL OR course BETWEEN 0 AND 359)
        );
        CREATE INDEX vehicle_latest_state_org_updated_idx
            ON vehicle_latest_state (organization_id, updated_at, vehicle_id);
        ALTER TABLE vehicle_latest_state ENABLE ROW LEVEL SECURITY;
        ALTER TABLE vehicle_latest_state FORCE ROW LEVEL SECURITY;
        CREATE POLICY vehicle_latest_state_api_read_policy
            ON vehicle_latest_state FOR SELECT TO fleet_api
            USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
        GRANT SELECT ON vehicle_latest_state TO fleet_api;

        CREATE OR REPLACE FUNCTION refresh_vehicle_latest_from_raw()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NEW.authenticated THEN
                INSERT INTO vehicle_latest_state (
                    organization_id, vehicle_id, device_id,
                    last_authenticated_message_at, updated_at
                )
                SELECT
                    NEW.organization_id, a.vehicle_id, NEW.device_id,
                    NEW.received_at, NEW.received_at
                FROM device_vehicle_assignments AS a
                WHERE a.organization_id = NEW.organization_id
                  AND a.device_id = NEW.device_id
                  AND a.effective_from <= NEW.received_at
                  AND (a.effective_to IS NULL OR a.effective_to > NEW.received_at)
                ORDER BY a.effective_from DESC
                LIMIT 1
                ON CONFLICT (organization_id, vehicle_id) DO UPDATE
                SET device_id = EXCLUDED.device_id,
                    last_authenticated_message_at = GREATEST(
                        COALESCE(vehicle_latest_state.last_authenticated_message_at, EXCLUDED.last_authenticated_message_at),
                        EXCLUDED.last_authenticated_message_at
                    ),
                    updated_at = GREATEST(vehicle_latest_state.updated_at, EXCLUDED.updated_at);
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE OR REPLACE FUNCTION refresh_vehicle_latest_from_position()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            INSERT INTO vehicle_latest_state (
                organization_id, vehicle_id, device_id,
                last_position_at, gps_timestamp, latitude, longitude,
                speed_kmh, course, status, updated_at
            ) VALUES (
                NEW.organization_id, NEW.vehicle_id, NEW.device_id,
                NEW.received_at, NEW.gps_timestamp, NEW.latitude, NEW.longitude,
                NEW.speed_kmh, NEW.course, NEW.status, NEW.received_at
            )
            ON CONFLICT (organization_id, vehicle_id) DO UPDATE
            SET device_id = EXCLUDED.device_id,
                last_position_at = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.last_position_at ELSE vehicle_latest_state.last_position_at END,
                gps_timestamp = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.gps_timestamp ELSE vehicle_latest_state.gps_timestamp END,
                latitude = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.latitude ELSE vehicle_latest_state.latitude END,
                longitude = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.longitude ELSE vehicle_latest_state.longitude END,
                speed_kmh = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.speed_kmh ELSE vehicle_latest_state.speed_kmh END,
                course = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.course ELSE vehicle_latest_state.course END,
                status = CASE
                    WHEN vehicle_latest_state.gps_timestamp IS NULL
                      OR EXCLUDED.gps_timestamp >= vehicle_latest_state.gps_timestamp
                    THEN EXCLUDED.status ELSE vehicle_latest_state.status END,
                updated_at = GREATEST(vehicle_latest_state.updated_at, EXCLUDED.updated_at);
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER positions_refresh_latest_state
            AFTER INSERT ON positions
            FOR EACH ROW EXECUTE FUNCTION refresh_vehicle_latest_from_position();
        CREATE TRIGGER raw_messages_refresh_latest_state
            AFTER INSERT ON raw_messages
            FOR EACH ROW EXECUTE FUNCTION refresh_vehicle_latest_from_raw();

        REVOKE ALL ON FUNCTION refresh_vehicle_latest_from_raw() FROM PUBLIC;
        REVOKE ALL ON FUNCTION refresh_vehicle_latest_from_position() FROM PUBLIC;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TRIGGER IF EXISTS raw_messages_refresh_latest_state ON raw_messages;
        DROP TRIGGER IF EXISTS positions_refresh_latest_state ON positions;
        DROP FUNCTION IF EXISTS refresh_vehicle_latest_from_raw();
        DROP FUNCTION IF EXISTS refresh_vehicle_latest_from_position();
        DROP TABLE IF EXISTS vehicle_latest_state;
        """
    )
