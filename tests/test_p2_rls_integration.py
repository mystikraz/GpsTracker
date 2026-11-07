"""Real-role RLS checks for the P2 migration.

Requires a disposable PostGIS database already migrated to head and these
variables:

    RUN_POSTGRES_TESTS=1
    TEST_DATABASE_URL=<owner/setup URL>
    TEST_API_DATABASE_URL=<fleet_api URL>
    TEST_INGEST_DATABASE_URL=<fleet_ingest URL>

The test never connects to Neon implicitly and does not run migrations.
"""

from __future__ import annotations

import os
import unittest
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

try:
    import psycopg
except ImportError as error:  # pragma: no cover
    raise unittest.SkipTest(f"psycopg unavailable: {error}") from error


if not os.environ.get("RUN_POSTGRES_TESTS"):
    raise unittest.SkipTest("set RUN_POSTGRES_TESTS=1 to run PostgreSQL integration tests")

SETUP_URL = os.environ.get("TEST_DATABASE_URL")
API_URL = os.environ.get("TEST_API_DATABASE_URL")
INGEST_URL = os.environ.get("TEST_INGEST_DATABASE_URL")
WORKER_URL = os.environ.get("TEST_WORKER_DATABASE_URL")
if not SETUP_URL or not API_URL or not INGEST_URL or not WORKER_URL:
    raise unittest.SkipTest(
        "set TEST_DATABASE_URL, TEST_API_DATABASE_URL, TEST_INGEST_DATABASE_URL, and TEST_WORKER_DATABASE_URL"
    )

from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.ingestion_store import PostgresIngestionStore
from fleet_tracker.db.provisioning import provision_postgres_device
from fleet_tracker.ingestion.auth import PlaintextSecretProtector
from fleet_tracker.ingestion.auth import DeviceAuthenticator
from fleet_tracker.ingestion.processor import ConnectionState, MessageProcessor
from fleet_tracker.protocol.jt808 import AUTHENTICATION_MESSAGE_ID, decode_frame, encode_frame

FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}


def apply_documented_role_grants(connection) -> None:
    """Apply active GRANT/REVOKE statements from the reviewed role SQL."""

    role_sql = Path(__file__).parents[1].joinpath("docs", "P2_DATABASE_ROLES.sql").read_text()
    uncommented = "\n".join(
        line for line in role_sql.splitlines() if not line.lstrip().startswith("--")
    )
    with connection.cursor() as cursor:
        for statement in uncommented.split(";"):
            statement = statement.strip()
            if statement.upper().startswith(("GRANT ", "REVOKE ")):
                cursor.execute(statement)


class P2RlsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.org_a = uuid4()
        cls.org_b = uuid4()
        cls.vehicle_a = uuid4()
        cls.vehicle_b = uuid4()
        cls.user_id = uuid4()
        cls.device_a = uuid4()
        cls.device_b = uuid4()
        with psycopg.connect(SETUP_URL) as connection:
            apply_documented_role_grants(connection)
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO organizations (id, name) VALUES (%s, %s), (%s, %s)",
                    (cls.org_a, "RLS A", cls.org_b, "RLS B"),
                )
                cursor.execute(
                    "SELECT set_config('app.organization_id', %s, true)",
                    (str(cls.org_a),),
                )
                cursor.execute(
                    "INSERT INTO vehicles (id, organization_id, name, created_at) VALUES (%s, %s, %s, now())",
                    (cls.vehicle_a, cls.org_a, "A"),
                )
                cursor.execute(
                    "SELECT set_config('app.organization_id', %s, true)",
                    (str(cls.org_b),),
                )
                cursor.execute(
                    "INSERT INTO vehicles (id, organization_id, name, created_at) VALUES (%s, %s, %s, now())",
                    (cls.vehicle_b, cls.org_b, "B"),
                )
                cursor.execute(
                    "INSERT INTO users (id, email, password_hash) VALUES (%s, %s, 'test-hash')",
                    (cls.user_id, "rls-user@example.invalid"),
                )
                cursor.execute(
                    "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES (%s, %s, 'viewer'), (%s, %s, 'viewer')",
                    (cls.org_a, cls.user_id, cls.org_b, cls.user_id),
                )
                cursor.execute(
                    "INSERT INTO devices (id, organization_id, terminal_id, auth_secret_hash, auth_secret_ciphertext, created_at, secret_rotated_at) VALUES "
                    "(%s, %s, '000000000001', 'a', 'a', now(), now()), (%s, %s, '000000000002', 'b', 'b', now(), now())",
                    (cls.device_a, cls.org_a, cls.device_b, cls.org_b),
                )
                cursor.execute(
                    "INSERT INTO raw_messages (organization_id, device_id, received_at, message_id, terminal_serial, raw_frame, body, authenticated, parser_status, created_at) VALUES "
                    "(%s, %s, '2020-01-01T00:00:00Z', 2, 1, '', '', true, 'test', now()), "
                    "(%s, %s, '2020-01-01T00:00:00Z', 2, 1, '', '', true, 'test', now())",
                    (cls.org_a, cls.device_a, cls.org_b, cls.device_b),
                )
                cursor.execute(
                    "SELECT fleet_create_position_partition(%s, %s)",
                    ("2099-01-01", "2099-02-01"),
                )

    def test_runtime_roles_cannot_bypass_rls(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT rolname, rolsuper, rolcreaterole, rolbypassrls FROM pg_roles "
                    "WHERE rolname IN ('fleet_api', 'fleet_ingest', 'fleet_worker') ORDER BY rolname"
                )
                self.assertEqual(
                    cursor.fetchall(),
                    [
                        ("fleet_api", False, False, False),
                        ("fleet_ingest", False, False, False),
                        ("fleet_worker", False, False, False),
                    ],
                )

    def test_every_tenant_table_is_force_rls_with_three_role_policies(self) -> None:
        tenant_tables = (
            "organizations",
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
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
                    "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' AND c.relname = ANY(%s)",
                    (list(tenant_tables),),
                )
                self.assertEqual(
                    {row[0]: (row[1], row[2]) for row in cursor.fetchall()},
                    {table: (True, True) for table in tenant_tables},
                )
                cursor.execute(
                    "SELECT p.tablename, array_agg(role_name ORDER BY role_name) "
                    "FROM pg_policies AS p, unnest(p.roles) AS role_name "
                    "WHERE schemaname = 'public' AND tablename = ANY(%s) "
                    "GROUP BY tablename",
                    (list(tenant_tables),),
                )
                policies = {row[0]: row[1] for row in cursor.fetchall()}
                expected_roles = {
                    "organizations": {"fleet_api", "fleet_worker"},
                    "vehicles": {"fleet_api"},
                    "devices": {"fleet_api", "fleet_ingest"},
                    "device_vehicle_assignments": {"fleet_api", "fleet_ingest"},
                    "raw_messages": {"fleet_ingest", "fleet_worker"},
                    "positions": {"fleet_api", "fleet_ingest", "fleet_worker"},
                    "outbox_events": {"fleet_ingest", "fleet_worker"},
                    "organization_memberships": {"fleet_api"},
                    "organization_invitations": {"fleet_api"},
                    "user_groups": {"fleet_api"},
                    "vehicle_group_memberships": {"fleet_api"},
                    "membership_group_scopes": {"fleet_api"},
                    "audit_events": {"fleet_api"},
                }
                for table, roles in expected_roles.items():
                    self.assertEqual(set(policies.get(table, [])), roles, table)

    def test_api_and_ingest_cannot_call_partition_security_definers(self) -> None:
        for url in (API_URL, INGEST_URL):
            with psycopg.connect(url) as connection:
                with connection.cursor() as cursor:
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        cursor.execute(
                            "SELECT fleet_create_position_partition(%s, %s)",
                            ("2099-02-01", "2099-03-01"),
                        )
                    connection.rollback()
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        cursor.execute("SELECT fleet_drop_position_partition(%s)", ("positions_2099_02",))

    def test_unset_context_returns_no_rows_and_cross_tenant_read_write_is_denied(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM vehicles")
                self.assertEqual(cursor.fetchone()[0], 0)
                cursor.execute("SELECT set_config('app.organization_id', %s, true)", (str(self.org_a),))
                cursor.execute("SELECT id FROM vehicles ORDER BY id")
                self.assertEqual({row[0] for row in cursor.fetchall()}, {self.vehicle_a})
                cursor.execute("SELECT set_config('app.organization_id', %s, true)", (str(self.org_b),))
                cursor.execute("SELECT id FROM vehicles WHERE id = %s", (self.vehicle_a,))
                self.assertIsNone(cursor.fetchone())
                cursor.execute("UPDATE vehicles SET name = 'cross-tenant' WHERE id = %s", (self.vehicle_a,))
                self.assertEqual(cursor.rowcount, 0)
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    cursor.execute(
                        "INSERT INTO vehicles (organization_id, name, created_at) VALUES (%s, 'cross-tenant', now())",
                        (self.org_a,),
                    )

    def test_api_can_write_pre_auth_audit_event_with_null_organization(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO audit_events (organization_id, action, target_type, result, request_id) "
                    "VALUES (NULL, 'login.failure', 'user', 'failure', %s)",
                    (str(uuid4()),),
                )

    def test_user_context_lists_memberships_before_organization_context(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.user_id', %s, true)", (str(self.user_id),))
                cursor.execute(
                    "SELECT organization_id FROM organization_memberships ORDER BY organization_id"
                )
                self.assertEqual({row[0] for row in cursor.fetchall()}, {self.org_a, self.org_b})

    def test_worker_retention_deletes_expired_rows_across_both_organizations(self) -> None:
        async def run_worker() -> int:
            engine, sessions = create_engine_and_session_factory(WORKER_URL)
            try:
                store = PostgresIngestionStore(sessions, PlaintextSecretProtector())
                return await store.purge_expired_raw_messages(
                    now=datetime(2026, 11, 7, tzinfo=timezone.utc)
                )
            finally:
                await engine.dispose()

        self.assertEqual(asyncio.run(run_worker()), 2)
        with psycopg.connect(WORKER_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM raw_messages")
                # The ingestion replay test runs earlier and leaves current
                # (non-expired) raw rows. Only the two seeded expired rows
                # must be removed across both organizations.
                self.assertEqual(cursor.fetchone()[0], 6)

    def test_fleet_ingest_replays_registration_auth_position_and_batch_without_context(self) -> None:
        async def run_ingest() -> int:
            owner_engine, owner_sessions = create_engine_and_session_factory(SETUP_URL)
            try:
                device_id, _ = await provision_postgres_device(
                    owner_sessions,
                    organization_id=str(self.org_a),
                    vehicle_id=str(self.vehicle_a),
                    terminal_id="999900001234",
                    secret_protector=PlaintextSecretProtector(),
                    auth_code="12345678901",
                )
            finally:
                await owner_engine.dispose()

            ingest_engine, ingest_sessions = create_engine_and_session_factory(INGEST_URL)
            try:
                store = PostgresIngestionStore(ingest_sessions, PlaintextSecretProtector())
                processor = MessageProcessor(
                    DeviceAuthenticator(store, PlaintextSecretProtector()),
                    store,
                )
                state = ConnectionState()
                received_at = datetime(2026, 11, 7, tzinfo=timezone.utc)
                frames = (
                    decode_frame(bytes.fromhex(BY_NAME["registration"]["frame_hex"])),
                    decode_frame(encode_frame(AUTHENTICATION_MESSAGE_ID, "999900001234", 1, b"12345678901")),
                    decode_frame(bytes.fromhex(BY_NAME["position_fix_serial12"]["frame_hex"])),
                    decode_frame(bytes.fromhex(BY_NAME["batch_0704_serial3"]["frame_hex"])),
                )
                results = []
                for frame in frames:
                    results.append(await processor.process(frame, state, received_at=received_at))
                replay_results = []
                for frame in frames[2:]:
                    replay_results.append(await processor.process(frame, state, received_at=received_at))
                self.assertTrue(results[1].authenticated)
                self.assertEqual(results[2].stored_positions, 1)
                self.assertEqual(results[3].stored_positions, 4)
                self.assertEqual([result.stored_positions for result in replay_results], [0, 0])
                return int(device_id is not None)
            finally:
                await ingest_engine.dispose()

        self.assertEqual(asyncio.run(run_ingest()), 1)

    def test_ingest_has_no_telemetry_select_and_no_returning_dependency(self) -> None:
        with psycopg.connect(INGEST_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT has_table_privilege('fleet_ingest', 'raw_messages', 'SELECT'), "
                    "has_table_privilege('fleet_ingest', 'outbox_events', 'SELECT')"
                )
                self.assertEqual(cursor.fetchone(), (False, False))
        source = Path("src/fleet_tracker/db/ingestion_store.py").read_text(encoding="utf-8")
        self.assertNotIn("RETURNING", source.upper())

    def test_connection_reuse_does_not_leak_between_tenants(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                for organization_id, vehicle_id in ((self.org_a, self.vehicle_a), (self.org_b, self.vehicle_b)):
                    cursor.execute("SELECT set_config('app.organization_id', %s, true)", (str(organization_id),))
                    cursor.execute("SELECT id FROM vehicles")
                    self.assertEqual({row[0] for row in cursor.fetchall()}, {vehicle_id})
                    connection.commit()
                cursor.execute("SELECT count(*) FROM vehicles")
                self.assertEqual(cursor.fetchone()[0], 0)

    def test_direct_partition_access_is_denied(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                with self.assertRaises((psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedTable)):
                    cursor.execute("SELECT count(*) FROM positions_2099_01")
                connection.rollback()
                cursor.execute("SELECT has_table_privilege(current_user, 'positions_2099_01', 'SELECT')")
                self.assertFalse(cursor.fetchone()[0])

    def test_partition_functions_are_owner_owned_and_not_runtime_executable(self) -> None:
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT p.proname, pg_get_userbyid(p.proowner), "
                    "has_function_privilege(current_user, p.oid, 'EXECUTE') "
                    "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'public' AND p.proname IN "
                    "('fleet_create_position_partition', 'fleet_drop_position_partition') "
                    "ORDER BY p.proname"
                )
                rows = cursor.fetchall()
                self.assertEqual([row[0] for row in rows], ["fleet_create_position_partition", "fleet_drop_position_partition"])
                self.assertTrue(all(row[1] not in {"fleet_api", "fleet_ingest", "fleet_worker"} for row in rows))
                self.assertTrue(all(row[2] is False for row in rows))

    def test_audit_events_are_append_only_for_api_role(self) -> None:
        with psycopg.connect(SETUP_URL) as setup:
            with setup.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO audit_events (organization_id, action, target_type, result, request_id) "
                    "VALUES (%s, 'test', 'test', 'success', %s) RETURNING id",
                    (self.org_a, str(uuid4())),
                )
                audit_id = cursor.fetchone()[0]
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.organization_id', %s, true)", (str(self.org_a),))
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    cursor.execute("UPDATE audit_events SET action = 'changed' WHERE id = %s", (audit_id,))
                connection.rollback()
                cursor.execute("SELECT set_config('app.organization_id', %s, true)", (str(self.org_a),))
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    cursor.execute("DELETE FROM audit_events WHERE id = %s", (audit_id,))


if __name__ == "__main__":
    unittest.main()
