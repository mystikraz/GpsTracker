from __future__ import annotations

import unittest

from fleet_tracker.db.migration_guard import migration_database_url


class MigrationGuardTests(unittest.TestCase):
    def test_requires_explicit_test_or_production_target(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "TEST_DATABASE_URL"):
            migration_database_url({})

    def test_test_target_must_be_direct(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "non-pooled"):
            migration_database_url({"TEST_DATABASE_URL": "postgresql://u:p@x-pooler.neon.tech/db"})

    def test_production_requires_direct_url_and_confirmation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "confirm-production"):
            migration_database_url({"DIRECT_DATABASE_URL": "postgresql://u:p@direct.neon.tech/db"})
        url, mode = migration_database_url(
            {
                "DIRECT_DATABASE_URL": "postgresql://u:p@direct.neon.tech/db",
                "MIGRATION_CONFIRM_PRODUCTION": "1",
            }
        )
        self.assertEqual(mode, "production")
        self.assertIn("direct.neon.tech", url)

