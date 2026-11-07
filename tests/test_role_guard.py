from __future__ import annotations

import unittest

try:
    from fleet_tracker.db.role_guard import API_ROLE_CHECK_SQL
except ImportError as error:  # pragma: no cover - minimal local interpreters
    raise unittest.SkipTest(f"database dependencies unavailable: {error}") from error


class RoleGuardTests(unittest.TestCase):
    def test_query_checks_all_api_bypass_properties(self) -> None:
        query = str(API_ROLE_CHECK_SQL)
        for field in ("rolsuper", "rolcreaterole", "rolbypassrls", "database_owner", "tenant_table_owner"):
            self.assertIn(field, query)


if __name__ == "__main__":
    unittest.main()
