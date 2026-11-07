from __future__ import annotations

import unittest
from uuid import uuid4

try:
    from fleet_tracker.db.tenant import TENANT_CONTEXT_SQL, organization_transaction
except ImportError as error:  # pragma: no cover - minimal local interpreters
    raise unittest.SkipTest(f"database dependencies unavailable: {error}") from error


class _FakeSession:
    def __init__(self) -> None:
        self.calls = []
        self.in_transaction_value = False

    def in_transaction(self) -> bool:
        return self.in_transaction_value

    def begin(self):
        session = self

        class Transaction:
            async def __aenter__(self):
                return session

            async def __aexit__(self, *args):
                return False

        return Transaction()

    async def execute(self, statement, params):
        self.calls.append((statement, params))


class TenantContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_context_is_transaction_local_and_uuid_bound(self) -> None:
        session = _FakeSession()
        organization_id = uuid4()
        async with organization_transaction(session, organization_id):
            pass
        self.assertIn("set_config('app.organization_id', :organization_id, true)", str(TENANT_CONTEXT_SQL))
        self.assertEqual(session.calls[0][1], {"organization_id": str(organization_id)})

    async def test_invalid_uuid_is_rejected_before_sql_execution(self) -> None:
        session = _FakeSession()
        with self.assertRaises(ValueError):
            async with organization_transaction(session, "not-a-uuid"):
                pass
        self.assertEqual(session.calls, [])

    async def test_existing_transaction_is_rejected(self) -> None:
        session = _FakeSession()
        session.in_transaction_value = True
        with self.assertRaises(RuntimeError):
            async with organization_transaction(session, uuid4()):
                pass


if __name__ == "__main__":
    unittest.main()
