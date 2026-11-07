from __future__ import annotations

import os
import unittest
from uuid import uuid4

import psycopg


API_URL = os.environ.get("TEST_API_DATABASE_URL", "")
SETUP_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and API_URL and SETUP_URL, "requires disposable PostgreSQL")
class AuthRlsTests(unittest.TestCase):
    def test_api_user_context_cannot_read_another_users_sessions_or_tokens(self) -> None:
        user_a = uuid4()
        user_b = uuid4()
        with psycopg.connect(SETUP_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, password_tokens, reauthentications TO fleet_api")
                for user_id in (user_a, user_b):
                    cursor.execute(
                        "INSERT INTO users (id, email, password_hash, created_at, updated_at, password_changed_at) "
                        "VALUES (%s, %s, 'test', now(), now(), now())",
                        (user_id, f"{user_id}@example.invalid"),
                    )
                cursor.execute(
                    "INSERT INTO sessions (user_id, session_hash, csrf_token_hash, idle_expires_at, absolute_expires_at) "
                    "VALUES (%s, digest(%s::text, 'sha256'), digest(%s::text, 'sha256'), now() + interval '1 hour', now() + interval '1 day')",
                    (user_b, str(uuid4()), str(uuid4())),
                )
                cursor.execute(
                    "INSERT INTO password_tokens (user_id, token_hash, expires_at) VALUES (%s, digest(%s::text, 'sha256'), now() + interval '1 hour')",
                    (user_b, str(uuid4())),
                )
        with psycopg.connect(API_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.user_id', %s, true)", (str(user_a),))
                cursor.execute("SELECT count(*) FROM sessions WHERE user_id = %s", (user_b,))
                self.assertEqual(cursor.fetchone()[0], 0)
                cursor.execute("SELECT count(*) FROM password_tokens WHERE user_id = %s", (user_b,))
                self.assertEqual(cursor.fetchone()[0], 0)

