from __future__ import annotations

import asyncio
import unittest
from datetime import UTC, datetime, timedelta

from fleet_tracker.auth_security import (
    PasswordPolicyError,
    PasswordService,
    ProcessRateLimiter,
    constant_time_equal,
    token_hash,
)
from fleet_tracker.csrf import CsrfError, cookie_header, validate_origin


class PhaseBSecurityTests(unittest.TestCase):
    def test_argon2id_hashing_policy_and_bounded_service(self) -> None:
        service = PasswordService(max_concurrency=1)
        with self.assertRaises(PasswordPolicyError):
            asyncio.run(service.hash("short"))
        with self.assertRaises(PasswordPolicyError):
            asyncio.run(service.hash("password123456"))
        encoded = asyncio.run(service.hash("correct horse battery staple"))
        self.assertTrue(encoded.startswith("$argon2id$"))
        self.assertTrue(asyncio.run(service.verify(encoded, "correct horse battery staple")))
        self.assertFalse(asyncio.run(service.verify(encoded, "wrong password")))

    def test_token_hash_is_one_way_and_constant_time_comparison(self) -> None:
        self.assertNotEqual(token_hash("secret-token"), b"secret-token")
        self.assertTrue(constant_time_equal(token_hash("a"), token_hash("a")))
        self.assertFalse(constant_time_equal(token_hash("a"), token_hash("b")))

    def test_process_limiter_is_per_ip_and_account(self) -> None:
        limiter = ProcessRateLimiter(per_ip=2, per_account=2, window_seconds=60)
        self.assertTrue(limiter.allow(ip="1.1.1.1", account="a@example.invalid"))
        self.assertTrue(limiter.allow(ip="1.1.1.1", account="b@example.invalid"))
        self.assertFalse(limiter.allow(ip="1.1.1.1", account="c@example.invalid"))
        account_limiter = ProcessRateLimiter(per_ip=20, per_account=2, window_seconds=60)
        self.assertTrue(account_limiter.allow(ip="1.1.1.1", account="a@example.invalid"))
        self.assertTrue(account_limiter.allow(ip="2.2.2.2", account="a@example.invalid"))
        self.assertFalse(account_limiter.allow(ip="3.3.3.3", account="a@example.invalid"))

    def test_origin_and_host_cookie(self) -> None:
        validate_origin(origin="https://fleet.example.invalid", host="fleet.example.invalid")
        with self.assertRaises(CsrfError):
            validate_origin(origin="https://evil.example.invalid", host="fleet.example.invalid")
        header = cookie_header("opaque", max_age=60)
        self.assertIn("__Host-fleet_session=opaque", header)
        self.assertIn("HttpOnly", header)
        self.assertIn("Secure", header)
        self.assertIn("SameSite=Lax", header)

