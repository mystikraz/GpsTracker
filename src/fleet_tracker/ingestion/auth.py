"""Provisioned-device authentication for the JT/T 808 connection lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from typing import Protocol


AUTH_CODE_LENGTH = 11


def validate_terminal_id(terminal_id: str) -> str:
    if len(terminal_id) != 12 or not terminal_id.isascii() or not terminal_id.isdecimal():
        raise ValueError("terminal ID must be exactly 12 ASCII digits")
    return terminal_id


def validate_auth_code(auth_code: str) -> str:
    if len(auth_code) != AUTH_CODE_LENGTH or not auth_code.isascii() or not auth_code.isdecimal():
        raise ValueError("authentication code must be exactly 11 ASCII digits")
    return auth_code


def generate_auth_code(terminal_id: str) -> str:
    """Generate an 11-digit secret, avoiding the observed default SN code."""

    terminal_id = validate_terminal_id(terminal_id)
    observed_default = terminal_id.lstrip("0")[-AUTH_CODE_LENGTH:]
    while True:
        code = "".join(str(secrets.randbelow(10)) for _ in range(AUTH_CODE_LENGTH))
        if code != observed_default:
            return code


def hash_auth_code(auth_code: str, pepper: bytes = b"") -> bytes:
    validate_auth_code(auth_code)
    return hmac.new(pepper, auth_code.encode("ascii"), hashlib.sha256).digest()


def verify_auth_code(auth_code: str, expected_hash: bytes, pepper: bytes = b"") -> bool:
    try:
        candidate = hash_auth_code(auth_code, pepper)
    except ValueError:
        return False
    return hmac.compare_digest(candidate, expected_hash)


class SecretProtector(Protocol):
    """Encrypt/decrypt the secret needed to answer future 0x0100 messages."""

    def encrypt(self, plaintext: str, *, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> str: ...


class PlaintextSecretProtector:
    """Test-only protector; production storage must use an authenticated cipher."""

    def encrypt(self, plaintext: str, *, associated_data: bytes) -> bytes:
        del associated_data
        return plaintext.encode("ascii")

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> str:
        del associated_data
        return ciphertext.decode("ascii")


class AesGcmSecretProtector:
    """AES-GCM envelope for device secrets.

    ``cryptography`` is imported lazily so the pure decoder and its fixtures can
    run without optional deployment dependencies. The production CLI fails
    clearly if this dependency is missing rather than silently storing secrets
    in plaintext.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES-GCM key must be 16, 24, or 32 bytes")
        self._key = key

    def encrypt(self, plaintext: str, *, associated_data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext.encode("ascii"), associated_data)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(ciphertext) < 13:
            raise ValueError("encrypted device secret is truncated")
        plaintext = AESGCM(self._key).decrypt(ciphertext[:12], ciphertext[12:], associated_data)
        return validate_auth_code(plaintext.decode("ascii"))


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    terminal_id: str
    organization_id: str
    vehicle_id: str
    auth_secret_hash: bytes
    auth_secret_ciphertext: bytes
    database_id: str | None = None
    active: bool = True


class DeviceRepository(Protocol):
    async def get_device(self, terminal_id: str) -> DeviceRecord | None: ...


class InMemoryDeviceRepository:
    def __init__(self) -> None:
        self.devices: dict[str, DeviceRecord] = {}

    async def get_device(self, terminal_id: str) -> DeviceRecord | None:
        return self.devices.get(terminal_id)

    def add(self, device: DeviceRecord) -> None:
        validate_terminal_id(device.terminal_id)
        self.devices[device.terminal_id] = device


async def provision_device(
    repository: InMemoryDeviceRepository,
    *,
    terminal_id: str,
    organization_id: str,
    vehicle_id: str,
    secret_protector: SecretProtector,
    auth_code: str | None = None,
    pepper: bytes = b"",
) -> DeviceRecord:
    terminal_id = validate_terminal_id(terminal_id)
    auth_code = validate_auth_code(auth_code) if auth_code is not None else generate_auth_code(terminal_id)
    device = DeviceRecord(
        terminal_id=terminal_id,
        organization_id=organization_id,
        vehicle_id=vehicle_id,
        auth_secret_hash=hash_auth_code(auth_code, pepper),
        auth_secret_ciphertext=secret_protector.encrypt(auth_code, associated_data=terminal_id.encode("ascii")),
    )
    repository.add(device)
    return device


class DeviceAuthenticator:
    def __init__(self, repository: DeviceRepository, secret_protector: SecretProtector, *, pepper: bytes = b"") -> None:
        self.repository = repository
        self.secret_protector = secret_protector
        self.pepper = pepper

    async def registration_code(self, terminal_id: str) -> tuple[DeviceRecord, str] | None:
        device = await self.repository.get_device(terminal_id)
        if device is None or not device.active:
            return None
        code = self.secret_protector.decrypt(
            device.auth_secret_ciphertext,
            associated_data=terminal_id.encode("ascii"),
        )
        return device, validate_auth_code(code)

    async def lookup(self, terminal_id: str) -> DeviceRecord | None:
        device = await self.repository.get_device(terminal_id)
        return device if device is not None and device.active else None

    async def authenticate(self, terminal_id: str, auth_code: str) -> DeviceRecord | None:
        device = await self.repository.get_device(terminal_id)
        if device is None or not device.active:
            return None
        if not verify_auth_code(auth_code, device.auth_secret_hash, self.pepper):
            return None
        return device
