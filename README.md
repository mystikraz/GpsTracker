# JT/T 808 fixtures (PG07 tracker)

`jt808_fixtures.json` holds synthetic JT/T 808 fixtures derived from a PG07 4G capture, plus derived negative cases. The original capture is kept only in the gitignored `.local/captures/` folder.

## Provenance
- `captured_auth_frames_exact`: 8 complete frames exactly as received (auth, serials 1-8).
- Every other fixture: the **message body was captured from the device**; the header, XOR checksum, escaping and
  0x7E flags were rebuilt with the same framing rules. The rebuild was verified by regenerating all 8 captured
  auth frames byte for byte.
- `negative_fixtures` are derived from a captured frame by corrupting it.

## Framing rules (confirmed by the data)
- Frame = 0x7E, escaped(header + body + checksum), 0x7E. Escape: 0x7D->0x7D01, 0x7E->0x7D02.
- Header (12 bytes): msg id(2), body properties(2, low 10 bits = body length), terminal id BCD(6), serial(2).
- Checksum = XOR of every byte from msg id through the last body byte (before escaping).
- Device serial restarts at 1 on every reconnect, so do NOT use it for deduplication. Use (device, GPS time).

## Things the fixtures exercise
- `position_fix_serial*`: the course field is 0x007E, so the frame contains an escaped byte (tests unescaping).
- `position_no_fix`: status bit1 = 0 and lat/lon = 0. Must not be stored.
- `batch_0704_*`: 4 buffered positions each; item length(2) + a 0x0200 body.
- Tracker clock is **UTC+8**. Each position lists `device_time_raw` and the expected `utc`.
- Altitude is a signed value in some fixtures (0xFF11 = -239), parse as signed if you store it.
- `frame_has_escape_sequence` flags frames that contain 0x7D bytes.

## Before sharing or committing this repo publicly
The fixtures contain this device's terminal id, its auth code (equal to the serial number printed on the box,
which is also the vendor app's default login) and its SIM ICCID (inside `vendor_1107_info`). Replace them with
test values in any public repository, and rotate the device secret once the new system issues its own.

## P1 implementation

The P1 code lives under `src/fleet_tracker/`:

- `protocol/jt808.py` is a pure decoder/encoder with strict escaping, checksum,
  body-length, BCD timestamp, position, TLV, and `0x0704` batch handling.
- `ingestion/processor.py` performs the provisioned-device registration and
  authentication state machine. It accepts reconnects that send `0x0102`
  directly, and never persists unauthenticated telemetry.
- `db/` contains the PostgreSQL/PostGIS metadata, Alembic migration, and
  transactional raw-message/position/outbox store.
- Positions are partitioned by GPS month. Each partition has a unique
  `(device_id, gps_timestamp)` index; terminal serials are intentionally not
  used for deduplication.
- Raw frames are retained according to the organization policy, defaulting to
  30 days. P1's maintenance worker enforces that policy.
- The default deployment budget is suitable for the agreed 4 GB EC2 host: Neon
  owns PostgreSQL memory/storage, while Compose limits reserve 256 MB each for
  ingestion, migration, and maintenance worker, leaving room for the OS and
  later services.
- At the agreed maximum rate, 50 devices produce about 3.3 positions/second,
  288,000 positions/day, and roughly 105 million positions/year. RAM is within
  the host assumption, but final EBS sizing must be confirmed before production
  cutover; P5 downsampling and retention will control long-term growth.

The fixture/auth tests can run without third-party packages in the managed
local interpreter:

```text
PYTHONPATH=src python -m unittest tests.test_jt808 tests.test_ingestion tests.test_tcp_simulator
```

Normal development uses the pytest configuration in `pyproject.toml`.

With a provisioned device in the database, the reusable simulator can replay
the fixtures against TCP 8881 and exercise the reconnect path:

```text
uv run fleet-tracker-replay --host 127.0.0.1 --port 8881 --reconnect
```

## P1 stack with Neon

Create the Neon project/database, then copy `.env.example` to `.env`. Set
`DATABASE_URL` to the pooled Neon connection string (the hostname contains
`-pooler`) and `DIRECT_DATABASE_URL` to the unpooled/direct connection string.
Replace both secret placeholders with independently generated URL-safe base64
secrets. The migration enables PostGIS on Neon and should be run with the
direct URL; ingestion and worker use the pooled URL.

Then run:

```text
docker compose up --build
```

The Compose profile runs the migration against Neon, listens for trackers on
TCP 8881, and runs raw-message retention maintenance. There is intentionally
no local database container. The HTTP API, web application, Caddy, and
alert/trip consumers are added in later phases.

Use the direct URL for migrations, provisioning/admin CLI work, and future
`pg_dump` backups. Runtime services must not depend on session state, `SET`, or
`LISTEN/NOTIFY`; Neon pooled connections use transaction pooling.

For local provisioning, create an organization and vehicle, then provision a
device before sending it any tracker traffic:

```text
docker compose run --rm ingestion fleet-tracker create-organization --name "Example Fleet"
docker compose run --rm ingestion fleet-tracker create-vehicle --org-id <org-id> --name "Vehicle 1"
docker compose run --rm ingestion fleet-tracker provision-device --org-id <org-id> --vehicle-id <vehicle-id> --terminal-id 999900001234
```

The generated code is stored encrypted for future `0x0100` responses and
stored separately as a keyed hash for `0x0102` verification. It is never
written to logs. The fixture's observed code is available only for replay and
the controlled migration procedure below.

## Existing-device canary and rollback

The existing prototype remains the rollback target. Do not point the device at
the new service until the device record and vehicle assignment exist.

1. Keep the prototype listening on TCP 8881.
2. Start the new P1 ingestion stack on temporary TCP 8882 and temporarily
   allow that port in the EC2 security group. The new ingestion service writes
   to Neon while the prototype remains on its existing SQLite database; do not
   configure both services to receive the same device simultaneously unless an
   explicit fan-out test has been designed.
3. Provision the existing terminal with its currently stored code
   `58392017406`, because this device reconnects with `0x0102` and does not
   receive a new `0x8100` response on every reconnect. Treat this as a
   time-bounded migration secret, not the production default.
4. Send `SL DP<ip>#8882#` by SMS. Confirm the new service accepts the direct
   `0x0102`, authenticated heartbeats, and positions.
5. If the canary fails, send `SL DP<ip>#8881#` and confirm the prototype
   resumes receiving the device. Keep the new database and logs intact for
   diagnosis; do not delete them during rollback.
6. After approval, schedule final cutover: stop the prototype, move the new
   service to TCP 8881, and repeat the SMS configuration. Keep the prototype
   deployment available until the observation window closes.

The alternate-auth-code test is included in the simulated tracker tests: the
server can issue and verify an 11-digit code different from the terminal SN.
Validating whether the physical PG07 accepts that code requires a controlled
`0x0100` registration event on hardware. If it does not, roll back by SMS and
keep the observed code strategy for that device until the hardware behavior is
understood. Raw JT/T 808 has no TLS or VPN on this hardware; that residual
confidentiality and replay risk is documented and is not a P1 blocker.

For the temporary-port cutover, SMS endpoint change, verification, and rollback
procedure, see `docs/CUTOVER_RUNBOOK.md`. For a provisioned device with a wrong
auth code, the service returns a JT/T 808 `0x8001` failure and closes the
connection. The real PG07's next retry behavior has not been observed on
hardware and must be recorded during the canary.

## Known fixture limits

The fixtures include reconnect-style authentication, escaped positions, no-fix
positions, signed altitude, vendor messages, and buffered batches. Alarm-bit
semantics, non-zero speed, platform-originated `0x8xxx` messages, and real
southern/western hemisphere samples remain unverified.
