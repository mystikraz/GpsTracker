# PG07 ingestion canary and cutover

This runbook uses the staging database URL from `.env.example`/`.env`. Do not
substitute the production or main Neon URL during the test-branch step.

## Preflight and migration gate

1. Copy `.env.example` to `.env` and set `DATABASE_URL` and
   `DIRECT_DATABASE_URL` to the staging/test Neon branch. Keep the main Neon
   URL out of this file while testing.
2. Apply migrations to the Neon test branch first:

   ```text
   docker compose run --rm migrate
   ```

   Confirm `0002_hardening` is current and verify `postgis` and `btree_gist`
   with a read-only query. Do not apply migrations to Neon main until explicit
   approval is recorded from the owner.
3. Before opening the canary listener, take the normal database/log backup and
   record the current prototype health.

## Temporary listener and security group

Run the new listener on TCP 8882:

```text
TRACKER_PORT=8882 docker compose up -d --build migrate ingestion worker
```

Open inbound TCP `8882` from `0.0.0.0/0` temporarily. The PG07 carrier/SIM
source address is not stable or reliably knowable in advance, so an IP allowlist
would risk dropping the tracker. Restrict the rule to TCP 8882 only, keep the
canary window short, monitor connection/auth logs, and remove the rule after
cutover. Do not expose database ports.

## Provision the concrete PG07

The canary device is terminal `071604184647` and currently sends initial auth
code `71604184647`.

Do not put the auth code in argv or print it. Load it from a protected
environment/secret store or pipe it to stdin:

```text
INITIAL_AUTH_CODE=71604184647 docker compose run --rm ingestion fleet-tracker provision-device --org-id <org-id> --vehicle-id <vehicle-id> --terminal-id 071604184647 --initial-auth-code
```

The command stores the code encrypted and hashed; it does not print the code.
If using stdin instead, omit `INITIAL_AUTH_CODE` and pipe the secret to the
same command. Confirm the device assignment exists before changing its SMS
endpoint.

## Point the PG07 at the canary

Send exactly:

```text
SL DP15.207.134.172#8882#
```

Expected device reply:

```text
Set ok!IP:15.207.134.172 8882
```

Confirm the configured endpoint with:

```text
SL CX
```

Record the SMS delivery, reply, and `SL CX` result in the canary notes.

## Verification

Expected ingestion log lines include:

```text
tracker_ingestion_started addresses=('0.0.0.0', 8882)
ingestion_message_accepted source_ip=<carrier-ip> terminal_id=071604184647 message_id=0x0102 parser_status=authenticated stored_positions=0
ingestion_message_accepted source_ip=<carrier-ip> terminal_id=071604184647 message_id=0x0200 parser_status=position_fix stored_positions=1
ingestion_message_accepted source_ip=<carrier-ip> terminal_id=071604184647 message_id=0x0704 parser_status=batch_positions stored_positions=<n>
```

No auth code is logged. A persistence failure must instead produce
`message_persistence_failed` and no `0x8001` ACK.

Query recent positions for the assigned vehicle using the direct staging URL:

```sql
SELECT
    p.gps_timestamp AT TIME ZONE 'UTC' AS gps_timestamp_utc,
    p.received_at AT TIME ZONE 'UTC' AS received_at_utc,
    p.latitude,
    p.longitude,
    p.speed_kmh,
    p.course
FROM positions AS p
JOIN vehicles AS v ON v.id = p.vehicle_id
WHERE v.organization_id = '<org-id>'::uuid
  AND v.id = '<vehicle-id>'::uuid
  AND p.device_id = (
      SELECT d.id FROM devices AS d
      WHERE d.terminal_id = '071604184647'
  )
  AND p.gps_timestamp >= now() - INTERVAL '15 minutes'
ORDER BY p.gps_timestamp DESC;
```

Check that stored UTC is current, not merely parseable:

```sql
SELECT
    clock_timestamp() AT TIME ZONE 'UTC' AS database_now_utc,
    max(p.gps_timestamp) AT TIME ZONE 'UTC' AS latest_gps_utc,
    EXTRACT(EPOCH FROM (clock_timestamp() - max(p.gps_timestamp))) AS age_seconds
FROM positions AS p
JOIN devices AS d ON d.id = p.device_id
WHERE d.terminal_id = '071604184647';
```

Compare `latest_gps_utc` with actual current UTC and the tracker's reported
time. Allow for device-clock and transport delay; investigate a timezone-sized
offset rather than accepting it as normal.

During the canary, explicitly record what the real PG07 does after receiving an
auth-failure `0x8001`: whether it retries, reconnects, sends registration again,
or remains silent, and the delay before any retry.

## Prototype and reconnect behavior

The prototype dashboard stops updating while the device is pointed at the new
listener. This is expected; use the new ingestion logs and SQL above as the
source of truth. After a silent drop, reconnects may be rejected for up to 60
seconds by the single-authenticated-connection policy. Buffered positions should
arrive later in a `0x0704` batch. Do not interpret the temporary dashboard gap
as data loss without checking the database.

Once the canary is stable and verified, close port 8881 and stop the prototype.
Keep the prototype available for rollback until the agreed observation window
ends, but do not let both services receive this device simultaneously.

## Separate auth-code rotation

Do not rotate the code during endpoint cutover. After the canary is stable,
rotate in a separate maintenance window using stdin or the protected
`DEVICE_AUTH_CODE` environment variable:

```text
DEVICE_AUTH_CODE=<new-11-digit-code> docker compose run --rm ingestion fleet-tracker rotate-device-secret --terminal-id 071604184647 --auth-code
```

The command does not print the new code. Trigger the PG07 registration/auth
flow, verify the new code, and record the result before retiring the old code.

## Rollback

If authentication, positions, or health checks fail, send exactly:

```text
SL DP15.207.134.172#8881#
```

Confirm the expected device reply, run `SL CX`, and verify the prototype
receives a heartbeat and position. Keep new database rows and logs for
diagnosis; do not delete them during rollback. Remove the temporary 8882
security-group rule after the canary is ended.
