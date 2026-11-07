#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || "$1" != "--confirm-host" ]]; then
  echo "usage: $0 --confirm-host <host>" >&2
  exit 2
fi
confirm_host="$2"

: "${TEST_DATABASE_URL:?TEST_DATABASE_URL is required}"
: "${TEST_API_DATABASE_URL:?TEST_API_DATABASE_URL is required}"
: "${TEST_INGEST_DATABASE_URL:?TEST_INGEST_DATABASE_URL is required}"
: "${TEST_WORKER_DATABASE_URL:?TEST_WORKER_DATABASE_URL is required}"

python - "$confirm_host" <<'PY'
import os
import sys
from urllib.parse import urlparse

url = urlparse(os.environ["TEST_DATABASE_URL"])
if url.scheme not in {"postgresql", "postgres"}:
    raise SystemExit("TEST_DATABASE_URL must be a PostgreSQL URL")
if "pooler" in (url.hostname or "").lower() or url.port in {6432, 6543}:
    raise SystemExit("TEST_DATABASE_URL must use the direct endpoint")
if url.hostname != sys.argv[1]:
    raise SystemExit("--confirm-host does not match TEST_DATABASE_URL host")
print(f"target host={url.hostname} database={url.path.lstrip('/').split('?')[0]}")
PY

docker build --tag fleet-tracker-p2-test .
docker run --rm --env TEST_DATABASE_URL="$TEST_DATABASE_URL" fleet-tracker-p2-test fleet-tracker migrate
docker run --rm \
  --env PYTHONPATH=/app/src \
  --env RUN_POSTGRES_TESTS=1 \
  --env TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  --env TEST_API_DATABASE_URL="$TEST_API_DATABASE_URL" \
  --env TEST_INGEST_DATABASE_URL="$TEST_INGEST_DATABASE_URL" \
  --env TEST_WORKER_DATABASE_URL="$TEST_WORKER_DATABASE_URL" \
  fleet-tracker-p2-test python -m unittest tests.test_p2_rls_integration
