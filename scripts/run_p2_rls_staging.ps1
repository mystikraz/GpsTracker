param(
    [switch]$BuildImage,
    [Parameter(Mandatory = $true)]
    [string]$ConfirmHost
)

$ErrorActionPreference = "Stop"

if ($env:CONFIRM_P2_STAGING -ne "1") {
    throw "Set CONFIRM_P2_STAGING=1 after confirming the printed host and database."
}

$required = @(
    "TEST_DATABASE_URL",
    "TEST_API_DATABASE_URL",
    "TEST_INGEST_DATABASE_URL",
    "TEST_WORKER_DATABASE_URL"
)
foreach ($name in $required) {
    if ([string]::IsNullOrWhiteSpace((Get-Item "Env:$name" -ErrorAction SilentlyContinue).Value)) {
        throw "$name must be set"
    }
}

$direct = [Uri]$env:TEST_DATABASE_URL
if ($direct.Host -match "pooler") {
    throw "TEST_DATABASE_URL must be a direct, non-pooled URL"
}
if ($direct.Host -ne $ConfirmHost) {
    throw "-ConfirmHost must exactly match the host parsed from TEST_DATABASE_URL"
}
$database = $direct.AbsolutePath.TrimStart("/").Split("?")[0]
Write-Output ("target host={0} database={1}" -f $direct.Host, $database)
Write-Output "No Neon branch label is read or written by this script."

if ($BuildImage) {
    docker build --tag fleet-tracker-p2-test .
}

# Roles must already have been reviewed and created on this exact branch.
# Migration is explicit and guarded by TEST_DATABASE_URL; this script never
# uses DIRECT_DATABASE_URL and never selects a production target.
docker run --rm `
    --env TEST_DATABASE_URL `
    fleet-tracker-p2-test fleet-tracker migrate

docker run --rm `
    --env PYTHONPATH=/app/src `
    --env RUN_POSTGRES_TESTS=1 `
    --env TEST_DATABASE_URL `
    --env TEST_API_DATABASE_URL `
    --env TEST_INGEST_DATABASE_URL `
    fleet-tracker-p2-test python -m unittest tests.test_p2_rls_integration
