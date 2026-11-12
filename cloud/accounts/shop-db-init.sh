#!/bin/sh
set -eu
# Idempotent: also used by "spdecode commerce init/migrate" on existing volumes.
# Never print credentials or pass them as command-line arguments.
: "${POSTGRES_USER:?}"
: "${POSTGRES_DB:?}"
: "${SPDECODE_SHOP_APP_PASSWORD:?}"
psql -X -q -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password SPDECODE_SHOP_APP_PASSWORD
SELECT format(
  CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='spdecode_shop_app')
       THEN 'ALTER ROLE spdecode_shop_app WITH LOGIN PASSWORD %L'
       ELSE 'CREATE ROLE spdecode_shop_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
  END,
  :'app_password'
)
\gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO spdecode_shop_app;
GRANT CONNECT, CREATE ON DATABASE spdecode_shop TO spdecode_shop_app;
SQL
