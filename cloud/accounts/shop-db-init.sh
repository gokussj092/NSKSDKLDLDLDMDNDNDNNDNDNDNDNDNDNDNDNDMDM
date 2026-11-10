#!/bin/sh
set -eu
# Runs only during the first PostgreSQL volume initialization. The application
# uses a separate nonsuperuser role; psql reads its password from the environment.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password SPDECODE_SHOP_APP_PASSWORD
CREATE ROLE spdecode_shop_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO spdecode_shop_app;
GRANT CONNECT, CREATE ON DATABASE spdecode_shop TO spdecode_shop_app;
SQL
