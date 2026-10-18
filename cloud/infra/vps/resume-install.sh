#!/usr/bin/env bash
# Resume SP-DECODE C8 after an HTTP-01 webroot/Certbot failure.
# The first install already created root-only env and cloned the repo:
# NEVER regenerate credentials/keystores or repeat apt/bootstrap.
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
die() { echo "ERROR: $*" >&2; exit 1; }
log() { printf '[spdecode TLS recovery] %s\n' "$*"; }
[[ $(id -u) -eq 0 ]] || die "Run with sudo/root"
CONF=/etc/spdecode/install.conf
ENVFILE=/etc/spdecode/cloud.env
ROOT=/opt/spdecode
[[ -f "$CONF" && -f "$ENVFILE" && -d "$ROOT/repo/.git" ]] ||
  die "Partial install not found. This is only for resuming after a certificate error."
[[ "$(stat -c %a "$ENVFILE")" == 600 ]] || die "Cloud secrets must remain mode 0600"
[[ -f /etc/spdecode/domain && -f /etc/spdecode/api-domain &&
  -f /etc/spdecode/panel-domain ]] || die "Domain configuration missing"
DOMAIN=$(cat /etc/spdecode/domain)
API=$(cat /etc/spdecode/api-domain)
PANEL=$(cat /etc/spdecode/panel-domain)
[[ "$DOMAIN" == "spdecode.xyz" && "$API" == "api.spdecode.xyz" &&
  "$PANEL" == "panel.spdecode.xyz" ]] ||
  die "Unexpected domain configuration; inspect /etc/spdecode before recovery"
EMAIL=$(cat /etc/spdecode/support-email)
[[ "$EMAIL" == "soporte@spdecode.xyz" ]] || die "Unexpected support email; check configuration"
command -v nginx >/dev/null && command -v certbot >/dev/null ||
  die "Nginx/Certbot missing: inspect the initial installer log"
[[ -f /etc/nginx/sites-available/spdecode.conf ]] ||
  die "Original ACME HTTP-only site is missing"
log "Checking for a known conflicting SP-DECODE provisional Nginx virtual host"
OLD=/etc/nginx/sites-enabled/spdecode
DISABLE_LEGACY=false
for arg in "$@"; do
  case "$arg" in
    --disable-legacy-spdecode) DISABLE_LEGACY=true;;
    *) die "Unknown argument: $arg (only --disable-legacy-spdecode)";;
  esac
done
if [[ -e "$OLD" || -L "$OLD" ]]; then
  if [[ "$DISABLE_LEGACY" != true ]]; then
    die "Legacy site $OLD still active. Inspect its target and, if it is the old SP-DECODE placeholder, rerun with --disable-legacy-spdecode"
  fi
  [[ -L "$OLD" && "$(readlink -f "$OLD")" == "/etc/nginx/sites-available/spdecode" ]] ||
    die "Legacy site is not the expected SP-DECODE placeholder symlink; refusing automatic changes"
  grep -Fq "spdecode.xyz" /etc/nginx/sites-available/spdecode ||
    die "Legacy target doesn't mention this project; refusing automatic changes"
  mkdir -p /etc/spdecode/backups
  stamp=$(date -u +%Y%m%dT%H%M%S)
  mv -- "$OLD" "/etc/spdecode/backups/nginx-legacy-spdecode-symlink-$stamp"
  log "Deactivated only known legacy SP-DECODE symlink; target file remains intact"
fi
# Ensure this recovery uses the HTTP-only ACME site, never provisional HTTPS.
if grep -Eq '^[[:space:]]*listen[[:space:]]+443' /etc/nginx/sites-available/spdecode.conf; then
  die "A TLS site is already configured. Inspect Nginx and certificates manually."
fi
nginx -t
systemctl reload nginx
ACME=/var/www/spdecode-acme/.well-known/acme-challenge
install -d -m 0755 "$ACME"
probe="spdecode-recovery-$(date -u +%s)-$$"
printf 'SPDECODE-ACME-READY\n' > "$ACME/$probe"
chmod 0644 "$ACME/$probe"
trap 'rm -f -- "$ACME/$probe"' EXIT
log "Testing HTTP-01 challenge on loopback for all three Host headers"
for host in "$DOMAIN" "$API" "$PANEL"; do
  actual=$(curl --silent --show-error --connect-timeout 4 --max-time 7 --max-redirs 0 \
    --resolve "$host:80:127.0.0.1" "http://$host/.well-known/acme-challenge/$probe") ||
    die "Nginx cannot serve challenge on localhost for $host"
  [[ "$actual" == "SPDECODE-ACME-READY" ]] ||
    die "HTTP-01 path returned wrong content for $host. Check duplicate virtual hosts with: sudo nginx -T"
  log "$host: ACME webroot OK"
done
rm -f -- "$ACME/$probe"
trap - EXIT
log "Requesting Let's Encrypt certificate (external port 80 must reach this VPS)"
certbot certonly --webroot --non-interactive --agree-tos \
  --email "$EMAIL" --cert-name "$DOMAIN" \
  -w /var/www/spdecode-acme -d "$DOMAIN" -d "$API" -d "$PANEL" ||
  die "Certificate validation still failed; verify external HTTP routing to VPS and try local ACME test"
[[ -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]] ||
  die "Expected fullchain.pem is missing"
log "Preparing isolated TLS domains for website, API and panel"
NGINX_GEN="$ROOT/repo/cloud/infra/vps/nginx-config.py"
[[ -f "$NGINX_GEN" ]] || die "Missing Nginx generator in cloned repo"
tmp=$(mktemp /etc/nginx/sites-available/.spdecode-XXXXXX)
trap 'rm -f -- "$tmp"' EXIT
python3 "$NGINX_GEN" "$DOMAIN" --api-domain "$API" --panel-domain "$PANEL" > "$tmp"
cp -p /etc/nginx/sites-available/spdecode.conf /etc/spdecode/backups/spdecode-http-acme.conf
cp -- "$tmp" /etc/nginx/sites-available/spdecode.conf
if ! nginx -t; then
  cp -- /etc/spdecode/backups/spdecode-http-acme.conf /etc/nginx/sites-available/spdecode.conf
  nginx -t || true
  die "Generated HTTPS virtual hosts failed syntax check; rolled back config"
fi
systemctl reload nginx
systemctl enable --now certbot.timer 2>/dev/null || true
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\n/usr/sbin/nginx -t && /bin/systemctl reload nginx\n' \
  > /etc/letsencrypt/renewal-hooks/deploy/spdecode-nginx
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/spdecode-nginx
log "Starting private Docker Compose services with existing secrets, no regeneration"
cd "$ROOT/repo"
docker compose --project-name spdecode --env-file "$ENVFILE" \
  -f cloud/compose.yaml config --quiet
docker compose --project-name spdecode --env-file "$ENVFILE" \
  -f cloud/compose.yaml up -d --build
install -m 0755 "$ROOT/repo/cloud/infra/vps/spdecodectl" /usr/local/bin/spdecode
log "Recovery completed. Services remain fail-closed (no Play Integrity production activation)."
spdecode status
