#!/usr/bin/env bash
# Ubuntu/Debian SP-DECODE Cloud first deployment: root, domain required.
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
fail(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo "[spdecode installer] $*"; }
[[ $(id -u) -eq 0 ]] || fail "sudo/root required"
# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || fail "Ubuntu/Debian only"
DOMAIN="" API_DOMAIN="" PANEL_DOMAIN="" EMAIL="" SUPPORT_EMAIL="soporte@spdecode.xyz"
REF="feat/cloud-c8-vps-installer-updater" EXPECTED_IP="" WWW=false
REPO_URL="https://github.com/Gh0stDeveloper/SP-DECODE.git"
while (($#)); do
  case "$1" in
    --domain) DOMAIN="${2:?}";shift 2;;
    --api-domain) API_DOMAIN="${2:?}";shift 2;;
    --panel-domain) PANEL_DOMAIN="${2:?}";shift 2;;
    --support-email) SUPPORT_EMAIL="${2:?}";shift 2;;
    --expected-ip) EXPECTED_IP="${2:?}";shift 2;;
    --www) WWW=true;shift;;
    --email) EMAIL="$2";shift 2;;
    --ref) REF="$2";shift 2;;
    --repo-ssh) REPO_URL="git@github.com:Gh0stDeveloper/SP-DECODE.git";shift;;
    *) fail "Unknown option: $1";;
  esac
done
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{1,250})[A-Za-z0-9]$ &&
  "$DOMAIN" == *.* && "$DOMAIN" != *..* ]] || fail "--domain is required and must resolve to this VPS"
API_DOMAIN="${API_DOMAIN:-api.$DOMAIN}"
PANEL_DOMAIN="${PANEL_DOMAIN:-panel.$DOMAIN}"
for name in "$DOMAIN" "$API_DOMAIN" "$PANEL_DOMAIN"; do
  [[ "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{1,250})[A-Za-z0-9]$ &&
    "$name" == *.* && "$name" != *..* ]] || fail "Invalid hostname: $name"
done
[[ "$API_DOMAIN" == *".$DOMAIN" && "$PANEL_DOMAIN" == *".$DOMAIN" &&
  "$API_DOMAIN" != "$PANEL_DOMAIN" ]] || fail "API and panel must be distinct subdomains"
[[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || fail "--email required"
[[ "$SUPPORT_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
  fail "Invalid support email"
if [[ -n "$EXPECTED_IP" ]]; then
  [[ "$EXPECTED_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] ||
    fail "Invalid --expected-ip"
fi
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ && "$REF" != -* && "$REF" != *..* ]] || fail "Invalid --ref"
[[ ! -e /etc/spdecode/install.conf ]] || fail "Already installed; use spdecode update"
log "Checking all public hostnames; email MX/TXT DNS records are never modified"
DNS_HOSTS=("$DOMAIN" "$API_DOMAIN" "$PANEL_DOMAIN")
if [[ "$WWW" == true ]]; then DNS_HOSTS+=("www.$DOMAIN"); fi
for name in "${DNS_HOSTS[@]}"; do
  records=$(getent ahostsv4 "$name" || true)
  [[ -n "$records" ]] || fail "Missing A record for $name"
  if [[ -n "$EXPECTED_IP" ]] && ! awk -v ip="$EXPECTED_IP" '$1==ip {match=1} END {exit !match}' <<<"$records"; then
    fail "$name does not resolve to expected VPS IPv4 ($EXPECTED_IP)"
  fi
done
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg git python3 jq unzip nginx certbot openssl
if ! docker compose version >/dev/null 2>&1; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod 0644 /etc/apt/keyrings/docker.gpg
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker nginx
install -d -m 0700 /etc/spdecode /opt/spdecode /opt/spdecode/backups /opt/spdecode/builds
[[ ! -e /opt/spdecode/repo ]] || fail "Checkout already exists; won't overwrite"
git clone --depth 1 --branch "$REF" -- "$REPO_URL" /opt/spdecode/repo
test -f /opt/spdecode/repo/cloud/compose.yaml || fail "Missing Cloud compose"
printf 'SPDECODE_REF=%q\nSPDECODE_REPO_URL=%q\n' "$REF" "$REPO_URL" > /etc/spdecode/install.conf
cat > /etc/spdecode/cloud.env <<EOC
CLOUD_API_ENABLED=false
CLOUD_QA_ENABLED=false
CLOUD_QA_EXPIRES_AT=0
CLOUD_ADMIN_ENABLED=false
CLOUD_TRUST_PROXY=true
CLOUD_FORCE_MAINTENANCE=true
CLOUD_PUBLIC_SITE_INDEX=false
CLOUD_SITE_PUBLIC_ORIGIN=https://$DOMAIN
CLOUD_ADMIN_PUBLIC_ORIGIN=https://$PANEL_DOMAIN
CLOUD_API_PUBLIC_ORIGIN=https://$API_DOMAIN
CLOUD_SUPPORT_EMAIL=$SUPPORT_EMAIL
CLOUD_GOOGLE_PLAY_PACKAGE=com.ghostdeveloper.spdecode
CLOUD_WORKER_TOKEN=$(openssl rand -hex 32)
CLOUD_SESSION_SIGNING_KEY=$(openssl rand -hex 32)
CLOUD_ADMIN_SESSION_KEY=$(openssl rand -hex 32)
CLOUD_EHI_IMPORT_ENABLED=false
CLOUD_NUR_FETCH_ENABLED=false
EOC
chmod 600 /etc/spdecode/install.conf /etc/spdecode/cloud.env
printf '%s\n' "$DOMAIN" > /etc/spdecode/domain
printf '%s\n' "$API_DOMAIN" > /etc/spdecode/api-domain
printf '%s\n' "$PANEL_DOMAIN" > /etc/spdecode/panel-domain
printf '%s\n' "$SUPPORT_EMAIL" > /etc/spdecode/support-email
chmod 600 /etc/spdecode/domain /etc/spdecode/api-domain /etc/spdecode/panel-domain /etc/spdecode/support-email
install -m 0755 /opt/spdecode/repo/cloud/infra/vps/spdecodectl /usr/local/bin/spdecode
# With umask 077, GNU install -d creates intermediate directories as 0700
# even if the leaf has -m 0755. Nginx must traverse every path component.
install -d -m 0755 /var/www/spdecode-acme
install -d -m 0755 /var/www/spdecode-acme/.well-known
install -d -m 0755 /var/www/spdecode-acme/.well-known/acme-challenge
chmod 0755 /var/www/spdecode-acme /var/www/spdecode-acme/.well-known \
  /var/www/spdecode-acme/.well-known/acme-challenge
cat >/etc/nginx/sites-available/spdecode.conf <<EOC
server {
  listen 80;
  server_name ${DNS_HOSTS[*]};
  root /var/www/spdecode-acme;
  location ^~ /.well-known/acme-challenge/ { try_files \$uri =404; }
  location / { return 404; }
}
EOC
ln -sf /etc/nginx/sites-available/spdecode.conf /etc/nginx/sites-enabled/spdecode.conf
nginx -t && systemctl reload nginx
# Before asking Let's Encrypt, prove every virtual host serves the exact
# challenge webroot. Prevent 404s from old provisional Nginx server blocks.
probe="spdecode-installer-$"
printf 'SPDECODE-ACME-READY\n' > "/var/www/spdecode-acme/.well-known/acme-challenge/$probe"
chmod 0644 "/var/www/spdecode-acme/.well-known/acme-challenge/$probe"
for host in "${DNS_HOSTS[@]}"; do
  actual=$(curl --noproxy '*' --proxy '' --silent --show-error \
    --connect-timeout 4 --max-time 8 --max-redirs 0 \
    --resolve "$host:80:127.0.0.1" "http://$host/.well-known/acme-challenge/$probe") ||
    fail "Unable to read ACME challenge on $host; check nginx -T"
  if [[ "$actual" != "SPDECODE-ACME-READY" ]]; then
    fail "Wrong Nginx webroot for $host. Check sudo nginx -T for duplicate SP-DECODE virtual hosts. Use the recovery script, do not rerun the installer."
  fi
done
rm -f -- "/var/www/spdecode-acme/.well-known/acme-challenge/$probe"
log "Requesting HTTPS certificate for $DOMAIN; open inbound TCP 80/443"
CERTBOT_DOMAINS=(-d "$DOMAIN" -d "$API_DOMAIN" -d "$PANEL_DOMAIN")
if [[ "$WWW" == true ]]; then CERTBOT_DOMAINS+=(-d "www.$DOMAIN"); fi
certbot certonly --webroot --non-interactive --agree-tos --email "$EMAIL" \
   --cert-name "$DOMAIN" -w /var/www/spdecode-acme "${CERTBOT_DOMAINS[@]}" ||
   fail "Let's Encrypt failed; check DNS and cloud/firewall 80/443"
NGINX_ARGS=("$DOMAIN" --api-domain "$API_DOMAIN" --panel-domain "$PANEL_DOMAIN")
if [[ "$WWW" == true ]]; then NGINX_ARGS+=(--www); fi
python3 /opt/spdecode/repo/cloud/infra/vps/nginx-config.py "${NGINX_ARGS[@]}" \
  > /etc/nginx/sites-available/spdecode.conf
nginx -t && systemctl reload nginx
systemctl enable --now certbot.timer 2>/dev/null || true
# Reload Nginx when Let's Encrypt renews a certificate.
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\n/usr/sbin/nginx -t && /bin/systemctl reload nginx\n' \
 > /etc/letsencrypt/renewal-hooks/deploy/spdecode-nginx
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/spdecode-nginx
# Keep session and admin disabled; enabling requires actual Play configuration.
cd /opt/spdecode/repo
docker compose --project-name spdecode --env-file /etc/spdecode/cloud.env \
 -f cloud/compose.yaml config --quiet
docker compose --project-name spdecode --env-file /etc/spdecode/cloud.env \
 -f cloud/compose.yaml up -d --build
log "Installed. API and admin disabled, maintenance enabled. Do not publish until C7/C8 approval."
spdecode status
