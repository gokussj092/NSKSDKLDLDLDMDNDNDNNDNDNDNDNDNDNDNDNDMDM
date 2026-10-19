#!/usr/bin/env bash
# Non-mutating diagnostics: website, Android API and restricted admin virtual host.
# Intentionally never prints secrets, headers, cookies or Docker environment.
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ printf '[spdecode routes] %s\n' "$*"; }
[[ $(id -u) -eq 0 ]] || { echo "Use sudo/root" >&2; exit 1; }
domain="spdecode.xyz"
api="api.spdecode.xyz"
panel="panel.spdecode.xyz"
[[ -s /etc/spdecode/domain ]] && domain=$(cat /etc/spdecode/domain)
[[ -s /etc/spdecode/api-domain ]] && api=$(cat /etc/spdecode/api-domain)
[[ -s /etc/spdecode/panel-domain ]] && panel=$(cat /etc/spdecode/panel-domain)
for name in "$domain" "$api" "$panel"; do
  [[ "$name" =~ ^[a-zA-Z0-9.-]+$ ]] || { echo "Invalid configured hostname" >&2; exit 1; }
done
request(){
  local label="$1" method="$2" url="$3" expected="$4" code output
  if [[ "$method" == direct-https ]]; then
    local host="${url#https://}"
    host="${host%%/*}"
    output=$(curl --noproxy '*' --proxy '' --silent --show-error --connect-timeout 3 \
      --max-time 8 --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code}' "$url" 2>&1) || {
        log "$label: CONNECTION/TLS ERROR (local) $(printf '%s' "$output" | head -c 180)"
        return 1
      }
  else
    output=$(curl --noproxy '*' --proxy '' --silent --show-error --connect-timeout 3 \
      --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>&1) || {
        log "$label: CONNECTION ERROR $(printf '%s' "$output" | head -c 180)"
        return 1
      }
  fi
  code="$output"
  log "$label: HTTP $code (expected $expected)"
  [[ "$code" == "$expected" ]]
}
log "Validating Nginx configuration and Docker state (no credentials printed)"
nginx -t || exit 1
docker ps --filter "name=spdecode-" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
log "Listening socket for Next.js:"
ss -ltn '( sport = :3000 )' | tail -n 3 || true
log "Testing Next.js directly (no TLS/Nginx)"
request "Backend liveness" plain-http "http://127.0.0.1:3000/api/v1/health" 200 || true
request "Backend admin login page" plain-http "http://127.0.0.1:3000/admin/login" 200 || true
log "Testing each HTTPS name through LOCAL Nginx with correct SNI/Host"
request "Website" direct-https "https://$domain/" 200 || true
request "Android API liveness" direct-https "https://$api/api/v1/health" 200 || true
# A 503 means the decoder intentionally remains disabled, not that HTTPS failed.
request "Android decode readiness" direct-https "https://$api/api/v1/ready" 503 || true
# The localhost request is on the default allowed admin IP and should reach Next.js.
request "Panel login page (localhost allowlist)" direct-https "https://$panel/admin/login" 200 || true
request "Admin session API disabled until configured" direct-https "https://$panel/api/admin/session" 503 || true
log "Public clients not on the admin allowlist should receive 403, not 502."
log "If any local HTTPS result is 502, examine the Nginx error log:"
log "  sudo tail -n 35 /var/log/nginx/error.log"
log "If direct backend is failing, examine the web container logs:"
log "  sudo docker logs --tail 80 spdecode-web-1"
log "API returning /health=200 but /ready=503 means transport works and decoding is OFF by design."
