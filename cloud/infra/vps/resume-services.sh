#!/usr/bin/env bash
# Resume after HTTPS succeeds but Docker worker is unhealthy.
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ printf '[spdecode container recovery] %s\n' "$*"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || die "Root required"
REPO=/opt/spdecode/repo
ENVFILE=/etc/spdecode/cloud.env
CONF=/etc/spdecode/install.conf
[[ -f "$ENVFILE" && -f "$CONF" && -d "$REPO/.git" ]] || die "Previous install missing"
[[ $(stat -c %a "$ENVFILE") == 600 ]] || die "Unsafe secret permissions"
[[ -s /etc/letsencrypt/live/spdecode.xyz/fullchain.pem ]] || die "HTTPS certificate missing"
nginx -t || die "Nginx invalid"
source "$CONF"
[[ "$SPDECODE_REF" =~ ^[A-Za-z0-9._/-]+$ && "$SPDECODE_REF" != -* && "$SPDECODE_REF" != *..* ]] || die "Invalid Git ref"
[[ -z $(git -C "$REPO" status --porcelain) ]] || die "Managed repository has local edits"
command -v docker >/dev/null && docker compose version >/dev/null || die "Docker Compose v2 required"
exec 9>/opt/spdecode/.operator.lock
flock -x 9
log "Updating managed source only; existing secrets and certificates remain unchanged"
git -C "$REPO" pull --ff-only origin "$SPDECODE_REF" || die "Managed checkout cannot fast-forward"
cd "$REPO"
compose=(docker compose --project-name spdecode --env-file "$ENVFILE" -f cloud/compose.yaml)
"${compose[@]}" config --quiet || die "Invalid Compose config"
log "Building and restarting private worker, Redis and web"
if ! "${compose[@]}" up -d --build; then
  log "Startup failure; container diagnostics:"
  "${compose[@]}" ps || true
  "${compose[@]}" logs --no-color --tail 65 decoder-worker redis web || true
  die "Container unhealthy. No certificate or signing key changes were made."
fi
for i in $(seq 1 18); do
  if curl --noproxy '*' --proxy '' -fsS --connect-timeout 2 --max-time 4 http://127.0.0.1:3000/api/health/live >/dev/null; then
    install -m 0755 "$REPO/cloud/infra/vps/spdecodectl" /usr/local/bin/spdecode.next
    mv -f /usr/local/bin/spdecode.next /usr/local/bin/spdecode
    log "Containers healthy, spdecode CLI installed. API/admin still fail closed."
    "${compose[@]}" ps
    exit 0
  fi
  sleep 3
done
"${compose[@]}" ps || true
die "Web did not pass local healthcheck"
