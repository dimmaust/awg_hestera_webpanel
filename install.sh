#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_DIR="/opt/awg-panel"
readonly DATA_DIR="$APP_DIR/data"
readonly LIB_DIR="/usr/local/lib/awg-panel"
readonly HOST_DIR="/etc/awg-panel"
readonly HOST_CONFIG="$HOST_DIR/agent.conf"
readonly BACKUP_KEY="$HOST_DIR/backup.key"
readonly BACKUP_DIR="/var/backups/awg-panel"
readonly LOG_FILE="/var/log/awg-panel-install.log"

# The installer runs unattended over a non-tty ssh session.
export DEBIAN_FRONTEND=noninteractive

expose_firewall=0
with_fail2ban=0
remote_unpack=""

cleanup() { [[ -z $remote_unpack ]] || rm -rf "$remote_unpack"; }
trap cleanup EXIT

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

usage() {
  cat <<'TEXT'
Usage: install.sh [--expose-firewall] [--with-fail2ban]

  --expose-firewall   bind the panel to 0.0.0.0 and open PANEL_PORT in ufw.
                      Default is 127.0.0.1 plus an SSH tunnel.
  --with-fail2ban     install the sshd jail and (re)start fail2ban.
TEXT
}

require_root() { [[ $EUID -eq 0 ]] || die "run as root or through sudo"; }

require_platform() {
  source /etc/os-release
  # 22.04 разрешён по решению оператора: DKMS-модуль amneziawg под его ядро уже собран.
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} =~ ^(22\.04|24\.04)$ ]] || die "Ubuntu 22.04 or 24.04 is required"
  [[ $(dpkg --print-architecture) == amd64 ]] || die "amd64 is required"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --expose-firewall) expose_firewall=1 ;;
      --with-fail2ban) with_fail2ban=1 ;;
      -h|--help) usage; exit 0 ;;
      *) usage; die "unknown option $1" ;;
    esac
    shift
  done
}

find_port() {
  local candidate
  for candidate in 5000 $(seq 5500 5999); do
    if ! ss -ltnH "sport = :$candidate" | grep -q .; then printf '%s' "$candidate"; return; fi
  done
  die "no free panel port found"
}

resolve_source() {
  if [[ -f Dockerfile && -f host-agent/agent.py && -f docker-compose.yml ]]; then
    printf '.'
    return
  fi
  # Remote bootstrap stays opt-in: it needs a published archive and a checksum.
  [[ -n ${AWG_PANEL_SOURCE_URL:-} && -n ${AWG_PANEL_SOURCE_SHA256:-} ]] ||
    die "run this script from a checkout, or set AWG_PANEL_SOURCE_URL and AWG_PANEL_SOURCE_SHA256"
  local archive
  archive=$(mktemp -t awg-panel-XXXXXX.tar.gz)
  log "Downloading $AWG_PANEL_SOURCE_URL"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$archive" "$AWG_PANEL_SOURCE_URL"
  printf '%s  %s\n' "$AWG_PANEL_SOURCE_SHA256" "$archive" | sha256sum -c - || { rm -f "$archive"; die "checksum mismatch"; }
  remote_unpack=$(mktemp -d -t awg-panel-src-XXXXXX)
  tar -xzf "$archive" -C "$remote_unpack" --strip-components=1
  rm -f "$archive"
  printf '%s' "$remote_unpack"
}

copy_app() {
  local source="$1"
  mkdir -p "$APP_DIR" "$DATA_DIR"
  tar -C "$source" --exclude .git --exclude .venv --exclude data --exclude .pytest-tmp \
    --exclude .pytest_cache --exclude __pycache__ --exclude '*.py[co]' --exclude .env -cf - . |
    tar -C "$APP_DIR" -xf -
  chown 10001:10001 "$DATA_DIR"
  chmod 700 "$APP_DIR/.env" 2>/dev/null || true
}

config_value() {
  local key="$1" file="$2"
  sed -n "s/^[[:space:]]*${key}=//p" "$file" | tail -n1
}

install_host_side() {
  install -d -m 700 "$LIB_DIR" "$HOST_DIR"
  install -m 700 "$APP_DIR/host-agent/agent.py" "$LIB_DIR/agent.py"
  install -m 700 "$APP_DIR/host-agent/backup.py" "$LIB_DIR/backup.py"
  if [[ ! -f "$HOST_CONFIG" ]]; then
    install -m 600 "$APP_DIR/host-agent/agent.conf.example" "$HOST_CONFIG"
    log "Installed $HOST_CONFIG from the example; review INTERFACE, NETWORK and GATEWAY_ADDRESS before use"
  fi
  if [[ ! -f "$BACKUP_KEY" ]]; then
    umask 077
    openssl rand -hex 32 > "$BACKUP_KEY"
    log "Generated $BACKUP_KEY. Copy it off-node: without it the backups are unrecoverable"
  fi
  local peers_dir
  peers_dir=$(config_value PEERS_DIR "$HOST_CONFIG")
  [[ -n $peers_dir ]] || die "PEERS_DIR is missing from $HOST_CONFIG"
  install -d -m 700 "$peers_dir"
  # systemd runs the backup with ProtectSystem=strict: the directory has to exist
  # beforehand, because the service cannot create it inside the read-only root.
  install -d -m 700 "$BACKUP_DIR"
  # First-run files come from the container's umask 0027 in docker-compose.yml; this chmod is for
  # databases created by older releases, which the container leaves untouched and world-readable.
  find "$DATA_DIR" -maxdepth 1 -name 'panel.sqlite3*' -exec chmod 640 {} + 2>/dev/null || true
  install -m 644 "$APP_DIR/host-agent/awg-panel-agent.service" /etc/systemd/system/awg-panel-agent.service
  install -m 644 "$APP_DIR/host-agent/awg-panel-peers.service" /etc/systemd/system/awg-panel-peers.service
  install -m 644 "$APP_DIR/host-agent/awg-panel-backup.service" /etc/systemd/system/awg-panel-backup.service
  install -m 644 "$APP_DIR/host-agent/awg-panel-backup.timer" /etc/systemd/system/awg-panel-backup.timer
  # /run is empty after every boot, so the socket directory comes from tmpfiles.d: the agent
  # cannot create it itself because ProtectSystem=strict makes its ReadWritePaths bind fail.
  install -m 644 "$APP_DIR/host-agent/awg-panel.tmpfiles" /etc/tmpfiles.d/awg-panel.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/awg-panel.conf
  systemctl daemon-reload
  systemctl enable --now awg-panel-agent.service
  systemctl restart awg-panel-agent.service
  systemctl enable awg-panel-peers.service
  systemctl enable --now awg-panel-backup.timer
}

install_fail2ban() {
  command -v fail2ban-client >/dev/null || die "fail2ban is not installed (apt-get install fail2ban)"
  local managed='managed by awg-panel'
  local legacy=/etc/fail2ban/jail.d/awg-panel-sshd.conf
  if [[ -f $legacy ]] && ! grep -q "$managed" "$legacy"; then
    die "$legacy exists and was not written by this installer"
  fi
  install -d -m 755 /etc/fail2ban/jail.d /etc/fail2ban/filter.d /etc/fail2ban/action.d
  local kind name target
  for kind in jail.d filter.d action.d; do
    for name in "$APP_DIR"/host-agent/fail2ban/"$kind"/*.conf; do
      target="/etc/fail2ban/$kind/$(basename "$name")"
      if [[ -f $target ]] && ! grep -q "$managed" "$target"; then
        die "$target exists and was not written by this installer"
      fi
      { echo "# $managed"; cat "$name"; } > "$target"
    done
  done
  # The sshd-only jail predates the panel and hysteria jails; the new file replaces it.
  rm -f "$legacy"
  # fail2ban reads no dependency on docker, and at boot it wins the race: by the time its
  # actionstart runs, dockerd has not created DOCKER-USER yet, so the panel jail comes up
  # with a chain nothing points at. Ordering makes the boot case deterministic; the action
  # re-asserts the jump per ban as the fallback.
  install -d -m 755 /etc/systemd/system/fail2ban.service.d
  printf '[Unit]\nAfter=docker.service\n' > /etc/systemd/system/fail2ban.service.d/after-docker.conf
  systemctl daemon-reload
  systemctl enable --now fail2ban
  systemctl restart fail2ban
  log "fail2ban jails installed. Verify YOUR OWN egress IP is in ignoreip before you rely on it"
}

write_env_file() {
  local port="$1" bind="$2"
  umask 077
  printf 'PANEL_PORT=%s\nPANEL_BIND=%s\nADMIN_LOGIN=%s\nADMIN_PASSWORD=%s\nSESSION_SECRET=%s\nAGENT_SOCKET=/run/awg-panel/agent.sock\nAGENT_TIMEOUT=5\nAUDIT_LOG=/var/log/awg-panel/audit.log\n' \
    "$port" "$bind" "${ADMIN_LOGIN:-admin}" "${ADMIN_PASSWORD:-$(openssl rand -base64 24)}" "$(openssl rand -hex 32)" > "$APP_DIR/.env"
}

# fail2ban читает этот файл с хоста, поэтому аудит пишется в bind-mount, а не в stdout.
install_audit_log() {
  install -d -m 750 -o 10001 -g 10001 /var/log/awg-panel
  [[ -f /var/log/awg-panel/audit.log ]] || install -m 640 -o 10001 -g 10001 /dev/null /var/log/awg-panel/audit.log
}

compose() {
  docker compose -f "$APP_DIR/docker-compose.yml" --project-directory "$APP_DIR" "$@"
}

wait_for_panel() {
  local port="$1" attempt
  for attempt in $(seq 1 20); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then return; fi
    sleep 1
  done
  die "panel did not become healthy"
}

main() {
  parse_args "$@"
  require_root
  touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
  require_platform
  command -v curl >/dev/null || { apt-get update; apt-get install -y curl; }

  local source bind initial_password port
  source=$(resolve_source)
  bind=127.0.0.1
  if [[ $expose_firewall -eq 1 ]]; then bind=0.0.0.0; fi

  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    log "Installing Docker Engine and Compose plugin from Ubuntu packages"
    apt-get update
    apt-get install -y docker.io docker-compose-v2
    systemctl enable --now docker
  fi

  copy_app "$source"
  install_host_side
  install_audit_log
  if [[ $with_fail2ban -eq 1 ]]; then install_fail2ban; fi

  if [[ -f "$APP_DIR/.env" ]]; then
    port=$(config_value PANEL_PORT "$APP_DIR/.env")
  else
    port=${PANEL_PORT:-$(find_port)}
    write_env_file "$port" "$bind"
    if [[ -z ${ADMIN_PASSWORD:-} ]]; then
      initial_password=$(config_value ADMIN_PASSWORD "$APP_DIR/.env")
      log "Generated initial administrator credentials; the password is printed only below"
    fi
  fi
  [[ -n ${port:-} ]] || die "PANEL_PORT is missing from $APP_DIR/.env"

  if [[ $expose_firewall -eq 1 ]] && command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    ufw allow "$port/tcp" comment 'AWG panel'
  fi

  compose up -d --build
  wait_for_panel "$port"
  # ADMIN_PASSWORD is only needed while the first administrator row is inserted.
  sed -i '/^ADMIN_PASSWORD=/d' "$APP_DIR/.env"
  compose up -d
  wait_for_panel "$port"
  systemctl restart awg-panel-peers.service

  log "Panel listens on ${bind}:${port}. Access it through an SSH tunnel unless you passed --expose-firewall"
  log "Administrator login: ${ADMIN_LOGIN:-admin}"
  if [[ -n ${initial_password:-} ]]; then
    printf 'Administrator password: %s\n' "$initial_password"
    log "The first login to the panel will require replacing this password"
  fi
  log "Installation log: $LOG_FILE"
}

main "$@"
