#!/usr/bin/env bash
# bootstrap.sh — установка всего стека узла с нуля: AmneziaWG, панель, Hysteria2,
# telemt (MTProto), fail2ban. По этапам, с проверкой фактического состояния после каждого.
#
#   git clone https://github.com/dimmaust/awg_hestera_webpanel.git /root/awg-panel-src
#   cd /root/awg-panel-src && sudo ./bootstrap.sh
#
#   sudo ./bootstrap.sh --check                 только чтение: отчёт по узлу, конфиги не меняются
#   sudo ./bootstrap.sh --stage telemt          один этап (и его проверка)
#   sudo ./bootstrap.sh --skip hysteria         пропустить этап
#   sudo ./bootstrap.sh --force-config          пересоздать узловые конфиги (старые — в .bak)
#
#   OPERATOR_IPS можно не передавать: в терминале скрипт сам определит адрес, с которого вы
#   работаете, спросит, внести ли его в ignoreip, и предложит добавить ещё (IPv4 или CIDR,
#   по одному на строку).
#   Без терминала — из pipe или CI — спросить негде, и тогда OPERATOR_IPS обязателен: этап fail2ban
#   отказывается стартовать, чтобы не оставить вас же под баном.
#
#   В конце полного прогона печатается блок доступа: адрес панели, логин, пароль (только если он
#   создан этим прогоном), предупреждение обязательной смены и путь, где пароль можно перечитать.
#
# Почему этапами, а не «одной командой и молитвой»: узел ставится на живой IP, и падение
# на третьем шаге не должно означать половину настроенного конфига. Каждый этап идемпотентен
# и заканчивается проверкой состояния, а не кодом возврата apt.
#
# Чего скрипт не делает никогда: не перезагружает узел, не включает ufw, не трогает
# PasswordAuthentication/PermitRootLogin, не удаляет чужие конфиги и не пишет секреты в лог
# (пароль администратора печатается только в терминал прогона).
# Если для DKMS нужна перезагрузка — остановится и скажет, что продолжить после.
set -Eeuo pipefail

SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly APP_DIR=/opt/awg-panel
readonly HOST_DIR=/etc/awg-panel
readonly AGENT_CONF=$HOST_DIR/agent.conf
readonly SECRETS_DIR=/root/awg-panel-secrets
readonly LOG_FILE=/var/log/awg-panel-bootstrap.log

# ---------------------------------------------------------------- параметры узла
PANEL_PORT=${PANEL_PORT:-44090}
ADMIN_LOGIN=${ADMIN_LOGIN:-admin}
AWG_IF=${AWG_IF:-awg0}
AWG_PORT=${AWG_PORT:-42511}
AWG_NET=${AWG_NET:-10.66.0.0/24}
AWG_GW=${AWG_GW:-10.66.0.1}
HY2_PORT=${HY2_PORT:-43522}
HY2_STATS_PORT=${HY2_STATS_PORT:-9999}
TELEMT_PORT=${TELEMT_PORT:-443}
TELEMT_API=${TELEMT_API:-127.0.0.1:9091}
TLS_DOMAIN=${TLS_DOMAIN:-www.bing.com}
OPERATOR_IPS=${OPERATOR_IPS:-}
UPLINK=${UPLINK:-}
PUBLIC_HOST=${PUBLIC_HOST:-}
FORCE_CONFIG=${FORCE_CONFIG:-0}
# 1 — пароль администратора создан этим прогоном, поэтому его можно показать наружу. Если пароль
# уже был, печатать его содержимое смысла нет: после смены оно перестало быть паролем.
ADMIN_PASSWORD_FRESH=0

# ---------------------------------------------------------------- пиннинг чужого кода
# Версии закреплены под теми сборками, на которых проверялась интеграция. Менять — только
# осознанно: если sha256 не совпал, скрипт останавливается и не запускает непроверенный код от root.
readonly TELEMT_VERSION=3.5.16
readonly TELEMT_SHA256=e6f46b2f3becf29bfd555cec8a059e429f7c082c1af402499b3a7940cf8ebd34
readonly HYSTERIA_VERSION=v2.13.0
readonly HYSTERIA_SHA256=907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691
readonly AMNEZIA_PPA_FINGERPRINT=75C9DD72C799870E310542E24166F2C257290828

readonly STAGES=(base awg panel hysteria telemt fail2ban)

# ---------------------------------------------------------------- служебное
# umask — состояние процесса, а не запись на узел: он нужен и для tee-лога, который создаётся
# до prepare_paths, если останов случился на проверке root.
umask 077

prepare_paths() {
  # Вызывается после проверки root: --help не должен создавать каталог и лог.
  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
  touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
}

log()  { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE"; }
note() { printf '\n== %s ==\n' "$*" | tee -a "$LOG_FILE"; }
pass() { printf '  [OK]   %s\n' "$*" | tee -a "$LOG_FILE"; }
warn() { printf '  [ВНИМ] %s\n' "$*" | tee -a "$LOG_FILE"; }
bail() { printf '  [FAIL] %s\n' "$*" | tee -a "$LOG_FILE"; return 1; }
abort() { log "ОСТАНОВ: $*"; exit 1; }
# secret — печать без tee, только в терминал этого запуска: пароль администратора нужен оператору
# сразу, а в $LOG_FILE его быть не должно (лог 0600, но он переживает перезагрузку в /var/log).
secret() { printf '  >>> %s\n' "$*"; }

CHECK_ONLY=0
CHECK_FAILS=0
ck() { # ck <что проверяем> <проверка...> — в боевом прогоне непройденная проверка останавливает этап
  local what=$1; shift
  if [[ $CHECK_ONLY == 1 ]]; then
    if "$@" >/dev/null 2>&1; then pass "$what"; else CHECK_FAILS=$((CHECK_FAILS + 1)); bail "$what"; fi
  else
    if "$@" >/dev/null 2>&1; then pass "$what"; else abort "проверка не пройдена: $what"; fi
  fi
}
ck_warn() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else warn "$what"; fi; }

require_root() { [[ $EUID -eq 0 ]] || abort "нужен root: sudo ./bootstrap.sh ..."; }

require_platform() {
  . /etc/os-release
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} =~ ^(22\.04|24\.04)$ ]] ||
    abort "нужен Ubuntu 22.04 или 24.04, здесь ${ID:-?} ${VERSION_ID:-?}"
  [[ $(dpkg --print-architecture) == amd64 ]] || abort "нужен amd64"
}

detect_uplink() {
  [[ -n $UPLINK ]] || UPLINK=$(ip route show default | awk '/default/{print $5; exit}')
  [[ -n $UPLINK ]] || abort "не нашёл интерфейс по умолчанию — задайте UPLINK=eth0 и т.п."
  [[ -n $PUBLIC_HOST ]] || PUBLIC_HOST=$(ip -4 -o addr show dev "$UPLINK" | awk '{split($4,a,"/"); print a[1]; exit}')
  [[ -n $PUBLIC_HOST ]] || abort "на $UPLINK нет IPv4 — задайте PUBLIC_HOST=..."
}

# Адрес, с которого оператор подключён к узлу. Пробать egress с самого узла бессмысленно: наружу
# он отдаёт адрес узла, а не оператора. Источник соединения знает sshd — SSH_CLIENT, когда шелл
# поднят по SSH, и `who -m`, когда прогон идёт через sudo со сброшенным окружением. В консоли
# хостера нет ни того, ни другого: там адрес видит только оператор, и вводит он его сам.
operator_peer() {
  local peer
  peer=${SSH_CLIENT-}
  peer=${peer%% *}
  [[ $peer =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$peer"; return 0; }
  peer=$(who -m 2>/dev/null | awk '{print $5}' | tr -d '():')
  [[ $peer =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$peer"; return 0; }
  return 1
}

# Опрос только для терминала: адрес подключения подтвердить или отказаться, затем собрать свои.
ask_operator_ips() {
  local peer reply entry
  if peer=$(operator_peer); then
    printf '  Вы подключены к узлу по SSH с адреса: %s\n' "$peer"
    printf '  Внести его в ignoreip fail2ban? [Y/n] '
    read -r reply || reply=n
    case "${reply:-y}" in
      [нNn]*) log "адрес $peer не добавлен — по нему бан работает как по чужому" ;;
      *) OPERATOR_IPS=$peer ;;
    esac
  else
    printf '  SSH-подключения не вижу (консоль хостера?) — ваш адрес узлу неизвестен, внесите его вручную.\n'
  fi
  printf '  Адреса, с которых вы входите в панель и по SSH: IPv4 или CIDR, по одному на строку.\n'
  printf '  Пустая строка — закончить. Без них второй неверный вход за час забанит вас же на 30 минут.\n'
  while printf '  ещё адрес: ' && read -r entry; do
    [[ -n $entry ]] || break
    OPERATOR_IPS="${OPERATOR_IPS:+$OPERATOR_IPS }$entry"
  done
  if [[ -n $OPERATOR_IPS ]]; then log "OPERATOR_IPS по опросу: $OPERATOR_IPS"; fi
  return 0
}

# Значения Authorization берутся из agent.conf по имени ключа и подаются curl через --config из
# process substitution: токен не попадает ни в argv (видно в ps), ни в вывод.
token_url_code() { # <ключ agent.conf> <url>
  local token
  token=$(sed -n "s/^$1=//p" "$AGENT_CONF" | tail -n1)
  [[ -n $token ]] || return 1
  curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
    --config <(printf 'header = "Authorization: %s"\nurl = "%s"\n' "$token" "$2")
}
is_http() { local key=$1 url=$2 want=$3; [[ "$(token_url_code "$key" "$url")" == "$want" ]]; }
unit_active() { [[ "$(systemctl is-active "$1")" == active ]]; }
unit_enabled() { [[ "$(systemctl is-enabled "$1" 2>/dev/null)" == enabled ]]; }
listens_tcp() { ss -lnt | grep -qE ":$1\b"; }
listens_udp() { ss -lun | grep -qE ":$1\b"; }
# waits <tcp|udp> <порт>: юнит становится active раньше, чем процесс поднимает listener, —
# `systemctl restart telemt; sleep 2` и одна проверка порта ловили «не слушает» на живом движке
# (09.11: tcp/443 появился уже после abort). Поэтому порт ждут, а не замеряют один раз.
waits() {
  local attempt
  for attempt in $(seq 1 20); do
    case $1 in
      tcp) listens_tcp "$2" && return 0 ;;
      udp) listens_udp "$2" && return 0 ;;
    esac
    sleep 1
  done
  return 1
}
# waits_addr <адрес:порт> — ждёт listener с конкретной привязкой (loopback — не «0.0.0.0»).
waits_addr() {
  local attempt
  for attempt in $(seq 1 20); do
    ss -lnt | grep -q "$1" && return 0
    sleep 1
  done
  return 1
}
# Первая проба healthcheck'а — только по start-period=10s из Dockerfile, и docker ps показывает
# "starting" до неё. Однострочный grep по статусу сразу за install.sh ронял этап на здоровом узле,
# поэтому ждём статус healthy, а не угадываем в момент, когда проба ещё не запускалась.
panel_is_healthy() {
  local attempt id
  for attempt in $(seq 1 30); do
    id=$(docker ps -q -f name=awg-panel-panel | head -n1)
    if [[ -n $id ]] && [[ "$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null)" == healthy ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}
conf_set() { # conf_set KEY VALUE — правка agent.conf без печати значения
  grep -q "^$1=" "$AGENT_CONF" 2>/dev/null || echo "$1=" >> "$AGENT_CONF"
  sed -i -E "s|^$1=.*|$1=$2|" "$AGENT_CONF"
}
conf_keys() { grep -oE '^[A-Z0-9_]+=' "$AGENT_CONF" | tr -d '=' | sort | tr '\n' ' '; }
restart_agent() { systemctl restart awg-panel-agent.service; sleep 1; unit_active awg-panel-agent; }
backup_once() { [[ -s $1 ]] && { cp -a "$1" "$1.bak-$(date +%Y%m%d-%H%M%S)"; warn "было — сохранил копию $1.bak-*"; } || true; }

# ---------------------------------------------------------------- этап base
stage_base() {
  note "этап base: пакеты, заголовки ядра под DKMS, форвардинг и буферы"
  export DEBIAN_FRONTEND=noninteractive
  # DEBIAN_FRONTEND не властен над needrestart: у него свой интерфейс, он пишет в терминал и ждёт
  # ответа, когда весь вывод apt уже спрятан в /dev/null — прогон выглядит зависшим на этапе base.
  # Режим a запрещает ему спрашивать и перезапускает службы самому.
  export NEEDRESTART_MODE=a
  apt-get update -y >/dev/null
  apt-get -y full-upgrade >/dev/null
  apt-get install -y linux-headers-generic dkms build-essential openssl ca-certificates \
    curl iptables fail2ban uidmap make python3 gnupg git >/dev/null
  apt-get install -y "linux-headers-$(uname -r)" >/dev/null 2>&1 || \
    warn "заголовков точно под $(uname -r) нет: после обновления ядра нужен reboot (по согласию) и повтор --stage awg"
  printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' > /etc/sysctl.d/99-awg-forward.conf
  printf 'net.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n' > /etc/sysctl.d/99-hysteria.conf
  sysctl --system >/dev/null 2>&1 || true
  command -v docker >/dev/null || { apt-get install -y docker.io docker-compose-v2 >/dev/null; systemctl enable --now docker; }
  log "база готова, ядро $(uname -r), docker $(docker --version 2>/dev/null | awk '{print $3}')"
}
verify_base() {
  ck "заголовки ядра под $(uname -r) на месте" test -e "/lib/modules/$(uname -r)/build/include"
  ck "ip_forward = 1"                 test "$(sysctl -n net.ipv4.ip_forward)" = 1
  ck "iptables на месте"              test -x "$(command -v iptables)"
  ck "fail2ban установлен"            test -x "$(command -v fail2ban-client)"
  ck "docker работает"                 docker info
}

# ---------------------------------------------------------------- этап awg
amnezia_ppa() {
  local codename list=/etc/apt/sources.list.d/amnezia-ppa.list keyring=/etc/apt/keyrings/amnezia-ppa.gpg
  codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)
  [[ -f $list && -f $keyring ]] && { log "PPA Amnezia уже подключён"; return; }
  # Отпечаток берём из Launchpad API и сверяем с записанным: поставить репозиторий под
  # чужим ключом — значит собрать модуль ядра из ниоткуда.
  local fp
  fp=$(curl -s --max-time 25 "https://launchpad.net/api/1.0/~amnezia/+archive/ubuntu/ppa" |
       python3 -c 'import json,sys; print(json.load(sys.stdin).get("signing_key_fingerprint",""))' | tr 'a-z' 'A-Z')
  [[ ${fp^^} == "$AMNEZIA_PPA_FINGERPRINT" ]] ||
    abort "отпечаток ключа PPA = ${fp:-пусто}, ждали $AMNEZIA_PPA_FINGERPRINT — дальше не идём"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL --max-time 30 "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${fp}" |
    gpg --dearmor -o "$keyring"
  chmod 0644 "$keyring"
  printf 'deb [arch=amd64 signed-by=%s] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu %s main\n' \
    "$keyring" "$codename" > "$list"
  apt-get update -y >/dev/null
}

stage_awg() {
  note "этап awg: модуль AmneziaWG и интерфейс $AWG_IF на udp/$AWG_PORT"
  if ! modprobe amneziawg 2>/dev/null; then
    amnezia_ppa
    apt-get install -y amneziawg-dkms amneziawg-tools >/dev/null
    depmod -a; modprobe amneziawg 2>/dev/null || true
  fi
  if [[ ! -d /sys/module/amneziawg ]]; then
    dkms status | sed 's/^/    /'
    abort "модуль amneziawg не грузится под $(uname -r). Обычно это значит, что ядро обновилось: перезагрузитесь (только по согласию оператора) и продолжите --stage awg"
  fi
  printf 'amneziawg\n' > /etc/modules-load.d/amneziawg.conf

  local cfg=/etc/amnezia/amneziawg/${AWG_IF}.conf tpl="$SRC_DIR/host-agent/amneziawg/awg0.conf.example"
  install -d -m 700 /etc/amnezia/amneziawg
  if [[ -s $cfg && $FORCE_CONFIG != 1 ]]; then
    log "$cfg уже есть — не трогаю (пересоздание: --force-config)"
  else
    [[ -f $tpl ]] || abort "нет шаблона $tpl"
    backup_once "$cfg"
    local priv hpk s1 s2 s3 s4
    priv=$(awg genkey)
    hpk=$(openssl rand -base64 32)
    # Ограничения AWG 3.1: S1+56 != S2, S3 != S2+28, S3/S4 >= 12, H1..H4 = 1..4, Jc <= 122.
    s1=$(( (RANDOM % 136) + 15 )); s2=$(( (RANDOM % 136) + 15 ))
    while [[ $((s1 + 56)) -eq $s2 ]]; do s2=$(( (RANDOM % 136) + 15 )); done
    s3=$(( (RANDOM % 139) + 12 ))
    while [[ $s3 -eq $((s2 + 28)) ]]; do s3=$(( (RANDOM % 139) + 12 )); done
    s4=$(( (RANDOM % 139) + 12 ))
    install -m 600 "$tpl" "$cfg.tmp"
    sed -i -e "s|^PrivateKey = __GENERATED__|PrivateKey = ${priv}|" \
           -e "s|^HeaderProtectionKey = __GENERATED__|HeaderProtectionKey = ${hpk}|" \
           -e "s|^Address = .*|Address = ${AWG_GW}/24|" \
           -e "s|^ListenPort = .*|ListenPort = ${AWG_PORT}|" \
           -e "s|10\.66\.0\.0/24|${AWG_NET}|g" \
           -e "s|-o __UPLINK__|-o ${UPLINK}|g" \
           -e "s|^S1 = .*|S1 = ${s1}|" -e "s|^S2 = .*|S2 = ${s2}|" \
           -e "s|^S3 = .*|S3 = ${s3}|" -e "s|^S4 = .*|S4 = ${s4}|" "$cfg.tmp"
    mv "$cfg.tmp" "$cfg"; chmod 600 "$cfg"; unset priv hpk
    log "создан $cfg (секреты не печатаются): $(grep -oE '^[A-Za-z0-9]+' "$cfg" | tr '\n' ' ')"
  fi

  # Порядок: сначала конфиг, потом юнит. Руками интерфейс не поднимать:
  # awg-quick up при живом awg0 даёт exit 1 и вешает юнит в failed. При --force-config нужен
  # restart — новый HeaderProtectionKey к уже поднятому интерфейсу сам не применяется.
  systemctl reset-failed "awg-quick@${AWG_IF}.service" 2>/dev/null || true
  if [[ $FORCE_CONFIG == 1 ]]; then
    systemctl restart "awg-quick@${AWG_IF}.service"
  elif ! systemctl is-active --quiet "awg-quick@${AWG_IF}.service"; then
    systemctl start "awg-quick@${AWG_IF}.service"
  fi
  systemctl enable "awg-quick@${AWG_IF}.service" >/dev/null 2>&1
}
verify_awg() {
  ck "модуль amneziawg загружен"      test -d /sys/module/amneziawg
  ck "интерфейс $AWG_IF поднят"       ip link show "$AWG_IF"
  ck "адрес $AWG_GW на $AWG_IF"       bash -c "ip -4 -o addr show $AWG_IF | grep -q '$AWG_GW/'"
  ck "слушает udp/$AWG_PORT"          listens_udp "$AWG_PORT"
  ck "MASQUERADE для $AWG_NET"        bash -c "iptables -t nat -S POSTROUTING | grep -qF '$AWG_NET'"
  ck "ListenPort в рантайме = $AWG_PORT" bash -c "test \$(awg show $AWG_IF listen-port) = $AWG_PORT"
  ck "юнит включён"                    unit_enabled "awg-quick@${AWG_IF}.service"
  ck "конфиг 0600"                     test "$(stat -c %a /etc/amnezia/amneziawg/${AWG_IF}.conf)" = 600
}

# ---------------------------------------------------------------- этап panel
stage_panel() {
  note "этап panel: код панели, хост-агент, юниты, контейнер"
  local pwfile=$SECRETS_DIR/admin-password.txt
  if [[ ! -s $pwfile ]]; then
    openssl rand -base64 18 > "$pwfile"; chmod 600 "$pwfile"
    ADMIN_PASSWORD_FRESH=1
    log "пароль администратора сгенерирован в $pwfile (0600)"
    # наружу — в этом прогоне и без tee: файл в $SECRETS_DIR остаётся единственным хранилищем
    secret "пароль администратора: $(cat "$pwfile")"
    secret "при первом входе в http://${PUBLIC_HOST}:${PANEL_PORT}/login панель потребует его заменить"
  else
    # Повторный прогон после прерванного этапа: пароль уже создан, наружу его не тащим, но и молчать
    # с вопросами «где пароль» нельзя — поэтому хотя бы путь.
    log "пароль администратора уже создан ранее — читать из $pwfile (0600), в вывод его не печатаю"
  fi
  # ADMIN_PASSWORD уходит окружением (не argv) только для первого запуска, когда в БД
  # создаётся строка администратора; install.sh сам вычёркивает его из .env и печатает
  # пароль лишь если он передан пустым — здесь он не пустой. umask 022 — как при ручном запуске:
  # установщик создаёт каталоги под контейнер, и его права не должны зависеть от этого скрипта.
  ( cd "$SRC_DIR" && umask 022 && ADMIN_LOGIN=$ADMIN_LOGIN ADMIN_PASSWORD="$(cat "$pwfile")" PANEL_PORT=$PANEL_PORT \
      ./install.sh --expose-firewall )
  [[ -f $AGENT_CONF ]] || abort "install.sh не установил $AGENT_CONF"
  conf_set INTERFACE "$AWG_IF"
  conf_set INTERFACE_CONFIG "/etc/amnezia/amneziawg/${AWG_IF}.conf"
  conf_set PEERS_DIR "/etc/amnezia/amneziawg/panel-peers"
  conf_set NETWORK "$AWG_NET"
  conf_set GATEWAY_ADDRESS "$AWG_GW"
  conf_set ENDPOINT_DEV "$UPLINK"
  conf_set PUBLIC_ENDPOINT "$PUBLIC_HOST"
  restart_agent
}
verify_panel() {
  ck "контейнер healthy"               panel_is_healthy
  ck "healthz 200 на 127.0.0.1:$PANEL_PORT" bash -c "test \$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PANEL_PORT/healthz) = 200"
  ck "страница входа 200"              bash -c "test \$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PANEL_PORT/login) = 200"
  ck "агент активен"                    unit_active awg-panel-agent
  ck "сокет агента есть"                 test -S /run/awg-panel/agent.sock
  ck "tmpfiles-декларация /run/awg-panel" test -e /etc/tmpfiles.d/awg-panel.conf
  ck "peers-юнит включён"                unit_enabled awg-panel-peers
  ck "бэкап-таймер включён"              unit_enabled awg-panel-backup.timer
  ck "БД панели читается только владельцем" bash -c "test \$(stat -c %a $APP_DIR/data/panel.sqlite3) = 600"
  ck "ключ бэкапов 0600"                 test "$(stat -c %a $HOST_DIR/backup.key)" = 600
  ck_warn "агент не падал на NAMESPACE за сутки" bash -c "test \$(journalctl -u awg-panel-agent --since -24h --no-pager | grep -c 226/NAMESPACE) = 0"
}

# ---------------------------------------------------------------- этап hysteria
stage_hysteria() {
  note "этап hysteria: Hysteria2 $HYSTERIA_VERSION на udp/$HY2_PORT, авторизация через панель"
  local bin=/usr/local/bin/hysteria dir=/etc/hysteria
  local conf=$dir/config.yaml
  if [[ -x $bin ]] && hysteria version 2>&1 | grep -qE "Version:[[:space:]]*$HYSTERIA_VERSION"; then
    log "бинарник уже $HYSTERIA_VERSION — скачивание пропущено"
  else
    local url="https://github.com/apernet/hysteria/releases/download/app/$HYSTERIA_VERSION/hysteria-linux-amd64"
    curl -fsSL --max-time 300 -o "$bin.tmp" "$url"
    local actual
    actual=$(sha256sum "$bin.tmp" | awk '{print $1}')
    [[ $actual == "$HYSTERIA_SHA256" ]] || { rm -f "$bin.tmp"; abort "sha256 Hysteria2 = $actual, ждали $HYSTERIA_SHA256 — бинарник удалён, стоп"; }
    mv "$bin.tmp" "$bin"; chmod 755 "$bin"
  fi
  install -d -m 700 "$dir"
  if [[ -s $dir/tls.crt && $FORCE_CONFIG != 1 ]]; then
    log "сертификат уже есть — не трогаю"
  else
    backup_once "$dir/tls.crt"
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 -keyout "$dir/tls.key" \
      -out "$dir/tls.crt" -subj "/CN=$PUBLIC_HOST" -addext "subjectAltName=IP:$PUBLIC_HOST" 2>/dev/null
    chmod 600 "$dir/tls.key" "$dir/tls.crt"
    log "self-signed сертификат с IP SAN = $PUBLIC_HOST (в ссылке обязан быть insecure=1 и pinSHA256)"
  fi
  if [[ -s $conf && $FORCE_CONFIG != 1 ]]; then
    log "$conf уже есть — не трогаю"
  else
    backup_once "$conf"
    local obfs stats
    obfs=$(openssl rand -base64 32); stats=$(openssl rand -hex 32)
    sed -e "s|:__HY2_PORT__|:${HY2_PORT}|" \
        -e "s|__PANEL_AUTH_URL__|http://127.0.0.1:${PANEL_PORT}/authenticate|" \
        -e "s|__MASQUERADE_URL__|https://${TLS_DOMAIN}/|" \
        -e "s|__OBFS_PASSWORD__|${obfs}|" -e "s|__STATS_SECRET__|${stats}|" \
        "$SRC_DIR/host-agent/hysteria/config.yaml.example" > "$conf"
    chmod 600 "$conf"; unset obfs
    printf '%s' "$stats" > "$SECRETS_DIR/hy2-stats-secret"; chmod 600 "$SECRETS_DIR/hy2-stats-secret"
    unset stats
  fi
  install -m 644 "$SRC_DIR/host-agent/hysteria/hysteria-server.service" /etc/systemd/system/hysteria-server.service
  systemctl daemon-reload
  systemctl enable hysteria-server.service >/dev/null 2>&1
  systemctl restart hysteria-server.service
  conf_set HYSTERIA_CONFIG "$conf"
  conf_set HYSTERIA_CERT "$dir/tls.crt"
  conf_set HYSTERIA_SERVICE hysteria-server
  conf_set HYSTERIA_SNI "$TLS_DOMAIN"
  conf_set HYSTERIA_STATS_URL "http://127.0.0.1:${HY2_STATS_PORT}"
  conf_set HYSTERIA_STATS_SECRET "$(cat "$SECRETS_DIR/hy2-stats-secret")"
  restart_agent
}
verify_hysteria() {
  ck "служба активна"                   unit_active hysteria-server
  ck "служба включена"                   unit_enabled hysteria-server
  ck "слушает udp/$HY2_PORT"             waits udp "$HY2_PORT"
  ck "config.yaml 0600"                  test "$(stat -c %a /etc/hysteria/config.yaml)" = 600
  ck "авторизация строго на loopback"    bash -c "grep -q 'http://127.0.0.1:$PANEL_PORT/authenticate' /etc/hysteria/config.yaml"
  ck "Traffic Stats отвечает 200"        is_http HYSTERIA_STATS_SECRET "http://127.0.0.1:$HY2_STATS_PORT/online" 200
}

# ---------------------------------------------------------------- этап telemt
stage_telemt() {
  note "этап telemt: MTProto-движок $TELEMT_VERSION на tcp/$TELEMT_PORT, Control API $TELEMT_API"
  local bin=/bin/telemt conf=/etc/telemt/telemt.toml
  if [[ -x $bin ]] && telemt --version 2>&1 | grep -q "$TELEMT_VERSION"; then
    log "бинарник уже $TELEMT_VERSION — скачивание пропущено"
  else
    install -d /usr/local/src/telemt
    local a="telemt-$(uname -m)-linux-gnu.tar.gz"
    ( cd /usr/local/src/telemt && curl -fsSL --proto '=https' -o "$a" \
        "https://github.com/telemt/telemt/releases/download/$TELEMT_VERSION/$a" &&
      printf '%s  %s\n' "$TELEMT_SHA256" "$a" | sha256sum -c - && tar -xzf "$a" )
    install -m 755 "/usr/local/src/telemt/telemt" "$bin"
  fi
  id telemt >/dev/null 2>&1 || useradd -d /opt/telemt -m -r -U telemt
  install -d -m 755 -o telemt -g telemt /etc/telemt
  if [[ -s $conf && $FORCE_CONFIG != 1 ]]; then
    log "$conf уже есть — не трогаю"
  else
    backup_once "$conf"
    install -m 640 "$SRC_DIR/host-agent/telemt/telemt.toml" "$conf"
    local token boot
    token="Bearer $(openssl rand -hex 32)"; boot=$(openssl rand -hex 16)
    sed -i -e "s|^auth_header = .*|auth_header = \"${token}\"|" \
           -e "s|^bootstrap = .*|bootstrap = \"${boot}\"|" \
           -e "s|^listen = .*|listen = \"${TELEMT_API}\"|" \
           -e "s|^public_host = .*|public_host = \"${PUBLIC_HOST}\"|" \
           -e "s|^public_port = .*|public_port = ${TELEMT_PORT}|" \
           -e "s|^port = .*|port = ${TELEMT_PORT}|" \
           -e "s|^tls_domain = .*|tls_domain = \"${TLS_DOMAIN}\"|" "$conf"
    unset token boot
    # НЕ root:telemt, а telemt:telemt: Control API пишет конфиг атомарной заменой,
    # и при чужом владельце отвечает internal_error, молча не добавив клиента.
    chown telemt:telemt "$conf"; chmod 640 "$conf"
  fi
  install -m 644 "$SRC_DIR/host-agent/telemt/telemt.service" /etc/systemd/system/telemt.service
  systemctl daemon-reload
  systemctl enable telemt >/dev/null 2>&1
  systemctl restart telemt; sleep 2
  local token
  token=$(awk -F'"' '/^auth_header/{print $2; exit}' "$conf")
  conf_set MTPROTO_API_URL "http://${TELEMT_API}"
  conf_set MTPROTO_API_TOKEN "$token"
  conf_set MTPROTO_SERVICE telemt
  unset token
  restart_agent
  warn "в движке пока только служебный клиент bootstrap. Создайте настоящего в разделе «MTProto», "
  warn "затем удалите bootstrap кнопкой «Удалить»: без хоть одного пользователя движок не стартует после reboot."
}
verify_telemt() {
  ck "бинарник $TELEMT_VERSION"          bash -c "telemt --version | grep -q '$TELEMT_VERSION'"
  ck "юнит активен"                       unit_active telemt
  ck "нет crash-loop (NRestarts <= 2)"    bash -c "test \$(systemctl show telemt -p NRestarts --value) -le 2"
  ck "слушает tcp/$TELEMT_PORT"           waits tcp "$TELEMT_PORT"
  ck "конфиг принадлежит движку"           bash -c "test \$(stat -c '%U:%G' /etc/telemt/telemt.toml) = telemt:telemt"
  ck "Control API на loopback"             waits_addr "$TELEMT_API"
  ck "/v1/users отвечает 200"              is_http MTPROTO_API_TOKEN "http://$TELEMT_API/v1/users" 200
  ck_warn "движок не ругается на конфиг"   bash -c "! journalctl -u telemt --since -10min --no-pager | grep -q 'Invalid config'"
}

# ---------------------------------------------------------------- этап fail2ban
stage_fail2ban() {
  note "этап fail2ban: sshd + панель + Hysteria2 + recidive (лестница: 2 неудачи → 30 минут)"
  if [[ -z $OPERATOR_IPS ]]; then
    # Из pipe (ssh -T без pty, CI, `curl | bash`) спросить негде: read вернул бы EOF и этап
    # ушёл в бан-политику без белого списка. Поэтому без терминала — прежнее поведение.
    [[ -t 0 ]] || abort "OPERATOR_IPS пуст, а stdin не терминал — спросить негде. Запустите ./bootstrap.sh в терминале: он сам определит ваш адрес и спросит, что ещё внести в ignoreip. Или передайте явно: OPERATOR_IPS=203.0.113.10 sudo -E ./bootstrap.sh --stage fail2ban"
    ask_operator_ips
  fi
  [[ -n $OPERATOR_IPS ]] || abort "OPERATOR_IPS пуст. Без своего адреса в ignoreip первая опечатка с домашнего адреса = бан на 30 минут, второй бан за сутки = DROP навсегда. Возьмите адрес дома (curl -4 https://ifconfig.co) и повторите: OPERATOR_IPS=203.0.113.10 sudo -E ./bootstrap.sh --stage fail2ban"
  # Значение из чужой подсказки вставляют буквально, вместе с угловыми скобками. В ignoreip такая
  # запись не запрещает бан, а просто ничего не игнорирует: оператор с maxretry=2 банит сам себя.
  local entry
  for entry in ${OPERATOR_IPS//,/ }; do
    [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] ||
      abort "OPERATOR_IPS='$OPERATOR_IPS': '$entry' не IPv4 и не CIDR. Нужен ваш реальный egress-адрес, без скобок и слов"
  done
  # install.sh здесь — только ради jail-файлов, но он пересобирает контейнер и печатает строку
  # доступа: без этих переменных он отчитался бы «127.0.0.1:5000, login admin» про живую панель.
  ( cd "$SRC_DIR" && umask 022 && ADMIN_LOGIN=$ADMIN_LOGIN PANEL_PORT=$PANEL_PORT \
      ./install.sh --with-fail2ban --expose-firewall )
  # ignoreip — список через пробел; запятую в значение из окружения вставляют по привычке, и она
  # склеила бы два адреса в один неверный токен.
  OPERATOR_IPS=${OPERATOR_IPS//,/ }
  sed -e "s|__OPERATOR_IPS__|${OPERATOR_IPS} ${PUBLIC_HOST}|" \
    "$SRC_DIR/host-agent/fail2ban/jail.d/awg-panel.local.example" > /etc/fail2ban/jail.d/awg-panel.local
  chmod 600 /etc/fail2ban/jail.d/awg-panel.local
  systemctl restart fail2ban; sleep 3
}
verify_fail2ban() {
  ck "fail2ban активен"                   unit_active fail2ban
  ck "четыре jail'а"                       bash -c "fail2ban-client status | grep -qE 'Number of jail:\s*4'"
  ck "jail awg-panel поднят"               fail2ban-client status awg-panel
  ck "jail awg-hy2 поднят"                 fail2ban-client status awg-hy2
  ck "jail recidive поднят"                fail2ban-client status recidive
  ck "maxretry = 2"                         test "$(fail2ban-client get awg-panel maxretry)" = 2
  ck "адрес узла в ignoreip панели"         bash -c "fail2ban-client get awg-panel ignoreip | grep -qF '$PUBLIC_HOST'"
  # Проверка именно перехода, а не наличия цепочки: f2b-panel создаётся всегда, а без
  # «DOCKER-USER -> f2b-panel» бан панели не трогает трафик. Так вышло на 09.11 после
  # перезагрузки — fail2ban поднялся за пять секунд до dockerd, actionstart не нашёл
  # цепочки и молча оставил jail без фильтра.
  if ! ck "бан панели живёт в DOCKER-USER"  bash -c "iptables -S DOCKER-USER | grep -q f2b-panel"; then
    warn "  починка: systemctl restart fail2ban (после этой правки переход доставляется и при бане)"
  fi
  ck "fail2ban стартует после docker"       bash -c "systemctl cat fail2ban | grep -qE '^After=docker[.]service$'"
  # Jail sshd наследует ignoreip из [DEFAULT], и проверка «адрес узла в ignoreip панели» про самого
  # оператора ничего не говорит: на 09.11 в ignoreip лежал плейсхолдер, а оператор улетел в бан со
  # своими же клиентами. Сравнивать имеет смысл только когда OPERATOR_IPS передан.
  if [[ -n $OPERATOR_IPS ]]; then
    local entry
    for entry in ${OPERATOR_IPS//,/ }; do
      ck "оператор $entry в ignoreip sshd"  bash -c "fail2ban-client get sshd ignoreip | grep -qF '$entry'"
    done
  fi
}

# ---------------------------------------------------------------- итог прогона
print_access() {
  # Отдельный блок в конце: пароль печатается на этапе panel, а после него идут ещё этапы —
  # к концу прогона он уезжает за экран, и оператор успевает спросить «где пароль».
  local pwfile=$SECRETS_DIR/admin-password.txt
  echo
  note "доступ к панели"
  secret "адрес:  http://${PUBLIC_HOST}:${PANEL_PORT}/login"
  secret "логин:  ${ADMIN_LOGIN}"
  if [[ ! -s $pwfile ]]; then
    secret "пароль: не создавался (этап panel не выполнялся) — $pwfile пуст"
    return 0
  fi
  if [[ $ADMIN_PASSWORD_FRESH == 1 ]]; then
    secret "пароль: $(cat "$pwfile")"
  else
    secret "пароль: тот, что вы задали сами (панель меняет его при первом входе)"
  fi
  secret "ВНИМАНИЕ: смените пароль при первом входе — пока must_change = 1, панель пускает только на /password."
  secret "Первоначальный пароль всегда можно перечитать с узла: sudo cat $pwfile (0600; в лог прогона он не писался)"
}

# ---------------------------------------------------------------- --check
do_check() {
  CHECK_ONLY=1
  note "проверка узла: только чтение, ничего из конфигов не меняется"
  local s
  for s in "${STAGES[@]}"; do "verify_$s" || true; done
  note "что должно слушаться наружу"
  echo "  ожидалось: tcp/22, tcp/$PANEL_PORT, tcp/$TELEMT_PORT, udp/$AWG_PORT, udp/$HY2_PORT"
  ss -tulnp | grep -vE '127\.0\.0\.1|\[::1\]|127\.0\.0\.53' | sed 's/^/    /'
  note "сверка"
  echo "  ключи agent.conf (только имена): $(conf_keys)"
  echo "  диск: $(df -h / | awk 'NR==2{print $4" свободно из "$2", занято "$5}')"
  echo "  бэкапы: $(ls -1 /var/backups/awg-panel 2>/dev/null | wc -l) архивов (retention 7)"
  echo "  пароль администратора: $SECRETS_DIR/admin-password.txt (0600)"
  echo "  backup.key: /etc/awg-panel/backup.key — копию держать ВНЕ узла, без неё архивы нечитаемы"
  if (( CHECK_FAILS > 0 )); then echo; echo "  ИТОГ: провалено проверок — $CHECK_FAILS"; return 1; fi
  echo; echo "  ИТОГ: все проверки пройдены"
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

main() {
  local only="" skip_list=() mode=install
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check) mode=check ;;
      --stage) only=${2:?укажите этап: ${STAGES[*]}}; shift ;;
      --skip) skip_list+=("${2:?укажите этап: ${STAGES[*]}}"); shift ;;
      --force-config) FORCE_CONFIG=1 ;;
      -h|--help) usage; exit 0 ;;
      *) abort "неизвестный режим $1 (см. --help)" ;;
    esac
    shift
  done
  require_root; prepare_paths; require_platform; detect_uplink
  if [[ $mode == check ]]; then do_check; exit $?; fi
  [[ -z $only || " ${STAGES[*]} " == *" $only "* ]] || abort "нет этапа $only; есть: ${STAGES[*]}"
  local sk
  for sk in "${skip_list[@]:-}"; do
    [[ -z $sk || " ${STAGES[*]} " == *" $sk "* ]] || abort "нет этапа $sk в списке пропуска; есть: ${STAGES[*]}"
  done
  log "узел $PUBLIC_HOST на $UPLINK: панель :$PANEL_PORT, awg udp/$AWG_PORT, hy2 udp/$HY2_PORT, mtproto tcp/$TELEMT_PORT"
  local s
  for s in "${STAGES[@]}"; do
    [[ -n $only && $only != "$s" ]] && continue
    [[ " ${skip_list[*]:-} " == *" $s "* ]] && { log "этап $s пропущен (--skip)"; continue; }
    log "--- этап $s: начало ---"
    "stage_$s"
    "verify_$s"
    log "--- этап $s: проверкой подтверждён ---"
  done
  if [[ -n $only ]]; then
    log "этап $only завершён; полный отчёт: sudo ./bootstrap.sh --check"
  else
    do_check || warn "есть непройденные проверки — см. [FAIL] и [ВНИМ]"
    print_access
    log "Дальше: создать первого клиента в каждом протоколе и проверить выдаваемые профили (docs/install.md, чек-лист приёмки)."
  fi
}

main "$@"
