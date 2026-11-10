# Конфигурация: `agent.conf` и `.env`

Механика разделов и модель peer'ов — [`architecture.md`](architecture.md), порядок применения всего
этого при установке — [`install.md`](install.md).

## `/etc/awg-panel/agent.conf` — параметры хост-агента

Файл `root:root` `0600`. Порядок слияния: значения по умолчанию → файл → переменные окружения.

| Ключ | По умолчанию | Назначение |
| --- | --- | --- |
| `AWG_BIN` / `IP_BIN` / `FAIL2BAN_BIN` | `/usr/bin/awg`, `/usr/sbin/ip`, `/usr/bin/fail2ban-client` | пути к бинарям |
| `INTERFACE` | `awg0` | имя интерфейса AmneziaWG |
| `NETWORK` | `10.66.0.0/24` | пул адресов клиентов |
| `GATEWAY_ADDRESS` | `10.66.0.1` | адрес интерфейса; исключается из выдачи и обязан входить в `NETWORK` |
| `INTERFACE_CONFIG` | `/etc/amnezia/amneziawg/awg0.conf` | источник `[Interface]`-параметров (в т.ч. junk-отпечатка `Jc/Jmin/Jmax/S1/S2/H1..H4`) для профилей клиента |
| `PEERS_DIR` | `/etc/amnezia/amneziawg/panel-peers` | каталог drop-in'ов (`0700`) |
| `SOCKET_PATH` / `SOCKET_GROUP` | `/run/awg-panel/agent.sock` / `10001` | сокет агента и группа, которой дан доступ (`0660`) |
| `ENDPOINT_DEV` / `PUBLIC_ENDPOINT` | `ens3` / пусто | откуда взять внешний адрес для `Endpoint =` |
| `CLIENT_DNS` | `1.1.1.1` | `DNS =` в выдаваемом профиле |
| `COMMAND_TIMEOUT` | `5` | секунды, диапазон `1–60` |
| `HYSTERIA_CONFIG` / `HYSTERIA_CERT` | `/etc/hysteria/config.yaml` / `/etc/hysteria/tls.crt` | откуда агент читает порт, obfs и отпечаток сертификата для ссылок |
| `HYSTERIA_SERVICE` / `HYSTERIA_SNI` | `hysteria-server` / пусто | имя systemd-юнита и SNI, который кладётся в ссылку |
| `HYSTERIA_STATS_URL` / `HYSTERIA_STATS_SECRET` | пусто / пусто | Traffic Stats API hysteria2 (`http://127.0.0.1:9999` и secret для заголовка `Authorization`); пусто → онлайн по Hysteria2 не определяется |
| `MTPROTO_API_URL` | пусто | Control API движка `telemt` (`http://127.0.0.1:9091`); пусто → весь раздел MTProto отдаёт «не настроен», агент не делает ни одного HTTP-запроса |
| `MTPROTO_API_TOKEN` | пусто | значение заголовка `Authorization` целиком: telemt сверяет строку точно, поэтому здесь нужно писать `Bearer <токен>` и то же самое в `auth_header` конфига движка; пусто → запросы без авторизации |
| `MTPROTO_SERVICE` | `telemt` | имя systemd-юнита движка, нужно только для `is-active` в карточке «ДВИЖОК»; пусто → состояние не показывается |
| `OPENSSL_BIN` / `SYSTEMCTL_BIN` | `/usr/bin/openssl` / `/usr/bin/systemctl` | нужны только для `-fingerprint -sha256` и `is-active` |
| `BACKUP_SOURCE_DB` | `/opt/awg-panel/data/panel.sqlite3` | БД панели |
| `BACKUP_DIR` / `BACKUP_KEY_FILE` / `BACKUP_RETENTION` | `/var/backups/awg-panel` / `/etc/awg-panel/backup.key` / `7` | куда писать, чем шифровать, сколько архивов хранить |

## `.env` рядом с `docker-compose.yml` — только веб-слой

`PANEL_PORT`, `PANEL_BIND` (по умолчанию `127.0.0.1`), `ADMIN_LOGIN`, `SESSION_SECRET` (≥ 32 символов),
`ADMIN_PASSWORD` (нужен лишь на первом старте), `AGENT_SOCKET`, `AGENT_TIMEOUT`, `AUDIT_LOG` (пусто →
аудит пишется только в лог контейнера).

## Каталог сокета создаёт systemd, а не агент

`/run` — tmpfs, который обнуляется при каждой загрузке, а юнит агента идёт с `ProtectSystem=strict` и
`ReadWritePaths=/run/awg-panel`, где bind-монтирование отсутствующего пути обрывает старт ещё до Python
(`226/NAMESPACE`). Поэтому в `install.sh` ставится `host-agent/awg-panel.tmpfiles` →
`/etc/tmpfiles.d/awg-panel.conf`, а `systemd-tmpfiles-setup` гарантированно раньше
`multi-user.target`. Тот же механизм требует, чтобы `/var/backups/awg-panel` создавал установщик
(см. [`backups.md`](backups.md)).
