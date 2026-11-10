"""Инварианты bootstrap.sh и узловых шаблонов.

Смысл этих тестов не в покрытии логики (её исполняет bash), а в том, чтобы скрипт и файлы,
которые он копирует на узел, не разъехались: sed по несуществующей строке не ругается, а
молча оставляет в бою конфиг с placeholder'ом.
"""

import re
from pathlib import Path
import subprocess

import pytest

import host_agent
from host_agent import Agent

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = (ROOT / "bootstrap.sh").read_text("utf-8")
INSTALL = (ROOT / "install.sh").read_text("utf-8")
AWG_TEMPLATE = (ROOT / "host-agent" / "amneziawg" / "awg0.conf.example").read_text("utf-8")
HY2_TEMPLATE = (ROOT / "host-agent" / "hysteria" / "config.yaml.example").read_text("utf-8")
TELEMT_TEMPLATE = (ROOT / "host-agent" / "telemt" / "telemt.toml").read_text("utf-8")
LOCAL_JAIL = (ROOT / "host-agent" / "fail2ban" / "jail.d" / "awg-panel.local.example").read_text("utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text("utf-8")


def func_body(name: str, text: str = BOOTSTRAP) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert match, f"нет функции {name}"
    return match.group(1)


def code(text: str) -> str:
    """Строки кода: комментарии — это рассуждения автора, а не поведение."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def double_quoted_spans(text: str) -> list[str]:
    """Содержимое двойных кавычек: одинарные кавычки и хвостовые комментарии в расчёт не идут."""
    spans: list[str] = []
    buf: list[str] = []
    state, i = None, 0
    while i < len(text):
        ch = text[i]
        if state is None:
            if ch == '"':
                state, buf = "d", []
            elif ch == "'":
                state = "s"
            elif ch == "#":
                break
        elif state == "s":
            if ch == "'":
                state = None
        elif ch == "\\":
            buf.append(text[i:i + 2])
            i += 2
            continue
        elif ch == '"':
            spans.append("".join(buf))
            state = None
        else:
            buf.append(ch)
        i += 1
    return spans


def sed_left_sides(body: str) -> list[str]:
    """Левые части sed-замен в том виде, в каком они обязаны найтись в шаблоне."""
    found = []
    for lhs in re.findall(r'-e "s\|\^?([^"|]+)\|', body):
        lhs = lhs.replace("\\.", ".").rstrip()
        found.append(lhs[:-2].rstrip() if lhs.endswith(".*") else lhs)
    return found


def test_every_stage_is_installed_and_verified() -> None:
    stages = re.search(r"^readonly STAGES=\(([^)]*)\)", BOOTSTRAP, re.M).group(1).split()
    assert stages == ["base", "awg", "panel", "hysteria", "telemt", "fail2ban"]
    for stage in stages:
        func_body(f"stage_{stage}")
        func_body(f"verify_{stage}")
    declared = set(re.findall(r"^(?:stage|verify)_(\w+)\(\)", BOOTSTRAP, re.M))
    assert declared == set(stages), f"этапы без пары: {sorted(declared ^ set(stages))}"
    assert re.search(rf'^\s+"stage_\$s"\n\s+"verify_\$s"$', BOOTSTRAP, re.M), "проверка не идёт сразу за установкой"


def test_foreign_code_is_pinned_by_hash() -> None:
    for name in ("TELEMT_SHA256", "HYSTERIA_SHA256"):
        assert re.search(rf"^readonly {name}=[0-9a-f]{{64}}$", BOOTSTRAP, re.M), name
    assert re.search(r"^readonly AMNEZIA_PPA_FINGERPRINT=[0-9A-F]{40}$", BOOTSTRAP, re.M)
    for stage in ("stage_hysteria", "stage_telemt"):
        body = code(func_body(stage))
        assert "sha256" in body, f"{stage}: скачивание без сверки хеша"
        assert not re.search(r"curl[^|]*\|\s*(?:bash|sh)\b", body), f"{stage}: чужой код выполняется из pipe"


def test_amnezia_ppa_is_added_only_after_the_fingerprint_matches() -> None:
    body = code(func_body("amnezia_ppa"))
    assert body.index("signing_key_fingerprint") < body.index("abort") < body.index('> "$list"')
    assert "signed-by=" in body


def test_bootstrap_writes_only_keys_the_agent_accepts() -> None:
    """read_config_file падает на unknown key, поэтому новый ключ в agent.conf возможен только вместе с правкой кода агента."""
    written = set(re.findall(r"^ +conf_set ([A-Z0-9_]+)", BOOTSTRAP, re.M))
    assert written, "bootstrap.sh перестал настраивать agent.conf"
    unknown = written - set(host_agent.DEFAULTS)
    assert not unknown, f"агент не знает ключей: {sorted(unknown)}"
    required = {
        "INTERFACE",
        "INTERFACE_CONFIG",
        "HYSTERIA_CONFIG",
        "HYSTERIA_STATS_URL",
        "HYSTERIA_STATS_SECRET",
        "MTPROTO_API_URL",
        "MTPROTO_API_TOKEN",
        "MTPROTO_SERVICE",
    }
    assert required <= written, f"разделы панели останутся без настроек: {sorted(required - written)}"
    # Имя интерфейса агент подставляет в команды awg; без него AWG_IF=wg1 настроит конфиг,
    # а агент останется с дефолтным awg0.
    assert re.search(r'^ +conf_set INTERFACE "\$AWG_IF"$', BOOTSTRAP, re.M)


@pytest.mark.parametrize("stage", ["stage_awg", "stage_hysteria", "stage_telemt"])
def test_sed_substitutions_match_a_real_line_in_the_template(stage: str) -> None:
    """Проверить, что подстановка чего-то касается: несуществующий ключ sed молчит, а узел получает placeholder."""
    templates = {
        "stage_awg": AWG_TEMPLATE,
        "stage_hysteria": HY2_TEMPLATE,
        "stage_telemt": TELEMT_TEMPLATE,
    }
    body = code(func_body(stage))
    lefts = sed_left_sides(body)
    assert lefts, f"{stage}: в этапе нет ни одной sed-подстановки"
    for left in lefts:
        assert left in templates[stage], f"{stage}: в шаблоне нет строки {left!r} — sed не сработает"


def test_templates_hold_no_secrets() -> None:
    for name, text in (
        ("awg0.conf.example", AWG_TEMPLATE),
        ("config.yaml.example", HY2_TEMPLATE),
        ("telemt.toml", TELEMT_TEMPLATE),
        ("awg-panel.local.example", LOCAL_JAIL),
    ):
        assert not re.search(r"[A-Za-z0-9+/]{43}=", text), f"{name}: похоже на настоящий ключ"
        assert not re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", text), f"{name}: похоже на настоящий токен"
    assert "PrivateKey = __GENERATED__" in AWG_TEMPLATE
    assert "HeaderProtectionKey = __GENERATED__" in AWG_TEMPLATE
    assert "password: __OBFS_PASSWORD__" in HY2_TEMPLATE
    assert "secret: __STATS_SECRET__" in HY2_TEMPLATE
    assert re.search(r'^auth_header = ""$', TELEMT_TEMPLATE, re.M)
    assert re.search(r'^bootstrap = ""$', TELEMT_TEMPLATE, re.M)


def test_client_profile_gets_the_whole_obfuscation_block() -> None:
    """Панель выдаёт клиенту строки [Interface] копией (interface_section), поэтому вычеркнутый из шаблона
    параметр обфускации — это молча нерабочий профиль, а не cosmetic-правка."""

    class _OnlyPath:
        interface_config = ROOT / "host-agent" / "amneziawg" / "awg0.conf.example"

    copied = {line.split(" =")[0] for line in Agent(_OnlyPath()).interface_section()}
    missing = {"MTU", "H1", "H2", "H3", "H4", "S1", "S2", "S3", "S4",
               "Jc", "Jmin", "Jmax", "HeaderProtectionKey", "RandomTrailers"} - copied
    assert not missing, f"в выдаваемый клиенту профиль не попадают: {sorted(missing)}"
    assert not copied & {"Address", "ListenPort", "PrivateKey", "PostUp", "PostDown"}
    assert "__" not in "".join(copied)
    assert int(re.search(r"^Jc = (\d+)", AWG_TEMPLATE, re.M).group(1)) <= 122
    assert "MTU = 1280" in AWG_TEMPLATE


def test_generated_awg_s_values_respect_the_protocol_limits() -> None:
    """AWG 3.1: S3 и S4 не меньше 12, S1+56 != S2, S3 != S2+28 (нарушено — мод укладывает трафик в мусор)."""
    body = code(func_body("stage_awg"))
    generators = {
        match.group(1): int(match.group(2))
        for match in re.finditer(r"(s[1-4])=\$\(\( \(RANDOM % \d+\) \+ (\d+) \)\)", body)
    }
    assert set(generators) == {"s1", "s2", "s3", "s4"}, generators
    for var in ("s3", "s4"):
        assert generators[var] >= 12, f"{var} может родиться меньше 12"
    assert re.search(r"while \[\[ \$\(\(s1 \+ 56\)\) -eq \$s2 \]\]", body)
    assert re.search(r"while \[\[ \$s3 -eq \$\(\(s2 \+ 28\)\) \]\]", body)


def test_argument_parsing_consumes_the_value_not_the_flag() -> None:
    """`--skip hysteria` обязан добавлять этап, а не строку '--skip': иначе «пропущенный» этап всё равно ставится."""
    branches = dict(re.findall(r"^ +(--[a-z-]+)\) (.*) ;;$", BOOTSTRAP, re.M))
    assert set(branches) == {"--check", "--stage", "--skip", "--force-config"}
    for option in ("--stage", "--skip"):
        assert "${2:" in branches[option] and "shift" in branches[option], option
    main = func_body("main")
    assert main.index("require_root") < main.index("do_check"), "--check пишется до проверки root"
    assert re.search(r'for sk in "\$\{skip_list\[@\]:-\}"', main), "имя этапа в --skip не проверяется"


def test_help_exits_before_any_write_to_the_node() -> None:
    bash = subprocess.run(["bash", "--version"], capture_output=True, text=True)
    if bash.returncode != 0:
        pytest.skip("нет bash")
    run = subprocess.run(
        ["bash", str(ROOT / "bootstrap.sh"), "--help"], capture_output=True, text=True, cwd=ROOT
    )
    assert run.returncode == 0, run.stderr
    assert "--force-config" in run.stdout and "ОСТАНОВ" not in run.stdout
    for leaked in ("set -Eeuo", "readonly ", "umask "):
        assert leaked not in run.stdout, f"в справку попало {leaked!r} — awk вышел за блок комментариев"


def test_every_declared_parameter_is_actually_used() -> None:
    """Параметр, который ни на что не влияет, — ловушка: PANEL_BIND=127.0.0.1 выглядит как настройка режима."""
    declared = re.findall(r"^([A-Z][A-Z0-9_]+)=\$\{[A-Z][A-Z0-9_]+:-", BOOTSTRAP, re.M)
    declared += re.findall(r"^readonly ([A-Z][A-Z0-9_]+)=", BOOTSTRAP, re.M)
    assert declared
    # Строки объявлений сами содержат ${ИМЯ:-...} — в поиске использования их быть не должно.
    body = "\n".join(
        line for line in BOOTSTRAP.splitlines()
        if not re.match(r"^(?:readonly )?[A-Z][A-Z0-9_]+=", line)
    )
    unused = [name for name in set(declared) if not re.search(rf"\$\{{?{name}\b", body)]
    assert not unused, f"нигде не читаются: {sorted(unused)}"


def test_node_configs_survive_a_rerun_without_force_config() -> None:
    for stage in ("stage_awg", "stage_hysteria", "stage_telemt"):
        body = func_body(stage)
        assert "FORCE_CONFIG != 1" in body, f"{stage}: перезапись боевого конфига без флага"
        assert "backup_once" in body, f"{stage}: старое значение не сохраняется"


def test_script_never_reboots_and_never_touches_ssh_or_ufw() -> None:
    """Перезагрузка и режим фильтрации — решения оператора; скрипт их не принимает (см. шапку)."""
    assert "sshd_config" not in BOOTSTRAP
    for token in ("PasswordAuthentication", "PermitRootLogin"):
        for line in BOOTSTRAP.splitlines():
            if token in line:
                assert line.lstrip().startswith("#"), f"упоминание {token} вне комментария: {line}"
    body = code(BOOTSTRAP)
    assert not re.search(r"(?:^|[;&|]\s*)(?:/s?bin/)?(?:reboot|shutdown|poweroff|halt)\b", body, re.M)
    assert not re.search(r"ufw[^\n]*(?:enable|disable|default)", body)


def test_container_health_check_waits_for_the_first_probe() -> None:
    """install.sh возвращается до первой пробы HEALTHCHECK, поэтому healthy нужно дождаться.

    Однострочный grep по статусу из `docker ps` в этот момент видит "(health: starting)"
    и ронял весь этап на заведомо живом узле.
    """
    assert re.search(r'ck "контейнер healthy"\s+panel_is_healthy$', BOOTSTRAP, re.M), \
        "проверка healthy не вызывает ожидание"
    body = code(func_body("panel_is_healthy"))
    assert "{{.State.Health.Status}}" in body and re.search(r"\bsleep\b", body)
    assert re.search(r"^\s+id=\$\(docker ps -q", BOOTSTRAP, re.M), "id контейнера не определяется"


def test_the_database_is_readable_only_by_its_owner() -> None:
    """Права базе задаёт тот, кто её создаёт. chmod в install.sh отрабатывает до `compose up -d
    --build`, то есть на девственном узле — по несуществующему файлу, и база с паролями Hysteria2
    открытым текстом оставалась 0644 (22.04, 09.11); проверка этапа panel на этом и встала.
    umask'ом в docker-compose.yml это не лечится: Compose с узла такое свойство отклоняет.
    640 тоже не годится: группа на файле — primary gid контейнера (999 в образе), а на узле этот
    gid занят чужой системной группой (24.04, 10.11 — systemd-journal), и читающие базу становятся
    читателями «случайной» группы хоста. Поэтому и создаём, и проверяем ровно 600."""
    db = (ROOT / "app" / "db.py").read_text("utf-8")
    assert re.search(r"Path\(path\)\.touch\(0o600\)", db), "база создаётся без явных прав"
    assert 'umask:' not in COMPOSE, "compose с узла не принимает umask — установка встанет на валидации"
    assert re.search(r"-name 'panel\.sqlite3\*' -exec chmod 600", code(func_body("install_host_side", INSTALL))), \
        "уже созданная база не приводится к 600"
    assert re.search(r'ck "БД панели читается только владельцем"\s+bash -c "test \\\$\(stat -c %a .*\) = 600"',
                     code(func_body("verify_panel"))), \
        "проверка этапа panel не требует ровно 600"


def test_no_local_line_expands_a_variable_declared_on_the_same_line() -> None:
    """Все слова `local a=1 b=$a` bash раскрывает до присваиваний, а под `set -u` это abort этапа.

    Так и умер hysteria на первом живом прогоне: `conf=$dir/config.yaml` стояло на одной строке
    с `dir=`, и этап падал ещё до скачивания бинарника — текст скрипта при этом выглядит здоровым.
    """
    offenders = []
    for line in BOOTSTRAP.splitlines():
        stripped = line.strip()
        if not stripped.startswith("local "):
            continue
        declared = set(re.findall(r"\b([a-z_][a-z0-9_]*)=", stripped))
        offenders += [ref for ref in re.findall(r"\$\{?([a-z_][a-z0-9_]*)", stripped) if ref in declared]
    assert not offenders, f"local ссылается на переменную с этой же строки: {offenders}"


def test_no_command_substitution_inside_a_double_quoted_message() -> None:
    """Backticks в двойных кавычках — не пунктуация: bash выполняет их при сборке строки.

    На живом узле (09.11) предупреждение одного из этапов само запускало указанную в нём команду
    и вставляло её вывод в середину сообщения — вместо текста остались обрывки «если … молчит».
    """
    for name in ("bootstrap.sh", "install.sh"):
        for number, line in enumerate((ROOT / name).read_text("utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            hits = [s for s in double_quoted_spans(line) if "`" in s]
            assert not hits, f"{name}:{number}: в двойных кавычках сработает команда: {hits}"


def test_operator_address_is_required_in_the_sshd_ignoreip() -> None:
    """Проверка ignoreip панели молчит про sshd: именно так оператор сел в бан со своими клиентами."""
    body = code(func_body("verify_fail2ban"))
    assert re.search(r'\[\[ -n \$OPERATOR_IPS \]\]', body), "адрес оператора в sshd не сверяется"
    assert 'fail2ban-client get sshd ignoreip | grep -qF' in body


def test_panel_ban_does_not_depend_on_docker_having_started() -> None:
    """Перезагрузка 09.11: fail2ban поднялся на пять секунд раньше dockerd, actionstart не нашёл
    DOCKER-USER, и jail awg-panel остался с цепочкой, в которую никто не заходит — баны без эффекта.

    Второй заход (22.04, 09.11) показал, что одной правки actionban мало: Fail2Ban 0.11.2 вызывает
    actioncheck перед каждым баном, при неуспехе «Trying to restore a sane environment» не повторяет
    actionstart и отменяет бан совсем — до actionban очередь не доходит.
    """
    action = (ROOT / "host-agent" / "fail2ban" / "action.d" / "awg-panel-docker.conf").read_text("utf-8")
    jump = r"iptables -C DOCKER-USER -j f2b-<name>.*\|\| iptables -I DOCKER-USER -j f2b-<name>"
    ban = re.search(r"^actionban =.*?(?=^actionunban =)", action, re.M | re.S).group(0)
    assert re.search(jump, ban), "при бане переход в DOCKER-USER не доставляется"
    check = re.search(r"^actioncheck =.*?(?=^actionban =)", action, re.M | re.S).group(0)
    assert re.search(jump, check), "проверка перехода не доставляет его — на 0.11.2 бан не состоится"

    installer = code(func_body("install_fail2ban", INSTALL))
    assert "/etc/systemd/system/fail2ban.service.d" in installer, "drop-in с порядком старта не пишется"
    assert re.search(r"After=docker[.]service", installer), "fail2ban не упорядочен после docker"
    assert "systemctl daemon-reload" in installer, "systemd не перечитал юнит после drop-in"

    body = code(func_body("verify_fail2ban"))
    assert re.search(r'ck "бан панели живёт в DOCKER-USER"', body), "переход в DOCKER-USER не проверяется"
    assert re.search(r'ck "fail2ban стартует после docker"', body), "порядок старта не проверяется"


def test_listener_checks_wait_for_the_process() -> None:
    """`active` у юнита появляется раньше, чем процесс слушает порт: одиночный замер валил этап."""
    for stage, arg in (
        ("verify_hysteria", r'waits udp "\$HY2_PORT"'),
        ("verify_telemt", r'waits tcp "\$TELEMT_PORT"'),
        ("verify_telemt", r'waits_addr "\$TELEMT_API"'),
    ):
        assert re.search(rf"ck [^\n]+ {arg}$", code(func_body(stage)), re.M), f"{stage}: порт не дожидаются"
    for name in ("waits", "waits_addr"):
        body = code(func_body(name))
        assert "seq" in body and re.search(r"\bsleep\b", body), f"{name}: ожидание не ограничено по времени"


def test_operator_ips_is_an_address_not_a_placeholder() -> None:
    """Подсказку `'<ваш egress>'` вставляют в команду буквально; в ignoreip она не защищает, а пустая."""
    body = code(func_body("stage_fail2ban"))
    assert "[[ $entry =~ ^([0-9]{1,3}" in body, "формат OPERATOR_IPS не проверяется"
    for text in (BOOTSTRAP, (ROOT / "README.md").read_text("utf-8"),
                 (ROOT / "docs" / "install.md").read_text("utf-8")):
        assert "ваш egress" not in text, "плейсхолдер вместо адреса — его копируют в команду"


def test_fail2ban_stage_refuses_to_lock_the_operator_out() -> None:
    """Лестница maxretry=2: одна опечатка с домашнего адреса = 30 минут бана, поэтому без OPERATOR_IPS этап не стартует."""
    body = code(func_body("stage_fail2ban"))
    assert re.search(r'\[\[ -n \$OPERATOR_IPS \]\] \|\| abort', body)
    assert "__OPERATOR_IPS__" in body
    assert LOCAL_JAIL.splitlines()[-1].startswith("operator_ip = __OPERATOR_IPS__")
    assert re.search(r"chmod 600 /etc/fail2ban/jail\.d/awg-panel\.local\b", body)
    for local in (ROOT / "host-agent" / "fail2ban" / "jail.d").glob("*.local.example"):
        stem = local.name[: -len(".local.example")]
        assert (local.parent / f"{stem}.conf").exists(), f"{local.name}: под него нечем управлять"
    assert "%(operator_ip)s" in (ROOT / "host-agent" / "fail2ban" / "jail.d" / "awg-panel.conf").read_text("utf-8")


def test_hysteria_auth_and_stats_stay_on_loopback() -> None:
    assert "http://127.0.0.1:${PANEL_PORT}/authenticate" in code(func_body("stage_hysteria"))
    assert re.search(r"^trafficStats:\n  listen: 127\.0\.0\.1:", HY2_TEMPLATE, re.M)
    assert "http://127.0.0.1:$PANEL_PORT/authenticate" in code(func_body("verify_hysteria"))


def test_secrets_leave_the_script_only_through_files_and_environment() -> None:
    body = code(func_body("stage_panel"))
    assert re.search(r'ADMIN_PASSWORD="\$\(cat "\$pwfile"\)"', body)
    assert "./install.sh" in body
    assert 'chmod 600 "$pwfile"' in body
    # пароль установщика показывается оператору — но только в терминал этого запуска и только
    # в момент генерации; в $LOG_FILE (0600, но переживает перезагрузку) секрета быть не должно
    assert re.search(r'^\s+secret "пароль администратора: \$\(cat "\$pwfile"\)"', body, re.M)
    assert re.search(r'^\s+secret "при первом входе .*панель потребует его заменить"', body, re.M)
    printed = re.compile(r'\b(?:echo|log|note|pass|warn|bail|printf)\b[^\n]*cat "\$pwfile"')
    assert [line for line in BOOTSTRAP.splitlines() if printed.search(line)] == []
    helper = re.search(r'^secret\(\) \{.*\}$', BOOTSTRAP, re.M).group(0)
    assert "tee" not in helper and "printf" in helper
    for stage in ("stage_awg", "stage_hysteria", "stage_telemt"):
        text = code(func_body(stage))
        for secret in ("priv", "hpk", "obfs", "stats", "token", "boot"):
            assert not re.search(rf'(?:echo|log|printf|pass|warn|note) "[^"]*\$\{{?{secret}\b', text), f"{stage}: {secret} печатается в лог"


def test_unit_files_are_installable() -> None:
    for unit in (ROOT / "host-agent" / "hysteria").glob("*.service"):
        text = unit.read_text("utf-8")
        assert "[Install]" in text and "WantedBy=" in text, unit.name
        assert re.search(r"^ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml$", text, re.M)


def test_bootstrap_is_executable_after_clone() -> None:
    raw = (ROOT / "bootstrap.sh").read_bytes()
    assert raw.startswith(b"#!/usr/bin/env bash\n")
    assert b"\r\n" not in raw, "CRLF: на узле bash упадёт на первой же строке"
    listing = subprocess.run(
        ["git", "ls-files", "-s", "bootstrap.sh"], cwd=ROOT, capture_output=True, text=True
    )
    if listing.returncode != 0:
        pytest.skip("нет git — режим файла проверить нечем")
    assert listing.stdout.split()[0] == "100755", "после клона sudo ./bootstrap.sh не запустится"
