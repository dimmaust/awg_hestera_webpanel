# Бэкапы и восстановление

Ключи и пароли, которые попадают в архив, — в [`architecture.md`](architecture.md); где создать
каталог бэкапов при установке — [`config.md`](config.md).

## Что и как пишется

`awg-panel-backup.timer` ежедневно в 03:30 (+ до 5 минут разброса, `Persistent=true`).
`host-agent/backup.py`: снапшот БД через online backup API с `PRAGMA integrity_check`, плюс `awg0.conf`,
`agent.conf` и весь `PEERS_DIR`; tar → `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt` с ключом из
`BACKUP_KEY_FILE`; запись через `.part` + `os.replace` (`0600`); обязательная проверка расшифровкой;
лишние архивы удаляются по `BACKUP_RETENTION`.

**В архиве лежит приватный ключ сервера** (в `awg0.conf`), поэтому он бесполезен без
`/etc/awg-panel/backup.key` — ключ нужно скопировать с узла сразу после установки.

## Расшифровка

```bash
cd /var/backups/awg-panel
enc=$(ls -1t *.tar.gz.enc | head -1)         # самый свежий архив
sudo mkdir -p /restore/awg-panel
sudo openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$enc" \
  -pass file:/etc/awg-panel/backup.key | sudo tar -xzf - -C /restore/awg-panel
```

`sudo` здесь не формальность: и `backup.key`, и сам архив доступны только root, а `tar` пишет в каталог
внутри `/restore`, которого на узле по умолчанию нет.

## Две тонкости, без которых бэкап не работает

Юнит сервиса идёт с `ProtectSystem=strict`, то есть корень для него read-only и `mkdir` внутри
`backup.py` не сработает: `/var/backups/awg-panel` обязан создать `install.sh`.

Файл БД контейнер создаёт с дефолтной маской, а в нём пароли клиентов Hysteria2 открытым текстом.
Каталог `data` и так `0700` от uid контейнера, поэтому права на сам файл доводит его создатель —
`app/db.py` ставит `0600` сразу после появления файла: читать его должны только root и uid панели.

## Первый архив

Таймер срабатывает в 03:30, и без ручного прогона первый архив можно не дождаться:

```bash
sudo systemctl start awg-panel-backup.service
ls -l /var/backups/awg-panel          # архив 0600, расширение .enc
```
