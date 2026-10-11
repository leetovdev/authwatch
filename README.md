# authwatch

![python](https://img.shields.io/badge/python-3.9%2B-black?style=flat-square)
![deps](https://img.shields.io/badge/dependencies-0-black?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

Анализатор SSH-логов для Linux-серверов. Находит брутфорс, перебор логинов и — самое важное —
**успешный вход после брутфорса**, то есть признак того, что сервер уже могли взломать.

```text
  authwatch
  2026-10-11 02:11 -> 2026-10-11 16:50

  events    55
  sources   5
  failed    39
  accepted  4

  alerts (5)
  [x] 203.0.113.77     login after brute force  'deploy' logged in via password after 14 failures
  [!] 203.0.113.45     brute force              18 failed logins within 10 min
  [!] 203.0.113.77     brute force              14 failed logins within 10 min
  [!] 192.0.2.55       root login               direct root login via publickey
  [!] 198.51.100.23    user enumeration         7 usernames tried (oracle, postgres, ubuntu, git, ...)

  top sources
  ip                fails  users  first seen    last seen
  203.0.113.45         18      4  Oct 11 02:11  Oct 11 02:14
  203.0.113.77         14      1  Oct 11 11:26  Oct 11 11:32
  198.51.100.23         7      7  Oct 11 03:40  Oct 11 04:16
```

## Что находит

| Алерт | Уровень | Когда срабатывает |
|---|---|---|
| login after brute force | critical | успешный вход с IP, который до этого много раз ошибался |
| brute force | high | N неудачных попыток за окно времени (по умолчанию 10 за 10 минут) |
| user enumeration | medium | с одного IP перебирают много разных логинов |
| root login | medium | прямой вход под root |

Понимает форматы `auth.log` (Debian/Ubuntu), `secure` (CentOS/RHEL), вывод `journalctl`,
ISO-время из rsyslog, IPv6, архивы `.gz` и новый `sshd-session` из OpenSSH 9.8+.

## Установка

```bash
git clone https://github.com/leetovdev/authwatch
cd authwatch
pip install .
```

## Использование

```bash
sudo authwatch /var/log/auth.log
sudo authwatch /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.*.gz
journalctl -u ssh --since today | authwatch
authwatch samples/auth.log --year 2026
```

Заблокировать всех, кто брутфорсил:

```bash
sudo authwatch /var/log/auth.log --blocklist bad.txt
while read ip; do sudo ufw deny from "$ip"; done < bad.txt
```

| Флаг | |
|---|---|
| `-t, --threshold` | сколько неудачных попыток считать брутфорсом (10) |
| `-w, --window` | окно в минутах (10) |
| `-u, --usernames` | сколько разных логинов считать перебором (5) |
| `--blocklist FILE` | список IP с алертами high/critical |
| `--json FILE` | полный результат в JSON |
| `--year` | год для syslog-строк, где он не пишется |

Код выхода: `0` — чисто, `1` — есть алерты, `2` — есть critical. Удобно для cron и мониторинга:

```bash
authwatch /var/log/auth.log > /dev/null || echo "check ssh logs" | mail -s alert admin@example.com
```

## Тесты

```bash
python -m unittest -v
```

В `samples/auth.log` — синтетический лог с атаками для демонстрации.
Все адреса в нём из диапазонов для документации (RFC 5737).

## Лицензия

MIT
