# VPR – Personal Stealth Tunnel

Этот репозиторий содержит реализацию персонального VPN-протокола на базе MASQUE/Noise.

## Директории
- `src/` – Rust/Go сервисы (MASQUE core, DNS, bootstrap).
- `gui/` – Python GUI `vpr Studio`.
- `infra/` – Terraform/Ansible/Nix модули.
- `docs/` – архитектура, операционные мануалы.
- `scripts/` – утилиты (`tls-fp-sync`, health harness и т.д.).
- `config/` – образцы конфигураций (`masque.toml`, `doh.toml`).
- `secrets/` – описание и шаблоны для ключей/сертификатов.

См. `TODO.md` для детального плана работ.

## Быстрый старт

```sh
cargo build --release
# Noise статические ключи (IK):
scripts/gen-noise-keys.sh secrets   # создаст secrets/server.key|.pub и client.key|.pub

# Серверы (быстро):
scripts/local-bootstrap.sh   # сгенерит cert/odoh_seed, поднимет оба сервиса, прогонит health-harness

# Ручной запуск серверов:
target/release/masque-core --config config/masque.toml.sample --noise-key secrets/server.key
target/release/doh-gateway --config config/doh.toml.sample --odoh-enable --odoh-seed secrets/odoh_seed.bin --doq-cert secrets/doq.crt --doq-key secrets/doq.key

# Тестовый клиент Noise/TLS (TCP):
echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | target/release/client --addr 127.0.0.1:4433 --server-name localhost --target example.com:80 --proto tcp --noise-key secrets/client.key --noise-peer-pub secrets/server.pub

# Тест UDP (DNS): локальный UDP слушатель 9053
target/release/client --addr 127.0.0.1:4433 --server-name localhost --target 1.1.1.1:53 --proto udp --udp-listen 127.0.0.1:9053 --noise-key secrets/client.key --noise-peer-pub secrets/server.pub
dig @127.0.0.1 -p 9053 example.com

# Health harness (локально проверяет DoH/DoQ/ODoH):
target/release/health-harness --doh-url http://127.0.0.1:8053/dns-query --odoh-url http://127.0.0.1:8053/odoh-query --doq-addr 127.0.0.1:8853 --server-name localhost --samples=3 --insecure-tls

> инструмент завершает работу строкой `HEALTH_REPORT {json}`, где отражены статусы/задержки каждого транспорта и итоговый suspicion score; GUI парсит именно эту строку.
```

- GUI Health: подсвечивает статус и даёт быстрые действия (Rotate DoH при WARN, Swap Node при CRITICAL).
## Health history CLI

- GUI вкладка Health подсвечивает кнопку и пишет рекомендации (Warn → rotate, Critical → swap) на основе suspicion.

```sh
python scripts/health-history.py --tail 5
```

Выведет последние отчёты из `~/.vpr/health_reports.jsonl` с их suspicion/jitter; `--json` вернёт сырой JSON для дальнейшей автоматизации.

## Tests

```sh
python -m unittest discover tests
```
