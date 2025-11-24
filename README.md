# VPR – Personal Stealth Tunnel

Персональный VPN на базе MASQUE/Noise с desktop-клиентом.

## Структура

```
src/
├── masque-core/     # MASQUE CONNECT-UDP сервер
├── doh-gateway/     # DoH/ODoH/DoQ DNS endpoints
├── health-harness/  # Health check утилита
└── vpr-app/         # Desktop клиент (Tauri)

infra/               # Terraform/Ansible модули
scripts/             # Утилиты развёртывания
config/              # Образцы конфигов
secrets/             # Шаблоны для ключей
docs/                # Документация
```

## Быстрый старт

### Клиент

```sh
make dev      # dev-режим с hot reload
make build    # сборка релиза
make app      # сборка и запуск

# или напрямую
./target/release/vpr-app
```

Пакеты после сборки:
- `target/release/bundle/deb/VPR_*.deb`
- `target/release/bundle/rpm/VPR-*.rpm`

### Сервер

```sh
cargo build --release

# Генерация ключей
scripts/gen-noise-keys.sh secrets

# Запуск
target/release/masque-core --config config/masque.toml.sample --noise-key secrets/server.key
target/release/doh-gateway --config config/doh.toml.sample --odoh-enable

# Health check
target/release/health-harness --doh-url http://127.0.0.1:8053/dns-query --samples=3
```

## Тесты

```sh
cargo test --workspace
```

## Health history CLI (Rust)

```sh
cargo run -p health-history -- --tail 5
```

Читает `~/.vpr/health_reports.jsonl`, выводит последние отчёты или `--json` для автоматизации. Заменяет старый python-скрипт.

## План работ

См. `TODO.md`
