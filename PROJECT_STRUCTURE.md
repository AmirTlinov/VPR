# VPR Project Structure

Описание структуры проекта VPR для разработчиков и контрибьюторов.

## Корневая структура

```
VPR/
├── .github/              # GitHub Actions и конфигурация
│   ├── workflows/        # CI/CD workflows
│   └── dependabot.yml    # Автоматическое обновление зависимостей
├── config/               # Образцы конфигурационных файлов
├── data/                 # Данные проекта
│   └── outbox/           # Outbox данные
├── docs/                 # Документация проекта
│   ├── design/           # Технические спецификации
│   ├── AI_STEALTH_PLAN.md
│   ├── AI_TRAFFIC_MORPHER.md
│   ├── architecture.md
│   ├── ROADMAP.md
│   ├── security.md
│   └── tui-earth.md
├── gui/                  # Python GUI (vpr Studio)
├── infra/                # Инфраструктура развертывания
│   ├── ansible/          # Ansible playbooks
│   ├── nix/              # Nix конфигурация
│   ├── systemd/          # Systemd сервисы
│   └── terraform/        # Terraform модули
├── logs/                 # Логи (gitignored)
├── ml/                   # ML модели и скрипты
├── scripts/              # Утилиты и скрипты
├── secrets/              # Секреты (gitignored, только README)
├── src/                  # Исходный код Rust
├── tests/                # Интеграционные тесты
├── .clippy.toml          # Конфигурация Clippy
├── .editorconfig         # Конфигурация редактора
├── .gitignore            # Git ignore правила
├── Cargo.toml            # Workspace конфигурация
├── Cargo.lock            # Lock файл зависимостей
├── CHANGELOG.md          # История изменений
├── CONTRIBUTING.md       # Руководство для контрибьюторов
├── LICENSE               # Лицензия MIT
├── Makefile              # Make команды
├── README.md             # Главный README
├── rustfmt.toml          # Конфигурация форматирования
└── TARGETS.md            # Описание целей сборки
```

## Rust Workspace

Проект использует Cargo workspace для управления несколькими крейтами:

### Core крейты

- **`src/masque-core/`** — MASQUE CONNECT-UDP сервер
  - Основной серверный компонент
  - Поддержка QUIC/HTTP/3
  - Hybrid Noise handshake
  - TLS fingerprint customization

- **`src/vpr-crypto/`** — Криптографические примитивы
  - Noise protocol
  - Hybrid ML-KEM768 + X25519
  - PKI и key management
  - Age encryption

- **`src/doh-gateway/`** — DNS-over-HTTPS/QUIC gateway
  - DoH/ODoH/DoQ endpoints
  - DNS health monitoring

- **`src/vpr-app/`** — Desktop клиент (Tauri)
  - GUI приложение
  - Kill switch
  - Process manager

### Вспомогательные крейты

- **`src/health-harness/`** — Health check утилита
- **`src/health-history/`** — CLI для истории health reports
- **`src/vpr-tui/`** — TUI с ASCII Earth
- **`src/vpr-ai/`** — AI Traffic Morpher

## Директории

### `config/`

Образцы конфигурационных файлов:
- `masque.toml.sample` — конфигурация MASQUE сервера
- `doh.toml.sample` — конфигурация DoH gateway
- `vpr.yaml.sample` — общая конфигурация VPR
- `tls_fingerprint_overrides.json` — TLS fingerprint overrides
- `tls_fp_sync_sources.json` — источники для синхронизации TLS fingerprints

### `docs/`

Документация проекта:
- `architecture.md` — архитектура проекта
- `ROADMAP.md` — план развития
- `security.md` — политики безопасности
- `design/` — технические спецификации компонентов
- `AI_*.md` — документация по AI компонентам

### `infra/`

Инфраструктура развертывания:
- `ansible/` — Ansible playbooks для автоматизации
- `terraform/` — Terraform модули для облачной инфраструктуры
- `nix/` — Nix конфигурация для reproducible builds
- `systemd/` — Systemd unit файлы для сервисов

### `scripts/`

Утилиты и скрипты:
- `e2e_*.sh` — E2E тесты
- `gen-noise-keys.sh` — генерация Noise ключей
- `tls-fp-sync.py` — синхронизация TLS fingerprints
- `build_release.sh` — сборка релиза

### `ml/`

ML модели и скрипты:
- `models/` — обученные модели (gitignored)
- `scripts/` — Python скрипты для обучения
- `config/` — конфигурация моделей
- `data/` — данные для обучения (gitignored)

### `secrets/`

Секреты (gitignored, только README.md в репозитории):
- Noise ключи
- TLS сертификаты
- Другие секретные материалы

## Конфигурационные файлы

### `.clippy.toml`

Конфигурация Rust Clippy линтера:
- Настройки сложности (cyclomatic complexity ≤ 10)
- Security линты
- Performance линты

### `rustfmt.toml`

Конфигурация форматирования кода:
- Edition 2021
- Максимальная ширина строки: 100
- Tab spaces: 4

### `.editorconfig`

Конфигурация редактора для консистентности:
- UTF-8 encoding
- LF line endings
- Indent size по типу файла

### `.gitignore`

Правила игнорирования для Git:
- Build artifacts (`target/`, `dist/`)
- Secrets (`secrets/**`, `*.key`, `*.pem`)
- Logs (`logs/`, `*.log`)
- IDE файлы (`.vscode/`, `.idea/`)
- OS файлы (`.DS_Store`, `Thumbs.db`)
- ML artifacts (большие модели)
- Terraform state файлы

## CI/CD

### `.github/workflows/ci.yml`

GitHub Actions workflow:
- Format check (`cargo fmt --check`)
- Clippy lint (`cargo clippy`)
- Test suite (`cargo test`)
- Build check для нескольких платформ

### `.github/dependabot.yml`

Автоматическое обновление зависимостей:
- Cargo зависимости (еженедельно)
- GitHub Actions (еженедельно)

## Стандарты

### Форматирование

```bash
cargo fmt
```

### Линтинг

```bash
cargo clippy --workspace --lib -- -D warnings
```

### Тестирование

```bash
cargo test --workspace
```

### Сборка

```bash
cargo build --release
```

## Best Practices

1. **Модульность**: Каждый компонент в отдельном крейте
2. **Тестирование**: Unit тесты рядом с кодом, integration тесты в `tests/`
3. **Документация**: Документация обновляется вместе с кодом
4. **Безопасность**: Секреты никогда не коммитятся
5. **CI/CD**: Все изменения проверяются автоматически

## Ссылки

- [README.md](README.md) — Обзор проекта
- [CONTRIBUTING.md](CONTRIBUTING.md) — Руководство для разработчиков
- [docs/architecture.md](docs/architecture.md) — Архитектура проекта
