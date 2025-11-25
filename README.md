# VPR – Stealth VPN Tunnel

**VPR** (VPN Protocol Router) — ультра-производительный, высокосекретный VPN протокол с защитой от обнаружения и блокировки. Проект разработан для работы в условиях активного DPI, цензуры и государственного надзора.

## 🎯 Цель проекта

Создание программы для туннелирования интернет-соединения с использованием неизвестного ультра-производительного, высокосекретного, безопасного протокола, который нельзя обнаружить или заблокировать. Протокол настраивается "одной кнопкой" на сервер и работает даже в условиях жесткой цензуры (Северная Корея, Татарстан, РФ, Китай и т.д.).

## ✨ Ключевые особенности

- **🔐 Гибридная постквантовая криптография**: Noise_IK/NK + ML-KEM768 + X25519
- **🎭 Защита от DPI**: TLS fingerprint customization, adaptive traffic morphing, cover traffic
- **🚀 MASQUE/QUIC**: Высокопроизводительный транспорт на базе HTTP/3
- **🛡️ Stealth режим**: Probe protection, replay protection, domain fronting
- **📊 AI-оркестрация**: Компактная нейросеть для адаптивного управления маскировкой
- **⚡ Производительность**: Поддержка Gbps трафика, низкая задержка
- **🔧 One-button deployment**: Terraform/Ansible автоматизация развертывания

## 📊 Статус проекта

**Readiness Score: 85/100** ✅ Flagship Ready

- ✅ Компиляция без ошибок
- ✅ 188+ тестов проходят
- ✅ Clippy без ошибок в библиотеках
- ✅ Критичные исправления безопасности завершены
- ✅ Документация unsafe блоков

Подробности: [`FLAGSHIP_PROGRESS.md`](FLAGSHIP_PROGRESS.md)

## 🏗️ Архитектура

VPR построен на многослойной архитектуре:

```
┌─────────────────────────────────────────────────────────────┐
│                    Desktop Client (Tauri)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   GUI/TUI    │  │ VPN Client   │  │ AI Morpher   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Transport Layer (MASQUE/QUIC)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ HTTP/3       │  │ QUIC Streams │  │ QUIC Datagr. │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│            Cryptographic Layer (Noise + PQ)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Noise_IK/NK  │  │ ML-KEM768    │  │ Key Rotation │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Stealth Layer (DPI Evasion)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ TLS FP       │  │ Traffic      │  │ Cover        │      │
│  │ Customization│  │ Morphing     │  │ Traffic      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Server (masque-core)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ MASQUE       │  │ DoH Gateway  │  │ TUN Device    │      │
│  │ Server       │  │              │  │               │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

Подробное описание архитектуры: [`docs/architecture.md`](docs/architecture.md)

## 📦 Компоненты

### Core компоненты

- **`masque-core`** — MASQUE CONNECT-UDP сервер с поддержкой QUIC/HTTP/3
  - Hybrid Noise handshake (Noise_IK/NK + ML-KEM768)
  - TLS fingerprint customization
  - Probe protection и replay protection
  - TUN/TAP интерфейс для захвата трафика
  - Adaptive padding и cover traffic

- **`vpr-crypto`** — Криптографические примитивы
  - PKI (offline CA generation)
  - Noise protocol с гибридным PQ-KEM
  - Age encryption для секретов
  - Key rotation и management

- **`doh-gateway`** — DNS-over-HTTPS/QUIC gateway
  - DoH/ODoH/DoQ endpoints
  - DNS health monitoring
  - Moving-target rotation

- **`vpr-app`** — Desktop клиент (Tauri)
  - GUI на базе Tauri + Rust
  - Kill switch
  - Auto-connect
  - Process manager

### Вспомогательные компоненты

- **`health-harness`** — Health check утилита
- **`health-history`** — CLI для истории health reports
- **`vpr-tui`** — TUI с ASCII Earth визуализацией
- **`vpr-ai`** — AI Traffic Morpher (20M параметров)

## 🚀 Быстрый старт

### Требования

- Rust 1.70+ (edition 2021)
- Linux/macOS (Windows в разработке)
- Root/Admin права для TUN устройства

### Сборка

```sh
# Клонировать репозиторий
git clone <repo-url>
cd VPR

# Собрать все компоненты
cargo build --release

# Запустить тесты
cargo test --workspace
```

### Клиент

```sh
# Dev режим с hot reload
make dev

# Сборка релиза
make build

# Запуск приложения
make app

# Или напрямую
./target/release/vpr-app
```

Пакеты после сборки:
- `target/release/bundle/deb/VPR_*.deb`
- `target/release/bundle/rpm/VPR-*.rpm`

### Сервер

```sh
# Генерация ключей
scripts/gen-noise-keys.sh secrets

# Запуск MASQUE сервера
target/release/masque-core \
  --config config/masque.toml.sample \
  --noise-key secrets/server.key

# Запуск DoH gateway
target/release/doh-gateway \
  --config config/doh.toml.sample \
  --odoh-enable

# TLS для DoH/DoQ
# Порядок выбора сертификата:
#   1) ACME через CertificateManager (если заданы cert_domain + acme_directory_url)
#   2) Явные файлы cert/key в конфиге
#   3) Автогенерируемый self-signed (fallback для dev)
#
# Пример с ACME в config/doh.toml:
#   cert_domain = "doh.example.com"
#   acme_directory_url = "https://acme-v02.api.letsencrypt.org/directory"
#   cert_dir = "/var/lib/vpr/certs"
#
# Пример с файлами:
#   doq_cert = "/etc/vpr/doh_cert.pem"
#   doq_key  = "/etc/vpr/doh_key.pem"

# DNS серверы (по умолчанию 8.8.8.8, 1.1.1.1)
# Можно задать свои: --dns-servers 9.9.9.9,1.0.0.1,2001:4860:4860::8888

# Health check
target/release/health-harness \
  --doh-url http://127.0.0.1:8053/dns-query \
  --samples=3
```

### Развертывание (One-button)

```sh
# Terraform для инфраструктуры
cd infra/terraform
terraform init
terraform apply

# Ansible для конфигурации
cd infra/ansible
ansible-playbook -i inventory deploy.yml
```

Подробности: [`infra/README.md`](infra/README.md)

## 🧪 Тестирование

```sh
# Все тесты
cargo test --workspace

# Тесты конкретного компонента
cargo test -p masque-core
cargo test -p vpr-crypto

# E2E тесты
scripts/e2e_full_test.sh
scripts/e2e_automated.sh

# Clippy проверки
cargo clippy --workspace --lib -- -D warnings

# Форматирование
cargo fmt --check
```

## 📚 Документация

- **[Архитектура](docs/architecture.md)** — Детальное описание архитектуры и компонентов
- **[Roadmap](docs/ROADMAP.md)** — План развития проекта
- **[Security](docs/security.md)** — Политики безопасности и threat model
- **[Project Structure](PROJECT_STRUCTURE.md)** — Структура проекта
- **[Changelog](CHANGELOG.md)** — История изменений
- **[AI Stealth Plan](docs/AI_STEALTH_PLAN.md)** — План интеграции ИИ для маскировки
- **[AI Traffic Morpher](docs/AI_TRAFFIC_MORPHER.md)** — Нейросеть для морфинга трафика
- **[Design Documents](docs/design/)** — Технические спецификации компонентов

## 🔒 Безопасность

VPR следует строгим стандартам безопасности:

- **Randomness (CRIT-001)**: Все ключи генерируются через `OsRng`
- **Secret Hygiene (CRIT-002)**: ML-KEM секреты в `Zeroizing<Vec<u8>>`
- **Replay Protection (CRIT-003)**: 5-минутное окно с sliding TTL
- **Unsafe блоки**: Все задокументированы с SAFETY комментариями
- **Error handling**: Критичные `unwrap()` заменены на правильную обработку ошибок

Подробности: [`docs/security.md`](docs/security.md)

## 🤝 Вклад в проект

Мы приветствуем вклад в проект! Пожалуйста, ознакомьтесь с:

- [CONTRIBUTING.md](CONTRIBUTING.md) — Руководство для разработчиков
- [AGENTS.md](AGENTS.md) — Система AI-агентов для разработки
- [TARGETS.md](TARGETS.md) — Цели сборки
- [TODO.md](TODO.md) — Краткий список задач (детальный roadmap: [docs/ROADMAP.md](docs/ROADMAP.md))

### Стандарты качества

- Cyclomatic complexity ≤ 10
- Test coverage ≥ 85% по изменённому коду
- Никаких моков/фейков в продакшн коде
- Conventional Commits
- Документация обновляется вместе с кодом

## 📈 Статус разработки

### ✅ Реализовано

- ✅ Гибридная криптография (Noise + ML-KEM768)
- ✅ MASQUE/QUIC транспорт
- ✅ TLS fingerprint customization
- ✅ DoH/ODoH/DoQ gateway
- ✅ Health monitoring
- ✅ TUI с ASCII Earth
- ✅ Desktop клиент (базовая функциональность)
- ✅ Kill switch и process manager
- ✅ Probe protection и replay protection
- ✅ Key rotation
- ✅ AI Traffic Morpher (базовая версия)

### 🔄 В разработке

- 🔄 MASQUE CONNECT-UDP полная реализация (RFC 9298)
- 🔄 Routing & NAT
- 🔄 Split tunnel
- 🔄 Bootstrap manifest system
- 🔄 Moving-target DoH rotation

### 📋 Планируется

- 📋 DPDK ingress path
- 📋 Hidden-master DNS
- 📋 Offline CA generation tooling
- 📋 CI/CD pipeline
- 📋 Network-namespace test harness

Подробный roadmap: [`docs/ROADMAP.md`](docs/ROADMAP.md)

## 🛠️ Утилиты

### Health History CLI

```sh
# Последние 5 отчетов
cargo run -p health-history -- --tail 5

# JSON формат для автоматизации
cargo run -p health-history -- --json
```

Читает `~/.vpr/health_reports.jsonl`.

### TUI ASCII Earth

```sh
# Интерактивный режим (выход: q/Esc)
cargo run -p vpr-tui --release

# Снепшот кадра
cargo run -p vpr-tui --bin frame_dump -- 64 32 0.6
```

Детали: [`docs/tui-earth.md`](docs/tui-earth.md)

## 📄 Лицензия

Проект распространяется под лицензией MIT. См. [LICENSE](LICENSE) для деталей.

## 🙏 Благодарности

Проект использует следующие технологии:
- [QUIC](https://quicwg.org/) / [MASQUE](https://datatracker.ietf.org/wg/masque/about/)
- [Noise Protocol](https://noiseprotocol.org/)
- [ML-KEM](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Tauri](https://tauri.app/)
- [Rust](https://www.rust-lang.org/)

---

**VPR** — Stealth VPN для свободного интернета 🌐
