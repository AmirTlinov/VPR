# VPR Architecture

> Полное описание архитектуры VPR — Stealth VPN Tunnel

## Содержание

1. [Обзор](#обзор)
2. [Threat Model](#threat-model)
3. [Архитектурные слои](#архитектурные-слои)
4. [Компоненты](#компоненты)
5. [Протоколы](#протоколы)
6. [Безопасность](#безопасность)
7. [Производительность](#производительность)
8. [Развертывание](#развертывание)

## Обзор

VPR — многослойная архитектура для создания необнаруживаемого VPN туннеля, способного работать в условиях активного DPI, цензуры и государственного надзора.

### Ключевые принципы

- **Stealth-first**: Все компоненты проектируются с учетом необходимости обхода DPI
- **Post-quantum ready**: Гибридная криптография (ML-KEM768 + X25519)
- **High performance**: Поддержка Gbps трафика с минимальной задержкой
- **One-button deployment**: Автоматизация развертывания через Terraform/Ansible
- **Zero-trust**: Полная проверка цепочек доверия, оффлайн root CA

### Архитектурная диаграмма

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ vpr-app      │  │ vpr-tui      │  │ vpr-ai       │      │
│  │ (Tauri GUI)  │  │ (ASCII Earth)│  │ (Morpher)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Transport Layer (MASQUE/QUIC)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ HTTP/3       │  │ QUIC Streams │  │ QUIC Datagr. │      │
│  │ (h3-quinn)   │  │              │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│            Cryptographic Layer (Noise + PQ)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Noise_IK/NK  │  │ ML-KEM768    │  │ Key Rotation │      │
│  │ Handshake    │  │ Hybrid KEM   │  │ (≤60s/1GB)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Stealth Layer (DPI Evasion)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ TLS FP       │  │ Traffic      │  │ Cover        │      │
│  │ Customization│  │ Morphing     │  │ Traffic      │      │
│  │ (JA3/JA4)    │  │ (AI-driven)  │  │ Generator    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Server Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ masque-core  │  │ doh-gateway  │  │ TUN Device   │      │
│  │ (MASQUE)     │  │ (DoH/DoQ)    │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Threat Model

### Адверсарии

VPR разработан для противодействия следующим угрозам:

1. **State-level DPI**: AI-driven deep packet inspection с TLS/JA3 fingerprinting
2. **Active probing**: dMAP-style активные зонды для идентификации VPN
3. **Traffic correlation**: Анализ временных паттернов и корреляция трафика
4. **MITM attacks**: Selective MITM на уровне ISP
5. **Protocol blocking**: QUIC/TCP resets, BGP poisoning
6. **Rapid rule updates**: Обновление правил блокировки <5 минут

### Цели защиты

- **Stealth**: JA3/JA4 уникальность <0.2%, suspicion score <0.35
- **Availability**: ≥99.95% session survival за 24ч
- **Performance**: ≥5 Gbps на 25G NIC, <70ms добавленная задержка
- **Bootstrap**: <3 секунды даже за captive portals
- **Recovery**: Failover <15 минут при массовом блоке

### Инварианты безопасности

1. **Randomness (CRIT-001)**: Все ключи через `OsRng`
2. **Secret Hygiene (CRIT-002)**: ML-KEM секреты в `Zeroizing<Vec<u8>>`
3. **Replay Protection (CRIT-003)**: 5-минутное окно с sliding TTL
4. **Trust Chains**: Root CA оффлайн, все артефакты подписаны
5. **Zero-trust**: Проверка всех цепочек доверия

## Архитектурные слои

### 1. Client Layer

**Компоненты:**
- `vpr-app`: Desktop клиент на Tauri
- `vpr-tui`: TUI с ASCII Earth визуализацией
- `vpr-ai`: AI Traffic Morpher (20M параметров)

**Функции:**
- Управление подключением
- Kill switch и process manager
- Auto-connect при старте
- Визуализация статуса и метрик

### 2. Transport Layer

**Протоколы:**
- **HTTP/3**: Базовый транспорт через h3-quinn
- **QUIC Streams**: Надежная доставка для handshake
- **QUIC Datagrams**: UDP туннелирование через MASQUE CONNECT-UDP

**Особенности:**
- ECH (Encrypted Client Hello) для скрытия SNI
- Multipath QUIC для отказоустойчивости
- Adaptive congestion control (SCReAM/BBRv3)

### 3. Cryptographic Layer

**Noise Protocol:**
- **Noise_IK**: Для известных серверов (pre-shared keys)
- **Noise_NK**: Для анонимных серверов
- **Hybrid KEM**: ML-KEM768 + X25519

**Key Management:**
- Session ticket rotation: ≤60 секунд или 1GB
- Forward secrecy через frequent rotation
- Post-quantum готовность через ML-KEM768

**Реализация:** [`src/vpr-crypto/`](../src/vpr-crypto/)

### 4. Stealth Layer

**TLS Fingerprint Customization:**
- Динамическая настройка JA3/JA4 отпечатков
- Поддержка custom TLS профилей
- Автоматическая ротация через `tls-fp-sync`

**Traffic Morphing:**
- AI-driven морфинг трафика (20M параметров)
- Имитация легитимных протоколов (HTTP/3, WebRTC)
- Adaptive padding buckets (32, 64, 256, 1024 bytes)

**Cover Traffic:**
- Генерация cover traffic для маскировки паттернов
- Trace-driven паттерны из реального трафика
- Jittered pacing для естественности

**Probe Protection:**
- Challenge/response с PQ токенами
- Timing obfuscation
- Drop при неудачной проверке зонда

**Replay Protection:**
- 5-минутное sliding window
- SHA-256 хеширование первых 128 байт
- O(1) проверка через HashMap

### 5. Server Layer

**masque-core:**
- MASQUE CONNECT-UDP сервер (RFC 9298)
- TUN/TAP интерфейс для захвата трафика
- Routing и NAT
- Health monitoring

**doh-gateway:**
- DoH/ODoH/DoQ endpoints
- DNS health monitoring
- Moving-target rotation

## Компоненты

### Core компоненты

#### masque-core

**Назначение:** MASQUE CONNECT-UDP сервер с полной поддержкой QUIC/HTTP/3

**Модули:**
- `masque.rs`: CONNECT-UDP обработка (RFC 9298)
- `h3_server.rs`: HTTP/3 сервер
- `hybrid_handshake.rs`: Noise + ML-KEM768 handshake
- `tls_fingerprint.rs`: TLS fingerprint customization
- `probe_protection.rs`: Защита от активных зондов
- `replay_protection.rs`: Защита от replay атак
- `key_rotation.rs`: Ротация ключей
- `tun.rs`: TUN/TAP интерфейс
- `transport.rs`: QUIC транспорт
- `padding.rs`: Adaptive padding
- `cover_traffic.rs`: Генерация cover traffic
- `suspicion.rs`: Расчет suspicion score
- `bootstrap.rs`: Bootstrap manifest система

**Бинарники:**
- `vpn-server`: Основной сервер
- `vpn-client`: VPN клиент
- `masque-h3-client`: MASQUE клиент для тестирования

#### vpr-crypto

**Назначение:** Криптографические примитивы

**Модули:**
- `noise.rs`: Noise protocol реализация
- `keys.rs`: Управление ключами
- `manifest.rs`: Подпись и проверка манифестов
- `seal.rs`: Age encryption для секретов
- `constant_time.rs`: Constant-time операции
- `lib.rs`: Публичный API

**Особенности:**
- Hybrid ML-KEM768 + X25519
- PKI с offline CA generation
- Zeroizing для секретов
- Constant-time операции

#### doh-gateway

**Назначение:** DNS-over-HTTPS/QUIC gateway

**Функции:**
- DoH (DNS-over-HTTPS)
- ODoH (Oblivious DoH)
- DoQ (DNS-over-QUIC)
- DNS health monitoring
- Moving-target rotation

#### vpr-app

**Назначение:** Desktop клиент на Tauri

**Функции:**
- GUI для управления подключением
- Kill switch
- Auto-connect
- Process manager
- Статистика сессии

### Вспомогательные компоненты

#### health-harness

CLI утилита для health checks:
- Проверка suspicion score
- Измерение RTT и jitter
- DNS health проверки

#### health-history

CLI для истории health reports:
- Чтение `~/.vpr/health_reports.jsonl`
- Вывод последних отчетов
- JSON формат для автоматизации

#### vpr-tui

TUI с ASCII Earth визуализацией:
- Интерактивный режим
- Снепшоты кадров
- Визуализация глобального трафика

#### vpr-ai

AI Traffic Morpher:
- 20M параметров нейросеть
- ONNX Runtime интеграция
- Морфинг трафика для обхода DPI

### Routing & NAT система

**Назначение:** Управление маршрутизацией и NAT для VPN туннеля

**Функции:**
- **Split Tunnel**: Выборочная маршрутизация только указанных сетей через VPN
- **Policy-based Routing**: Маршрутизация на основе правил (source-based, fwmark-based)
- **IPv6 поддержка**: Полная поддержка IPv6 маршрутизации и NAT
- **NAT Masquerading**: Улучшенный NAT с поддержкой IPv4/IPv6 и отслеживанием правил

**Компоненты:**
- `RoutingPolicy`: Политика маршрутизации (FullTunnel, SplitTunnel, BypassTunnel)
- `RouteRule`: Правило маршрутизации с поддержкой метрик и custom tables
- `RoutingConfig`: Конфигурация маршрутизации с DNS серверами
- `NatConfig`: Конфигурация NAT masquerading
- `RoutingState`: Состояние для отслеживания и восстановления маршрутов

**Особенности:**
- Автоматическое восстановление маршрутов при отключении
- Поддержка custom routing tables для policy routing
- Проверка существования правил перед добавлением
- IPv6 forwarding и NAT через ip6tables

**Примеры использования:**

**Клиент - Split Tunnel:**
```bash
# Только трафик к 192.168.1.0/24 и 10.0.0.0/8 через VPN
vpn-client --split-tunnel --route 192.168.1.0/24,10.0.0.0/8
```

**Клиент - Policy-based Routing:**
```bash
# Использование policy routing с custom таблицей
vpn-client --policy-routing --route 203.0.113.0/24
```

**Клиент - IPv6 поддержка:**
```bash
# Включить IPv6 маршрутизацию
vpn-client --ipv6
```

**Сервер - Routing Policy:**
```bash
# Отправка split tunnel конфигурации клиентам
vpn-server --routing-policy split --routes 192.168.1.0/24,10.0.0.0/8
```

**Сервер - IPv6 NAT:**
```bash
# Включить IPv6 NAT masquerading
vpn-server --outbound-iface eth0 --ipv6 --ipv6-nat
```

**Конфигурация через YAML:**
```yaml
routing:
  policy: split  # full|split|bypass
  routes:
    - destination: "192.168.1.0/24"
      gateway: "10.9.0.1"
      metric: 0
    - destination: "10.0.0.0/8"
      gateway: "10.9.0.1"
      metric: 100
      table: 100
  dns_servers:
    - "1.1.1.1"
    - "8.8.8.8"
  ipv6_enabled: true
```

## Протоколы

### MASQUE CONNECT-UDP (RFC 9298)

**Протокол:**
1. QUIC connection establishment (TLS 1.3)
2. HTTP/3 Extended CONNECT с `:protocol=connect-udp`
3. Noise handshake внутри туннеля
4. UDP datagrams через QUIC Datagrams

**Формат URI:**
```
/.well-known/masque/udp/{host}/{port}/
```

**Capsule Protocol:**
- Context ID = 0 для raw UDP payload
- Context ID = 1 для handshake capsules

Подробности: [`docs/design/masque-connect-udp.md`](design/masque-connect-udp.md)

### Noise Protocol

**Handshake patterns:**
- **Noise_IK**: Для известных серверов
- **Noise_NK**: Для анонимных серверов

**Hybrid KEM:**
- X25519 (классический)
- ML-KEM768 (post-quantum)
- Concatenated shared secrets

**Session tickets:**
- Sealed с ML-KEM seeds
- 0-RTT resumption
- Rotation ≤60s или 1GB

### TLS Fingerprint Customization

**Поддерживаемые форматы:**
- JA3 (TLS 1.2)
- JA4 (TLS 1.3)

**Custom профили:**
- Загружаются из конфигурации
- Автоматическая ротация через `tls-fp-sync`
- Canary rollout (5% клиентов)

### DNS Protocols

**DoH (DNS-over-HTTPS):**
- RFC 8484
- Стандартный HTTPS транспорт

**ODoH (Oblivious DoH):**
- RFC 9230
- Дополнительная приватность через proxy

**DoQ (DNS-over-QUIC):**
- RFC 9250
- Низкая задержка, встроенное шифрование

## Безопасность

### Криптографические гарантии

1. **Forward Secrecy**: Через frequent key rotation
2. **Post-Quantum Ready**: ML-KEM768 гибрид
3. **Authenticated Encryption**: Noise AEAD
4. **Replay Protection**: 5-минутное окно
5. **Probe Protection**: Challenge/response с PQ токенами

### Trust Chains

**Bootstrap Chain:**
1. Operator root (оффлайн) подписывает manifest
2. Manifest публикуется через ODoH/stego RSS
3. Клиент валидирует подпись и версию
4. Noise handshake только после верификации

**Cryptographic Chain:**
1. Root CA (offline) → Intermediate CA → Service cert
2. Noise использует hybrid ML-KEM768 × X25519
3. Session tickets подписываются derivable ключом
4. Revocation через CRL + новый manifest

**DNS Chain:**
1. Hidden master генерирует зоны с DNSSEC
2. Edge secondaries получают IXFR по WireGuard
3. Клиенты хардкодят DS и root trust anchor
4. Moving-target DoH списки подписаны оператором

### Security Policies

Подробности: [`security.md`](security.md)

- **CRIT-001**: Randomness через OsRng
- **CRIT-002**: ML-KEM secret hygiene
- **CRIT-003**: Replay protection window

## Производительность

### Целевые метрики

- **Throughput**: ≥5 Gbps на 25G NIC
- **Latency**: <70ms добавленная задержка
- **Bootstrap**: <3 секунды
- **CPU**: <70% при полной нагрузке

### Оптимизации

**Server-side:**
- io_uring для асинхронного I/O
- DPDK ingress (опционально)
- NUMA pinning
- Kernel bypass где возможно

**Client-side:**
- Userspace QUIC (quinn)
- Adaptive congestion control
- Multipath QUIC
- Forward error correction (RaptorQ)

### Режимы работы

**Stealth Core:**
- Resource: 1 узел (≥8 vCPU, 16GB RAM, 1G uplink)
- KPI: suspicion <0.3, JA3 uniq <0.1%, bootstrap <2s
- Focus: Максимальная скрытность

**Performance Edge:**
- Resource: 1 узел с 25G NIC, DPDK
- KPI: ≥8 Gbps goodput, latency <10ms
- Focus: Максимальная производительность

**Portable Edge Node:**
- Resource: miniPC/NUC (4 vCPU, 8GB RAM, 500M uplink)
- KPI: bootstrap <1s, resolver hit >70%
- Focus: Резервный узел для failover

## Развертывание

### One-Button Deployment

**Terraform:**
- Инфраструктура на VPS
- Автоматическая настройка сети
- DNS и сертификаты

**Ansible:**
- Конфигурация сервисов
- Развертывание бинарей
- Health checks

**Nix:**
- Reproducible builds
- Детерминированные образы
- Окружения разработки

Подробности: [`../infra/README.md`](../infra/README.md)

### Bootstrap Process

1. **Discovery**: Клиент получает manifest через ODoH/stego RSS
2. **Primary**: MASQUE CONNECT-UDP over QUIC с ECH
3. **Fallbacks**: 
   - Self-hosted cover CDN
   - WebRTC Snowflake-mode
   - DoH-to-H3 pivot

### Operational Procedures

**Deploy Node:**
- Terraform для инфраструктуры
- Ansible для конфигурации
- Автоматические тесты
- Обновление manifest

**Rotate Fronts:**
- ACME сертификаты
- Обновление DNS
- Публикация manifest
- Canary rollout

**Failover:**
- DNS переключение
- Manifest обновление
- Drain mode для старого узла
- Health monitoring

## Мониторинг и Observability

### Метрики

- **Suspicion score**: Расчет на основе DPI сигналов
- **RTT и jitter**: Измерение задержки
- **Throughput**: Пропускная способность
- **Error rate**: Процент ошибок
- **Replay blocked**: Количество заблокированных replay

### Telemetry

- Structured logging (JSON)
- Tracing events через `tracing`
- Prometheus метрики (локально)
- Health reports в `~/.vpr/health_reports.jsonl`

### Alerting

- Suspicion score >0.35
- Bootstrap latency >3s
- DNS failures >1%
- Replay attacks detected

## Roadmap

Текущий статус и планы развития: [`ROADMAP.md`](ROADMAP.md)

### Реализовано ✅

- Гибридная криптография (Noise + ML-KEM768)
- MASQUE/QUIC транспорт
- TLS fingerprint customization
- DoH/ODoH/DoQ gateway
- Health monitoring
- TUI с ASCII Earth
- Desktop клиент (базовая функциональность)
- Kill switch и process manager
- Probe protection и replay protection
- Key rotation
- AI Traffic Morpher (базовая версия)

### В разработке 🔄

- MASQUE CONNECT-UDP полная реализация
- Routing & NAT
- Split tunnel
- Bootstrap manifest system
- Moving-target DoH rotation

### Планируется 📋

- DPDK ingress path
- Hidden-master DNS
- Offline CA generation tooling
- CI/CD pipeline
- Network-namespace test harness

## Ссылки

- [README](../README.md) — Обзор проекта
- [ROADMAP](ROADMAP.md) — План развития
- [Security](security.md) — Политики безопасности
- [AI Stealth Plan](AI_STEALTH_PLAN.md) — План интеграции ИИ
- [AI Traffic Morpher](AI_TRAFFIC_MORPHER.md) — Нейросеть для морфинга
- [Design Documents](design/) — Технические спецификации
- [FLAGSHIP_PROGRESS](../FLAGSHIP_PROGRESS.md) — Статус готовности
- [CONTRIBUTING](../CONTRIBUTING.md) — Руководство для разработчиков
