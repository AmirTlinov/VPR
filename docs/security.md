# Security Policies (VPR)

> Политики безопасности и threat model для VPR

## Содержание

1. [Threat Model](#threat-model)
2. [Security Policies](#security-policies)
3. [Cryptographic Assurances](#cryptographic-assurances)
4. [Trust Chains](#trust-chains)
5. [Operational Security](#operational-security)
6. [Audit & Compliance](#audit--compliance)

## Threat Model

### Адверсарии

VPR разработан для противодействия следующим угрозам:

1. **State-level DPI**: AI-driven deep packet inspection с TLS/JA3 fingerprinting
2. **Active probing**: dMAP-style активные зонды для идентификации VPN
3. **Traffic correlation**: Анализ временных паттернов и корреляция трафика
4. **MITM attacks**: Selective MITM на уровне ISP
5. **Protocol blocking**: QUIC/TCP resets, BGP poisoning
6. **Rapid rule updates**: Обновление правил блокировки <5 минут
7. **Post-quantum threats**: Защита от будущих квантовых компьютеров

### Цели защиты

- **Confidentiality**: Все данные зашифрованы с forward secrecy
- **Integrity**: Все сообщения аутентифицированы
- **Availability**: ≥99.95% session survival за 24ч
- **Stealth**: JA3/JA4 уникальность <0.2%, suspicion score <0.35
- **Post-quantum ready**: Гибридная криптография с ML-KEM768

### Инварианты безопасности

1. **Randomness (CRIT-001)**: Все ключи генерируются через `OsRng`
2. **Secret Hygiene (CRIT-002)**: ML-KEM секреты в `Zeroizing<Vec<u8>>`
3. **Replay Protection (CRIT-003)**: 5-минутное окно с sliding TTL
4. **Trust Chains**: Root CA оффлайн, все артефакты подписаны
5. **Zero-trust**: Проверка всех цепочек доверия

## Security Policies

### CRIT-001: Randomness

**Требование:** Все генерация ключей и nonces использует криптографически стойкий RNG.

**Реализация:**
- Все ключи генерируются через `rand::rngs::OsRng`
- Используются crate-local helpers:
  - `vpr-crypto::rng::secure_rng`
  - `masque-core::rng::secure_rng`

**Верификация:**
- Unit тесты проверяют использование `OsRng` при генерации ключей
- Тесты проверяют использование `OsRng` при создании session-id

**Запрещено:**
- Seeded RNGs в продакшн коде
- Thread-local RNGs в продакшн коде
- Детерминистические генераторы (кроме тестов)

**Тестирование:**
```bash
cargo test -p vpr-crypto --lib
cargo test -p masque-core --tests replay_integration
```

### CRIT-002: Hybrid ML-KEM Secret Hygiene

**Требование:** ML-KEM приватные ключи должны быть безопасно очищены из памяти.

**Реализация:**
- ML-KEM private key bytes обернуты в `Zeroizing<Vec<u8>>`
- Структура `HybridMlKemSecret` использует `Zeroizing`
- Избегаем долгоживущих библиотечных структур для секретов

**Drop семантика:**
- `HybridKeypair::drop` zeroizes оба секрета:
  - X25519 secret
  - ML-KEM bytes
- За `drop` следует compiler fence для предотвращения elision

**Тестирование:**
- `mlkem_secret_zeroizes` тест подтверждает очистку буфера после explicit drop
- Coverage run обязателен для изменений в этой области

**Пример:**
```rust
impl Drop for HybridKeypair {
    fn drop(&mut self) {
        // Zeroize X25519 secret
        self.x25519_secret.zeroize();
        // Zeroize ML-KEM bytes
        self.mlkem_secret.zeroize();
        // Prevent compiler optimizations
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}
```

### CRIT-003: Replay Protection Window

**Требование:** Защита от replay атак на handshake сообщения.

**Окно защиты:**
- Sliding TTL = 300 секунд (5 минут)
- Используется `std::time::Instant` (monotonic, immune к ≤60s clock drift)

**Ключевание:**
- SHA-256 по первым 128 байтам handshake сообщения
- 16-байтный префикс digest используется как cache key

**Структура данных:**
- `HashMap<16-byte key, expiry>` под `RwLock`
- O(1) ожидаемая insert/check
- Периодическая очистка каждые 60s

**Телеметрия:**
- Tracing события `telemetry.replay` с counters:
  - `blocked`: количество заблокированных replay
  - `processed`: количество обработанных сообщений
- Метрики доступны через `ReplayMetrics`

**Целостность:**
- Сообщения новее TTL принимаются
- Дубликаты в окне отклоняются и считаются
- Истекшие записи удаляются

**Операционные заметки:**
- Избегаем логирования raw packet или handshake содержимого
- Только счетчики эмиттируются для replay событий

**Тестирование:**
```bash
cargo test -p vpr-crypto --lib
cargo test -p masque-core --tests replay_integration
```

Подробности: [`design/replay_protection.md`](design/replay_protection.md)

## Cryptographic Assurances

### Forward Secrecy

**Гарантия:** Компрометация долгосрочных ключей не раскрывает прошлые сессии.

**Механизм:**
- Session keys ротируются каждые ≤60 секунд или 1GB трафика
- Каждая ротация использует новый ephemeral ключ
- Старые ключи немедленно удаляются из памяти

**Реализация:**
- `key_rotation.rs`: Автоматическая ротация session keys
- `HybridKeypair`: Ephemeral ключи для каждой сессии
- `Zeroizing` для безопасной очистки

### Post-Quantum Readiness

**Гарантия:** Защита от будущих квантовых компьютеров.

**Механизм:**
- Гибридная криптография: ML-KEM768 + X25519
- Concatenated shared secrets
- ML-KEM768 обеспечивает post-quantum безопасность
- X25519 обеспечивает классическую безопасность

**Реализация:**
- `hybrid_handshake.rs`: Hybrid KEM key exchange
- `noise.rs`: Noise protocol с ML-KEM768 поддержкой
- NIST PQC стандарт: ML-KEM768 (Kyber-768)

### Authenticated Encryption

**Гарантия:** Все данные зашифрованы и аутентифицированы.

**Механизм:**
- Noise protocol AEAD (ChaCha20Poly1305 или AES-GCM)
- Все сообщения включают authentication tag
- Replay protection через sliding window

**Реализация:**
- `noise.rs`: Noise AEAD encryption
- `replay_protection.rs`: Защита от replay

### Key Management

**Гарантия:** Безопасное управление ключами на всех этапах жизненного цикла.

**Механизм:**
- Root CA остается оффлайн
- Intermediate CA для каждого узла
- Service certs для MASQUE, DoH, WebRTC
- Age encryption для всех секретов

**Реализация:**
- `keys.rs`: Key generation и management
- `manifest.rs`: Подпись и проверка манифестов
- `seal.rs`: Age encryption для секретов

## Trust Chains

### Bootstrap Chain

**Цепочка доверия для bootstrap:**

1. `operator-root` (оффлайн) подписывает bootstrap manifest
2. Manifest публикуется через self-hosted ODoH/DoH и stego RSS
3. Клиент валидирует подпись и сверяет версию
4. Клиент выбирает профиль и получает MASQUE endpoint + trust anchors
5. Noise handshake стартует только после верификации ECH cert + manifest hash

**Защита от MITM:**
- Manifest подписан offline root ключом
- Клиент проверяет подпись перед использованием
- При подмене манифеста клиент откатывается на cached версию

### Cryptographic Chain

**Цепочка доверия для криптографии:**

1. Root CA (offline) → Intermediate CA (per node) → Service cert
2. NoiseIK/NK использует гибрид ML-KEM768 × X25519
3. PQ seeds появляются только на узле, шифруются через `age`
4. Session tickets подписываются ключом, derivable из hybrid secret
5. `tls-fp-sync` подписывает обновлённые fingerprint bundles

**Revocation:**
- Оператор удаляет скомпрометированный intermediate
- Публикует CRL + новый manifest
- Клиенты проверяют CRL при подключении

### DNS Chain

**Цепочка доверия для DNS:**

1. Hidden master генерирует зоны, подписывает DNSSEC (ZSK weekly, KSK monthly)
2. Edge secondaries получают IXFR по WireGuard/Noise-SSH
3. Проверяют подпись перед обслуживанием трафика
4. Клиентские резолверы хардкодят DS и root trust anchor
5. Moving-target DoH списки подписаны оператором

**Защита от отравления:**
- DNSSEC подпись всех зон
- Клиенты проверяют DS записи
- Upstream отравление игнорируется

## Operational Security

### Secret Storage

**Требования:**
- Root CA остается оффлайн
- Все секреты шифруются через `age`
- Резервные копии на зашифрованных токенах
- HSM опционален для personal deployment

**Процедуры:**
- Генерация root CA в air-gapped окружении
- Age encryption для всех артефактов
- Оффлайн хранение root ключей

### Key Rotation

**Политика:**
- Session keys: ≤60 секунд или 1GB
- Intermediate CA: каждые 14 дней (или раньше при инциденте)
- TLS certificates: через ACME автоматически
- Noise seeds: при ротации intermediate CA

**Процедуры:**
- Автоматическая ротация session keys
- Полуавтоматическая ротация intermediate CA через GUI
- Автоматическая ротация TLS certs через ACME

### Logging & Telemetry

**Требования:**
- Не логируем raw packet содержимое
- Не логируем handshake содержимое
- Только счетчики и метрики
- Structured logging (JSON)

**Телеметрия:**
- Suspicion score
- RTT и jitter
- Error rates
- Replay blocked counters

**Приватность:**
- Анонимизация телеметрии
- Локальное хранение метрик
- Prometheus только локально

### Incident Response

**Процедуры при компрометации:**
1. Немедленная ротация compromised ключей
2. Публикация CRL
3. Обновление manifest
4. Уведомление клиентов (если возможно)
5. Анализ инцидента и документирование

**Failover процедуры:**
1. DNS переключение на резервный узел
2. Обновление manifest
3. Drain mode для compromised узла
4. Health monitoring

## Audit & Compliance

### Code Review Requirements

**Требования:**
- Все изменения криптографии требуют review
- Все unsafe блоки должны быть задокументированы
- Все security-critical изменения требуют тестов

**SAFETY комментарии:**
- Все unsafe блоки должны иметь SAFETY комментарий
- Объяснение инвариантов
- Объяснение рисков

### Testing Requirements

**Обязательные тесты:**
- Unit тесты для всех криптографических функций
- Integration тесты для handshake
- Property тесты для криптографических примитивов
- E2E тесты для полного потока

**Coverage:**
- Цель: ≥85% по изменённому коду
- Критичные модули: ≥90%

**Тестирование безопасности:**
```bash
# Все тесты
cargo test --workspace

# Криптографические тесты
cargo test -p vpr-crypto

# Replay protection тесты
cargo test -p masque-core --tests replay_integration

# Handshake тесты
cargo test -p masque-core --tests noise_handshake_integration
```

### Security Audits

**Периодичность:**
- Ежемесячный review unsafe блоков
- Ежеквартальный crypto audit
- Ежегодный external audit (рекомендуется)

**Проверки:**
- Clippy security lints
- `cargo audit` для зависимостей
- Fuzzing критичных путей
- Side-channel анализ PQ кода

### Compliance Checklist

**Криптография:**
- ✅ Все ключи через OsRng
- ✅ ML-KEM секреты в Zeroizing
- ✅ Forward secrecy через rotation
- ✅ Post-quantum готовность

**Секреты:**
- ✅ Root CA оффлайн
- ✅ Age encryption для секретов
- ✅ Безопасная очистка памяти

**Протоколы:**
- ✅ Replay protection
- ✅ Probe protection
- ✅ Authenticated encryption

**Операции:**
- ✅ Structured logging
- ✅ Телеметрия без PII
- ✅ Incident response процедуры

## Unsafe Blocks Documentation

Все unsafe блоки в коде задокументированы с SAFETY комментариями:

### tun.rs:431

**Unsafe:** `libc::geteuid()` системный вызов

**SAFETY:**
- Системный вызов libc, безопасен для использования
- Возвращает эффективный UID процесса
- Не имеет побочных эффектов

### constant_time.rs:176

**Unsafe:** Volatile write для безопасной очистки памяти

**SAFETY:**
- Volatile write предотвращает оптимизацию компилятора
- Используется для zeroizing секретов
- Гарантирует очистку памяти

### h3_server.rs:287

**Unsafe:** Layout transmutation для доступа к SendStream

**SAFETY:**
- Transmutation для доступа к внутренним полям h3-quinn
- Риск: может сломаться при обновлении h3-quinn
- Рекомендуется: upstream PR для улучшения доступа

## References

- [Architecture](architecture.md) — Архитектура проекта
- [ROADMAP](ROADMAP.md) — План развития
- [Replay Protection Design](design/replay_protection.md) — Детали replay protection
- [FLAGSHIP_PROGRESS](../FLAGSHIP_PROGRESS.md) — Статус готовности
- [README](../README.md) — Обзор проекта
- [CONTRIBUTING](../CONTRIBUTING.md) — Руководство для разработчиков
