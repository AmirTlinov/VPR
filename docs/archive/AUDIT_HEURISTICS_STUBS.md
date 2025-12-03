# Аудит эвристик, заглушек, моков и неполных реализаций

Дата: 2025-01-27
Статус: Полный аудит проекта VPR

## Категории проблем

### 🔴 Критические (продакшн код)

#### 1. TODO в продакшн коде

**`src/masque-core/src/bootstrap.rs:211`**
```rust
// TODO: Implement ODoH protocol
// For now, treat as regular HTTPS endpoint
```
**Проблема**: ODoH протокол не реализован, используется обычный HTTPS как заглушка.
**Приоритет**: Высокий (влияет на stealth capabilities)

**`src/masque-core/src/h3_server.rs:304`**
```rust
// TODO: Replace with public API when available in h3/h3-quinn
// Tracking: https://github.com/hyperium/h3/issues/XXX
```
**Проблема**: Используется unsafe код для доступа к приватным полям RequestStream.
**Приоритет**: Критический (unsafe код, может сломаться при обновлении зависимостей)

#### 2. Упрощенные реализации (simplified/for now)

**`src/masque-core/src/stego_rss.rs:138-142`**
```rust
/// Compress data (for now just return bytes, in production use zstd)
fn compress(&self, data: &str) -> Result<Vec<u8>> {
    // For now, just return bytes directly
    // In production, could use zstd compression for better capacity
    Ok(data.as_bytes().to_vec())
}
```
**Проблема**: Компрессия не реализована, данные передаются без сжатия.
**Приоритет**: Средний (влияет на capacity RSS feed)

**`src/masque-core/src/stego_rss.rs:146-149`**
```rust
fn decompress(&self, data: &[u8]) -> Result<String> {
    // For now, just convert bytes to string
    String::from_utf8(data.to_vec())
```
**Проблема**: Соответствует compress - нет реальной декомпрессии.

**`src/masque-core/src/stego_rss.rs:540`**
```rust
// Extract permutation seed from item order
// This is simplified - in practice would need to know original order
```
**Проблема**: Ordering-based steganography упрощена, не использует реальный порядок для декодирования.
**Приоритет**: Средний (влияет на надежность декодирования)

**`src/masque-core/src/stego_rss.rs:568-570`**
```rust
// Parse timestamp and extract LSB
// Simplified: extract byte from timestamp
if let Ok(timestamp) = item.pub_date.parse::<u64>() {
    // Extract encoded byte (simplified)
    let byte = (timestamp & 0xFF) as u8;
```
**Проблема**: Timestamp-based steganography упрощена, не соответствует encode_timestamp логике.
**Приоритет**: Средний

**`src/masque-core/src/stego_rss.rs:602-604`**
```rust
/// Parse RSS items from XML (simplified parser)
fn parse_rss_items(&self, rss_xml: &str) -> Result<Vec<RssItem>> {
    // Simplified RSS parser - in production use proper XML parser
```
**Проблема**: Используется упрощенный парсер RSS вместо полноценного XML парсера.
**Приоритет**: Средний (может не обрабатывать сложные RSS форматы)

**`src/masque-core/src/stego_rss.rs:640`**
```rust
/// Extract content from XML tag (simplified)
```
**Проблема**: Упрощенная функция извлечения XML контента.

**`src/masque-core/src/dns_updater.rs:315`**
```rust
// For now, we'll use a simplified approach that works with proper credentials
// Full implementation would use aws-sigv4 crate properly
```
**Проблема**: AWS Signature V4 реализован вручную упрощенно вместо использования aws-sigv4.
**Приоритет**: Средний (может быть несовместим с некоторыми AWS сервисами)

**`src/masque-core/src/tls_fingerprint.rs:472`**
```rust
/// Simplified JA4 fingerprint (client)
```
**Проблема**: JA4 fingerprint упрощен, может не соответствовать полной спецификации.
**Приоритет**: Низкий (если работает для базовых случаев)

#### 3. Workaround решения

**`src/masque-core/src/cert_manager.rs:368`**
```rust
// Since rcgen 0.13 doesn't directly support CSR with existing keys,
// we'll use a workaround: create a certificate and use its structure
```
**Проблема**: Используется workaround для генерации CSR из-за ограничений rcgen 0.13.
**Приоритет**: Средний (документировано, но не идеально)

**`src/masque-core/src/h3_server.rs:546`**
```rust
// This is a workaround since we cannot write to RequestStream/BidiStream directly
```
**Проблема**: Workaround для отправки данных через RequestStream.
**Приоритет**: Высокий (связано с unsafe кодом выше)

#### 4. Placeholder реализации

**`src/masque-core/src/transport.rs:264`**
```rust
/// WebRTC transport placeholder
///
/// NOTE: Full WebRTC implementation requires webrtc crate.
/// This provides the interface and configuration structure.
```
**Проблема**: WebRTC transport - только заглушка, не реализован.
**Приоритет**: Низкий (если не используется)

**`src/masque-core/src/transport.rs:313`**
```rust
// Placeholder - real implementation needs:
// 1. Create RTCPeerConnection
// 2. Create DataChannel
// 3. Generate offer SDP
// 4. Exchange SDP via signaling server
// 5. Gather ICE candidates
// 6. Establish connection
```
**Проблема**: WebRTC connect() не реализован.

**`src/masque-core/src/transport.rs:399`**
```rust
// Placeholder - real implementation needs:
```
**Проблема**: WebSocket transport также placeholder.

### 🟡 Средние (тесты и временные решения)

#### 5. Игнорируемые тесты

**`src/masque-core/tests/routing_nat_integration.rs`**
- 10 тестов помечены `#[ignore]` с комментарием "Requires root or network namespace"
- **Проблема**: Тесты требуют root привилегий, не запускаются автоматически.
- **Приоритет**: Низкий (это нормально для интеграционных тестов, требующих привилегий)

#### 6. Mock/Fake в тестах (нормально)

**`src/masque-core/tests/acme_cert_dns_integration.rs:116-117`**
```rust
// Test DNS-01 challenge calculation with a mock challenge
// Create a mock challenge with a token
```
**Статус**: ✅ Нормально - это unit тест с мок-данными

**`src/masque-core/tests/acme_cert_dns_integration.rs:241`**
```rust
// Using dummy credentials since we're only testing verify_txt_record
let updater = CloudflareUpdater::new("dummy-token".to_string(), None)?;
```
**Статус**: ✅ Нормально - тест не делает реальных API вызовов

**`src/vpr-ai/src/e2e_test.rs:217`**
```rust
// Create a fake packet for the morpher
```
**Статус**: ✅ Нормально - тестовые данные

**`src/masque-core/src/hybrid_handshake.rs:434-435`**
```rust
// Create a fake "handshake message" to replay
let fake_msg = b"fake handshake message for replay test";
```
**Статус**: ✅ Нормально - тест replay protection

#### 7. Проблемные unwrap/expect/panic в продакшн коде

**`src/masque-core/src/acme_client.rs:62`**
```rust
panic!("failed to clone ACME account keypair - this indicates corrupted key state")
```
**Проблема**: panic в продакшн коде при ошибке клонирования ключа.
**Приоритет**: Высокий (должно возвращать Result)

**`src/masque-core/src/acme_client.rs:122`**
```rust
panic!("Failed to generate ACME account key: {}. This indicates a critical system failure (RNG unavailable).", e)
```
**Проблема**: panic при недоступности RNG.
**Приоритет**: Критический (должно обрабатываться gracefully)

**`src/masque-core/src/replay_protection.rs`**
- Множественные `.expect("replay protection cache lock poisoned")`
- **Проблема**: Если lock отравлен, приложение паникует.
- **Приоритет**: Средний (lock poisoning - редкая ситуация, но должна обрабатываться)

**`src/masque-core/src/cert_manager.rs:479`**
```rust
let temp_dir = TempDir::new().expect("failed to create temp dir");
```
**Проблема**: expect в тесте (нормально), но если это продакшн код - проблема.

**`src/masque-core/src/manifest_rotator.rs:371`**
```rust
let temp_dir = TempDir::new().expect("failed to create temp dir");
```
**Проблема**: Аналогично - проверить контекст.

#### 8. Временные решения (for now)

**`src/masque-core/src/bin/vpn_client.rs:808`**
```rust
// For now, we'll create it but not use suspicion tracking on client side
```
**Проблема**: Suspicion tracking не используется на клиенте.
**Приоритет**: Низкий (если не критично для функциональности)

**`src/masque-core/src/bin/vpn_server.rs:451`**
```rust
// For now, we'll update DPI feedback manually from suspicion score in connection handlers
```
**Проблема**: DPI feedback обновляется вручную, не автоматически.
**Приоритет**: Средний

**`src/masque-core/src/tun.rs:844`**
```rust
// For now, we use source-based routing
```
**Проблема**: Используется source-based routing, возможно нужна более сложная логика.
**Приоритет**: Низкий (если работает)

**`src/masque-core/src/transport.rs:192`**
```rust
// For now, simulate connection attempt
```
**Проблема**: Симуляция подключения вместо реального.
**Приоритет**: Средний (если это не продакшн код)

**`src/vpr-crypto/src/manifest.rs:227`**
```rust
// For now, only exact version match is supported
```
**Проблема**: Только точное совпадение версий, нет миграций.
**Приоритет**: Низкий (если версии стабильны)

**`src/vpr-crypto/src/manifest.rs:259`**
```rust
// For now, only version 1 is supported, so migration is identity
```
**Проблема**: Только версия 1, миграция - identity функция.

### 🟢 Низкие (комментарии, документация)

#### 9. Комментарии про упрощения (документация)

**`src/masque-core/src/cert_manager.rs:232`**
```rust
// Note: In production, implement proper polling with exponential backoff
```
**Статус**: ✅ Документация, не критично

**`src/masque-core/src/cert_manager.rs:384`**
```rust
/// **Implementation Note**: rcgen 0.13 doesn't directly support CSR generation
```
**Статус**: ✅ Документированное ограничение

## Резюме по приоритетам

### Критические (требуют немедленного исправления):
1. ✅ **h3_server.rs:304** - unsafe код с TODO, может сломаться
2. ✅ **acme_client.rs:122** - panic при недоступности RNG
3. ✅ **acme_client.rs:62** - panic при ошибке клонирования ключа

### Высокие (влияют на функциональность):
1. ✅ **bootstrap.rs:211** - ODoH не реализован
2. ✅ **h3_server.rs:546** - workaround для RequestStream
3. ✅ **replay_protection.rs** - множественные expect на lock poisoning

### Средние (улучшают качество):
1. ✅ **stego_rss.rs** - упрощенные compress/decompress, RSS parser, ordering/timestamp decoding
2. ✅ **dns_updater.rs:315** - упрощенная AWS Signature V4
3. ✅ **cert_manager.rs:368** - workaround для CSR generation
4. ✅ **vpn_server.rs:451** - ручное обновление DPI feedback

### Низкие (можно отложить):
1. ✅ **transport.rs** - WebRTC/WebSocket placeholders (если не используются)
2. ✅ **tls_fingerprint.rs:472** - упрощенный JA4
3. ✅ **routing_nat_integration.rs** - игнорируемые тесты (нормально для root-тестов)

## Рекомендации

1. **Немедленно**: Исправить критические panic и unsafe код
2. **В ближайшее время**: Реализовать ODoH протокол, улучшить h3_server workaround
3. **Постепенно**: Заменить упрощенные реализации на полноценные (compress, RSS parser, AWS SigV4)
4. **Документировать**: Все workaround должны быть явно задокументированы с причинами
