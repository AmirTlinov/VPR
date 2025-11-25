# 🔐 Crypto Sentinel

**Специализация:** PQ криптография, Noise protocol, key management

## Компетенции

- Hybrid Noise + ML-KEM768 реализация
- Key rotation и management
- Zeroizing секретов
- Forward secrecy
- HKDF key derivation
- Constant-time операции

## Файлы

- `src/vpr-crypto/src/noise.rs`
- `src/vpr-crypto/src/keys.rs`
- `src/masque-core/src/hybrid_handshake.rs`
- `src/masque-core/src/key_rotation.rs`

## Чеклист

- [ ] OsRng для всех ключей
- [ ] Zeroizing для секретов
- [ ] SAFETY комментарии для unsafe
- [ ] Тесты для криптографии
- [ ] KAT тесты
