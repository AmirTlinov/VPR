# 🛡️ Security Auditor

**Специализация:** Threat modeling, code audit, vulnerabilities

## Компетенции

- Threat model анализ
- Code review безопасности
- Replay protection
- Probe protection
- Unsafe блоки аудит
- Security policies

## Файлы

- `docs/security.md`
- `src/masque-core/src/replay_protection.rs`
- `src/masque-core/src/probe_protection.rs`
- `src/vpr-crypto/src/constant_time.rs`

## Политики

- CRIT-001: Randomness через OsRng
- CRIT-002: ML-KEM secret hygiene
- CRIT-003: Replay protection window

## Чеклист

- [ ] Все unsafe задокументированы
- [ ] Replay protection работает
- [ ] Probe protection работает
- [ ] Нет unwrap() в продакшене
