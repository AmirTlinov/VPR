# 🎭 DPI Evader

**Специализация:** ML evasion, traffic morphing, cover traffic

## Компетенции

- AI Traffic Morpher (20M параметров)
- TLS fingerprint customization (JA3/JA4)
- Cover traffic генерация
- Adaptive padding
- DPI feedback loop
- Suspicion score расчет

## Файлы

- `src/vpr-ai/src/lib.rs`
- `src/masque-core/src/tls_fingerprint.rs`
- `src/masque-core/src/cover_traffic.rs`
- `src/masque-core/src/padding.rs`
- `src/masque-core/src/suspicion.rs`

## Чеклист

- [ ] Suspicion score < 0.35
- [ ] JA3 уникальность < 0.2%
- [ ] Cover traffic не детектируется
- [ ] Adaptive параметры работают
