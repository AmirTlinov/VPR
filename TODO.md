# TODO - VPR Project Tasks

> **Примечание**: Этот файл содержит краткий список задач. Для детального roadmap см. [`docs/ROADMAP.md`](docs/ROADMAP.md)

**Статус проекта:** ✅ **FLAGSHIP READY (100/100)**  
**Последнее обновление:** 2025-11-25

## ✅ Выполнено (см. FLAGSHIP_PROGRESS.md)

- ✅ Гибридная криптография (Noise + ML-KEM768)
- ✅ MASQUE/QUIC транспорт
- ✅ TLS fingerprint customization
- ✅ DoH/ODoH/DoQ gateway
- ✅ Health monitoring
- ✅ TUI с ASCII Earth
- ✅ Desktop клиент (базовая функциональность)
- ✅ Kill switch и process manager
- ✅ Auto-connect
- ✅ Probe protection и replay protection
- ✅ Key rotation
- ✅ AI Traffic Morpher (базовая версия)
- ✅ Документация проекта
- ✅ CI/CD инфраструктура

## 🔄 В разработке (P0 - Критический путь)

### MASQUE CONNECT-UDP полная реализация
- [x] Полная поддержка всех capsule типов ✅
- [x] UDP forwarding оптимизация ✅
- [x] Context ID management ✅
- [x] Integration тесты ✅

### Routing & NAT
- [x] NAT masquerading на сервере ✅
- [x] Split tunnel поддержка ✅
- [x] Policy-based routing ✅
- [x] IPv6 поддержка ✅

### VPN Client полная интеграция
- [x] Полная интеграция с masque-core ✅
- [x] TUN device управление ✅
- [x] Routing configuration ✅
- [x] DNS configuration ✅

## 📋 Планируется (P1 - Stealth & Security)

### Adaptive Traffic Shaping
- [ ] Интеграция с реальным трафиком
- [ ] Адаптивная настройка параметров
- [ ] Cover traffic оптимизация
- [ ] DPI feedback loop

### Bootstrap Manifest System
- [x] Stego RSS publisher ✅
- [x] RSS интеграция в ManifestClient ✅
- [x] Version management ✅
- [x] Тесты для Stego RSS ✅
- [ ] Автоматическое распространение
- [ ] Rollback механизм

### Moving-target DoH Rotation
- [x] ACME автоматизация ✅
- [x] Certificate Manager ✅
- [x] Интеграция в DoH Gateway ✅
- [x] DNS обновления ✅
- [x] Manifest Rotator ✅
- [x] Canary Rollout ✅
- [x] JWS signing для ACME ✅
- [x] AWS Signature V4 для Route53 ✅
- [x] DNS verification через trust-dns-resolver ✅
- [x] Route53 delete implementation ✅

## 📋 Планируется (P2 - Ops & Infrastructure)

### CI/CD
- [x] GitHub Actions workflow ✅
- [x] Security audit ✅
- [x] Caching ✅
- [ ] Coverage reports (optional)
- [ ] Release automation (optional)

### Packaging
- [ ] Linux packages (deb, rpm, AppImage)
- [ ] macOS package (dmg)
- [ ] Windows package (msi)

### Testing Infrastructure
- [ ] Network-namespace test harness
- [ ] Chaos testing suite
- [ ] DPI lab scripts
- [ ] Property-based testing расширение

### Documentation
- [x] Architecture documentation ✅
- [x] Security policies ✅
- [x] Contributing guide ✅
- [x] User guide для desktop client ✅
- [x] Disaster-recovery workflow ✅
- [x] Compliance checklist ✅

## 📋 Планируется (P3 - Расширенные функции)

### Performance
- [ ] DPDK ingress path (опционально)
- [ ] Multipath QUIC
- [ ] Forward Error Correction (FEC)

### DNS Infrastructure
- [ ] Hidden-master DNS
- [ ] IXFR sync pipeline
- [ ] Offline CA generation tooling
- [ ] Key rotation policy automation

### Advanced Features
- [ ] Split tunnel
- [ ] Self-hosted cover CDN
- [ ] WebRTC fallback
- [ ] Moving-target domain rotation

## Ссылки

- **[ROADMAP.md](docs/ROADMAP.md)** — Детальный план развития с приоритетами и ETA
- **[UX_IMPROVEMENT_ROADMAP.md](docs/UX_IMPROVEMENT_ROADMAP.md)** — План улучшения пользовательского опыта
- **[FLAGSHIP_PROGRESS.md](FLAGSHIP_PROGRESS.md)** — Текущий статус готовности
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Руководство для разработчиков

---

**Примечание:** Этот файл служит кратким справочником. Для полной информации о статусе проекта, приоритетах и планах см. [`docs/ROADMAP.md`](docs/ROADMAP.md).
