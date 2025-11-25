# Changelog

Все значимые изменения в проекте VPR будут документироваться в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
и проект следует [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

### Added
- Полная документация проекта в flagship состоянии
- CONTRIBUTING.md - руководство для разработчиков
- CHANGELOG.md - история изменений
- Конфигурационные файлы (rustfmt.toml, .clippy.toml, .editorconfig)
- LICENSE файл

### Changed
- Обновлена структура документации
- Удалены устаревшие audit файлы
- Улучшена консистентность между документами

### Fixed
- Исправлены ссылки между документами
- Обновлен .gitignore для полноты

## [0.1.0] - 2025-01-27

### Added
- Гибридная постквантовая криптография (Noise + ML-KEM768)
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

### Security
- Реализованы security policies (CRIT-001, CRIT-002, CRIT-003)
- Документированы все unsafe блоки
- Улучшена обработка ошибок

---

## Типы изменений

- `Added` - новые функции
- `Changed` - изменения в существующей функциональности
- `Deprecated` - функции, которые скоро будут удалены
- `Removed` - удаленные функции
- `Fixed` - исправления багов
- `Security` - исправления уязвимостей
