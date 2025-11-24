# VPR GUI Application

Профессиональный GUI клиент для VPR VPN с полной интеграцией.

## Возможности

- ✅ **VPN Process Manager** - профессиональное управление процессом vpn-client
- ✅ **Kill Switch** - блокировка всего трафика при отключении VPN (Linux/macOS/Windows)
- ✅ **Auto-connect** - автоматическое подключение при старте
- ✅ **Statistics** - статистика трафика в реальном времени
- ✅ **State Management** - персистентное состояние и восстановление
- ✅ **Error Handling** - полная обработка ошибок без panic
- ✅ **Signal Handling** - graceful shutdown с SIGTERM/SIGINT

## Требования

- Rust 1.70+
- Tauri 2.0+
- VPN клиент бинарник (`vpn-client`) должен быть доступен в PATH или в `target/debug`/`target/release`

## Сборка

```bash
# Сборка VPN клиента
cargo build --bin vpn-client --release

# Сборка GUI приложения
cd src/vpr-app
cargo tauri build
```

## Использование

1. Настройте сервер в GUI
2. Выберите опции (kill switch, auto-connect, DNS protection)
3. Нажмите Connect

## Архитектура

- `process_manager.rs` - управление жизненным циклом VPN процесса
- `killswitch.rs` - реализация kill switch для всех платформ
- `main.rs` - Tauri приложение с IPC коммуникацией

## Безопасность

- Kill switch блокирует весь трафик при неожиданном отключении
- DNS leak protection через VPN DNS серверы
- Graceful shutdown предотвращает утечки трафика
- Полная обработка ошибок без паник
