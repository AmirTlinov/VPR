# VPR User Guide

Руководство пользователя для VPR - Stealth VPN.

## Установка

### Linux

```bash
# Debian/Ubuntu
sudo dpkg -i VPR_*.deb

# Fedora/RHEL
sudo rpm -i VPR-*.rpm

# Из исходников
cargo build --release
sudo cp target/release/vpr-app /usr/local/bin/
```

### Требования

- Linux kernel 4.19+ (для TUN)
- Root права для создания TUN устройства
- Rust 1.70+ (для сборки из исходников)

## Быстрый старт

### 1. Генерация ключей

```bash
./scripts/gen-noise-keys.sh ~/.vpr/keys
```

### 2. Конфигурация

Создайте `~/.vpr/config.yaml`:

```yaml
server:
  address: "vpn.example.com:443"
  noise_public_key: "base64_encoded_key"

routing:
  policy: full  # full, split, bypass
  dns_servers:
    - "1.1.1.1"
    - "8.8.8.8"

security:
  kill_switch: true
  auto_connect: false
```

### 3. Подключение

```bash
# GUI
vpr-app

# CLI
sudo vpn-client --config ~/.vpr/config.yaml
```

## Режимы работы

### Full Tunnel
Весь трафик через VPN. Максимальная приватность.

### Split Tunnel
Только указанные сети через VPN:
```yaml
routing:
  policy: split
  routes:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
```

### Bypass
VPN не используется (для тестирования).

## Kill Switch

Блокирует весь трафик при разрыве VPN:
```yaml
security:
  kill_switch: true
```

## Troubleshooting

### Ошибка "Permission denied"
```bash
sudo vpr-app
```

### Не удается подключиться
1. Проверьте интернет
2. Проверьте адрес сервера
3. Проверьте ключи

### Медленное соединение
1. Используйте Split Tunnel
2. Попробуйте другой сервер

## Логи

```bash
# Просмотр логов
tail -f ~/.vpr/logs/vpr.log

# Health reports
cat ~/.vpr/health_reports.jsonl
```
