# VPR Disaster Recovery

Процедуры восстановления при инцидентах.

## Сценарии

### 1. Массовая блокировка серверов

**Признаки:** Клиенты не могут подключиться, высокий suspicion score.

**Действия:**
```bash
# 1. Активировать резервные серверы
./scripts/activate_backup.sh

# 2. Обновить manifest
./scripts/update_manifest.sh --emergency

# 3. Развернуть новые серверы
cd infra/terraform && terraform apply -var="region=eu-west-2"
```

### 2. Компрометация ключей

**Действия:**
```bash
# 1. Отозвать ключи
./scripts/revoke_keys.sh --key-id <ID>

# 2. Генерировать новые
./scripts/gen-noise-keys.sh secrets/new

# 3. Обновить manifest
./scripts/publish_manifest.sh --new-keys
```

### 3. DPI обнаружение

**Действия:**
```bash
# 1. Ротация TLS fingerprints
./scripts/rotate_tls_fp.sh

# 2. Увеличить cover traffic
./scripts/adjust_cover.sh --rate 0.5

# 3. Обновить параметры морфинга
./scripts/update_morphing.sh --aggressive
```

### 4. Отказ инфраструктуры

**Действия:**
```bash
# 1. Диагностика
./scripts/check_servers.sh

# 2. Failover
./scripts/failover.sh --to-region us-west-1

# 3. Восстановление
ansible-playbook -i inventory restart.yml
```

## Контакты

- On-call: Telegram @vpr_oncall
- Status: https://status.vpr.example

## Чеклист готовности

- [ ] Резервные серверы развернуты
- [ ] Backup ключи сгенерированы
- [ ] Emergency manifest готов
- [ ] Скрипты протестированы
