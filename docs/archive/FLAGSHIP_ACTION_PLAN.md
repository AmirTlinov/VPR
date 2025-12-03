# VPR Flagship Action Plan - Без Эвристик и Моков

**Дата:** 2025-11-24  
**Цель:** Довести проект до 100% flagship состояния  
**Принцип:** Только реальные реализации, никаких заглушек, моков или эвристик

---

## Текущий Статус: 87/100

**Что работает:**
- ✅ Криптография (94/100) - production ready
- ✅ Безопасность (90/100) - все политики соблюдены
- ✅ Документация (90/100) - полная
- ✅ 188+ тестов проходят

**Что требует доработки:**
- ⚠️ 34 clippy warnings в masque-core
- ⚠️ CI/CD неполный (55/100)
- ⚠️ Test coverage 75% (цель 85%)
- ⚠️ Некоторые компоненты требуют завершения

---

## Фаза 1: Code Quality Cleanup (2-3 дня)

### День 1: Исправление Clippy Warnings

**Задача:** Устранить все 34 clippy warnings в masque-core

#### 1.1 Автоматические исправления
```bash
# Применить автоматические фиксы
cargo fix --lib -p masque-core --allow-dirty

# Проверить результат
cargo clippy --workspace --lib -- -D warnings
```

#### 1.2 Ручные исправления

**suspicion.rs - let_and_return pattern:**
```rust
// Было:
let new_bucket = match current_bucket { ... };
new_bucket

// Станет:
match current_bucket { ... }
```

**stego_rss.rs - derivable_impls:**
```rust
// Было:
impl Default for StegoMethod {
    fn default() -> Self {
        StegoMethod::Hybrid
    }
}

// Станет:
#[derive(Default)]
pub enum StegoMethod {
    // ...
    #[default]
    Hybrid,
}
```

**tun.rs - enum_variant_names:**
```rust
// Было:
pub enum RoutingPolicy {
    FullTunnel,
    SplitTunnel,
    BypassTunnel,
}

// Станет:
pub enum RoutingPolicy {
    Full,
    Split,
    Bypass,
}
// И обновить все использования
```

**tun.rs:927 - collapsible_match:**
```rust
// Было:
if let Some(gw) = rule.gateway {
    if let IpAddr::V6(gw_v6) = gw {
        // ...
    }
}

// Станет:
if let Some(IpAddr::V6(gw_v6)) = rule.gateway {
    // ...
}
```


#### 1.3 Dead Code Cleanup

**Удалить неиспользуемые поля или добавить обоснование:**

```rust
// acme_client.rs - AcmeDirectory
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    #[allow(dead_code)] // Будет использоваться для revocation
    pub revoke_cert: String,
}

// dns_updater.rs - HttpApiUpdater
pub struct HttpApiUpdater {
    api_url: String,
    #[allow(dead_code)] // Будет использоваться для auth
    api_key: Option<String>,
}

// stego_rss.rs - decompress
impl StegoRssEncoder {
    #[allow(dead_code)] // Будет использоваться для compressed payloads
    fn decompress(&self, data: &[u8]) -> Result<String> { ... }
}
```

**Проверка:**
```bash
cargo build --workspace 2>&1 | grep "warning:"
# Должно быть 0 warnings
```

---

### День 2: Создание AI-агентов

**Задача:** Создать 9 файлов AI-агентов согласно AGENTS.md

#### 2.1 Структура агента (шаблон)

```markdown
# [Имя Агента]

**Специализация:** [Область]  
**Активация:** `/agents/[имя]`

## Цель

[Описание цели агента]

## Компетенции

- [Компетенция 1]
- [Компетенция 2]
- [Компетенция 3]

## Стандарты качества

- Cyclomatic complexity ≤ 10
- Test coverage ≥ 85%
- Никаких моков/фейков
- Conventional Commits
- Документация вместе с кодом

## Примеры использования

### Пример 1: [Название]
```
[Команда]
```

### Пример 2: [Название]
```
[Команда]
```

## Чеклист проверки

- [ ] Код компилируется без ошибок
- [ ] Все тесты проходят
- [ ] Clippy без warnings
- [ ] Документация обновлена
- [ ] [Специфичные проверки]

## Ссылки

- [Релевантная документация]
```


#### 2.2 Создание файлов агентов

```bash
mkdir -p .claude/commands/agents

# Создать 9 файлов агентов:
# 1. crypto-sentinel.md
# 2. dpi-evader.md
# 3. transport-architect.md
# 4. security-auditor.md
# 5. e2e-enforcer.md
# 6. rust-surgeon.md
# 7. infra-ops.md
# 8. stealth-orchestrator.md
# 9. doc-smith.md
# 10. index.md (индекс всех агентов)
```

**Проверка:**
```bash
ls -la .claude/commands/agents/
# Должно быть 10 файлов
```

---

### День 3: CI/CD Enhancement

**Задача:** Расширить CI/CD pipeline до production-ready состояния

#### 3.1 Добавить Coverage Reporting

**.github/workflows/ci.yml:**
```yaml
coverage:
  name: Code Coverage
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: llvm-tools-preview
    
    - name: Install cargo-llvm-cov
      run: cargo install cargo-llvm-cov
    
    - name: Generate coverage
      run: cargo llvm-cov --workspace --lib --lcov --output-path lcov.info
    
    - name: Upload to codecov
      uses: codecov/codecov-action@v3
      with:
        files: lcov.info
        fail_ci_if_error: true
```

#### 3.2 Добавить Security Audit

```yaml
security:
  name: Security Audit
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
    
    - name: Install cargo-audit
      run: cargo install cargo-audit
    
    - name: Run security audit
      run: cargo audit
```

#### 3.3 Добавить Artifact Caching

```yaml
- name: Cache cargo registry
  uses: actions/cache@v3
  with:
    path: ~/.cargo/registry
    key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}

- name: Cache cargo index
  uses: actions/cache@v3
  with:
    path: ~/.cargo/git
    key: ${{ runner.os }}-cargo-git-${{ hashFiles('**/Cargo.lock') }}

- name: Cache target directory
  uses: actions/cache@v3
  with:
    path: target
    key: ${{ runner.os }}-target-${{ hashFiles('**/Cargo.lock') }}
```


#### 3.4 Интегрировать E2E тесты (manual trigger)

```yaml
e2e:
  name: E2E Tests
  runs-on: ubuntu-latest
  if: github.event_name == 'workflow_dispatch' || contains(github.event.head_commit.message, '[e2e]')
  steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
    
    - name: Build all binaries
      run: cargo build --workspace --release
    
    - name: Run E2E tests
      run: |
        chmod +x scripts/e2e_automated.sh
        ./scripts/e2e_automated.sh
```

**Проверка:**
```bash
# Локально проверить workflow
act -l  # Если установлен act

# Или push и проверить на GitHub
git add .github/workflows/ci.yml
git commit -m "ci: enhance pipeline with coverage, audit, and e2e"
git push
```

---

## Фаза 2: Test Coverage Improvement (3-4 дня)

**Цель:** Довести coverage с 75% до 85%+

### День 4-5: Добавить Unit тесты

#### 4.1 health-harness тесты

**src/health-harness/src/main.rs:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_stats_empty() {
        let stats = latency_stats(&[]);
        assert!(stats.is_none());
    }

    #[test]
    fn test_latency_stats_single() {
        let stats = latency_stats(&[Duration::from_millis(100)]).unwrap();
        assert_eq!(stats.min, Duration::from_millis(100));
        assert_eq!(stats.max, Duration::from_millis(100));
        assert_eq!(stats.avg, Duration::from_millis(100));
    }

    #[test]
    fn test_latency_stats_multiple() {
        let latencies = vec![
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(150),
        ];
        let stats = latency_stats(&latencies).unwrap();
        assert_eq!(stats.min, Duration::from_millis(50));
        assert_eq!(stats.max, Duration::from_millis(150));
        assert_eq!(stats.avg, Duration::from_millis(100));
    }

    #[test]
    fn test_compute_suspicion_low_latency() {
        let score = compute_suspicion(
            Duration::from_millis(10),
            Duration::from_millis(2),
            0, // NOERROR
        );
        assert!(score < 0.3);
    }

    #[test]
    fn test_compute_suspicion_high_latency() {
        let score = compute_suspicion(
            Duration::from_millis(500),
            Duration::from_millis(100),
            0,
        );
        assert!(score > 0.5);
    }

    #[test]
    fn test_compute_suspicion_error_rcode() {
        let score = compute_suspicion(
            Duration::from_millis(50),
            Duration::from_millis(10),
            2, // SERVFAIL
        );
        assert!(score > 0.7);
    }

    #[test]
    fn test_build_query_valid_domain() {
        let query = build_query("example.com", RecordType::A);
        assert!(query.is_ok());
        let msg = query.unwrap();
        assert_eq!(msg.queries().len(), 1);
    }
}
```


#### 4.2 Расширить property-based тесты

**src/masque-core/tests/property_tests.rs:**

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_noise_handshake_random_keys(
        client_seed in any::<[u8; 32]>(),
        server_seed in any::<[u8; 32]>()
    ) {
        // Генерируем ключи из seeds для детерминизма
        let client_keypair = generate_keypair_from_seed(&client_seed);
        let server_keypair = generate_keypair_from_seed(&server_seed);
        
        // Выполняем handshake
        let result = perform_handshake(&client_keypair, &server_keypair);
        
        // Проверяем успешность
        prop_assert!(result.is_ok());
        
        // Проверяем, что shared secrets совпадают
        let (client_secret, server_secret) = result.unwrap();
        prop_assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn test_replay_protection_random_messages(
        message in prop::collection::vec(any::<u8>(), 1..1024)
    ) {
        let protection = ReplayProtection::new(Duration::from_secs(300));
        
        // Первое сообщение должно пройти
        prop_assert!(protection.check_and_record(&message).is_ok());
        
        // Дубликат должен быть заблокирован
        prop_assert!(protection.check_and_record(&message).is_err());
    }

    #[test]
    fn test_tls_fingerprint_valid_config(
        cipher_count in 1usize..20,
        kx_group_count in 1usize..5
    ) {
        // Генерируем валидную конфигурацию
        let config = generate_tls_config(cipher_count, kx_group_count);
        
        // Проверяем, что конфигурация применяется без ошибок
        let result = apply_tls_config(&config);
        prop_assert!(result.is_ok());
    }
}
```

#### 4.3 Добавить edge case тесты

**src/vpr-crypto/tests/edge_cases.rs:**

```rust
#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn test_hybrid_keypair_zero_bytes() {
        // Проверяем, что нулевые байты не принимаются
        let zero_bytes = vec![0u8; 32];
        let result = HybridKeypair::from_bytes(&zero_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_expired() {
        let mut manifest = create_test_manifest();
        manifest.expires_at = SystemTime::now() - Duration::from_secs(3600);
        
        let result = manifest.verify(&signing_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_protection_boundary() {
        let protection = ReplayProtection::new(Duration::from_secs(300));
        let message = b"test";
        
        // Записываем сообщение
        protection.check_and_record(message).unwrap();
        
        // Ждем почти до истечения TTL
        std::thread::sleep(Duration::from_secs(299));
        
        // Должно быть еще заблокировано
        assert!(protection.check_and_record(message).is_err());
        
        // Ждем еще 2 секунды (итого 301)
        std::thread::sleep(Duration::from_secs(2));
        
        // Теперь должно пройти
        assert!(protection.check_and_record(message).is_ok());
    }

    #[test]
    fn test_key_rotation_concurrent() {
        use std::sync::Arc;
        use std::thread;
        
        let manager = Arc::new(KeyRotationManager::new());
        let mut handles = vec![];
        
        // Запускаем 10 потоков, каждый записывает данные
        for _ in 0..10 {
            let mgr = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    mgr.record_bytes(1024);
                }
            });
            handles.push(handle);
        }
        
        // Ждем завершения всех потоков
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Проверяем, что счетчик корректен
        assert_eq!(manager.total_bytes(), 10 * 1000 * 1024);
    }
}
```

**Проверка coverage:**
```bash
cargo llvm-cov --workspace --lib --html
# Открыть target/llvm-cov/html/index.html
# Проверить, что coverage >= 85%
```


---

## Фаза 3: Завершение Критичных Компонентов (5-7 дней)

### День 6-7: MASQUE CONNECT-UDP полная реализация

**Задача:** Завершить полную реализацию RFC 9298

#### 6.1 Реализовать все capsule типы

**src/masque-core/src/masque.rs:**

```rust
// Добавить поддержку всех capsule типов из RFC 9298
pub enum CapsuleType {
    Datagram = 0x00,           // ✅ Уже реализовано
    AddressAssign = 0x01,      // TODO: Реализовать
    AddressRequest = 0x02,     // TODO: Реализовать
    RouteAdvertisement = 0x03, // TODO: Реализовать
    // ... другие типы
}

impl MasqueHandler {
    async fn handle_address_assign(&mut self, capsule: &[u8]) -> Result<()> {
        // Парсим ADDRESS_ASSIGN capsule
        let (ip_version, ip_address, ip_prefix_len) = parse_address_assign(capsule)?;
        
        // Назначаем адрес клиенту
        self.assign_address(ip_version, ip_address, ip_prefix_len).await?;
        
        // Отправляем подтверждение
        self.send_address_assign_response().await?;
        
        Ok(())
    }

    async fn handle_route_advertisement(&mut self, capsule: &[u8]) -> Result<()> {
        // Парсим ROUTE_ADVERTISEMENT capsule
        let routes = parse_route_advertisement(capsule)?;
        
        // Добавляем маршруты
        for route in routes {
            self.add_route(route).await?;
        }
        
        Ok(())
    }
}
```

#### 6.2 Оптимизировать UDP forwarding

**src/masque-core/src/udp_forwarder.rs:**

```rust
use tokio::net::UdpSocket;
use std::collections::HashMap;

pub struct UdpForwarder {
    // Пул сокетов для переиспользования
    socket_pool: HashMap<SocketAddr, Arc<UdpSocket>>,
    // Буферы для zero-copy
    buffer_pool: Vec<Vec<u8>>,
    // Метрики
    metrics: ForwarderMetrics,
}

impl UdpForwarder {
    pub async fn forward_datagram(
        &mut self,
        target: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        // Получаем или создаем сокет
        let socket = self.get_or_create_socket(target).await?;
        
        // Отправляем данные (zero-copy где возможно)
        socket.send_to(data, target).await?;
        
        // Обновляем метрики
        self.metrics.bytes_forwarded += data.len() as u64;
        self.metrics.packets_forwarded += 1;
        
        Ok(())
    }

    async fn get_or_create_socket(&mut self, target: SocketAddr) -> Result<Arc<UdpSocket>> {
        if let Some(socket) = self.socket_pool.get(&target) {
            return Ok(Arc::clone(socket));
        }
        
        // Создаем новый сокет
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(socket);
        self.socket_pool.insert(target, Arc::clone(&socket));
        
        Ok(socket)
    }
}
```

#### 6.3 Context ID management

**src/masque-core/src/context_manager.rs:**

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ContextManager {
    contexts: Arc<RwLock<HashMap<u64, Context>>>,
    next_id: Arc<RwLock<u64>>,
}

#[derive(Clone)]
pub struct Context {
    pub id: u64,
    pub target: SocketAddr,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ContextManager {
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)), // 0 зарезервирован
        }
    }

    pub async fn create_context(&self, target: SocketAddr) -> Result<u64> {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;
        
        let context = Context {
            id,
            target,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        };
        
        let mut contexts = self.contexts.write().await;
        contexts.insert(id, context);
        
        Ok(id)
    }

    pub async fn get_context(&self, id: u64) -> Option<Context> {
        let contexts = self.contexts.read().await;
        contexts.get(&id).cloned()
    }

    pub async fn update_activity(&self, id: u64, bytes: u64, direction: Direction) {
        let mut contexts = self.contexts.write().await;
        if let Some(ctx) = contexts.get_mut(&id) {
            ctx.last_activity = Instant::now();
            match direction {
                Direction::Sent => ctx.bytes_sent += bytes,
                Direction::Received => ctx.bytes_received += bytes,
            }
        }
    }

    pub async fn cleanup_stale(&self, timeout: Duration) {
        let mut contexts = self.contexts.write().await;
        let now = Instant::now();
        contexts.retain(|_, ctx| now.duration_since(ctx.last_activity) < timeout);
    }
}
```


#### 6.4 Integration тесты

**src/masque-core/tests/masque_full_integration.rs:**

```rust
#[tokio::test]
async fn test_masque_full_flow() {
    // Запускаем сервер
    let server = spawn_test_server().await;
    
    // Создаем клиента
    let client = MasqueClient::connect(server.addr()).await.unwrap();
    
    // Выполняем Noise handshake
    client.handshake().await.unwrap();
    
    // Запрашиваем адрес
    let assigned_ip = client.request_address().await.unwrap();
    assert!(assigned_ip.is_ipv4() || assigned_ip.is_ipv6());
    
    // Отправляем UDP datagram
    let target = "8.8.8.8:53".parse().unwrap();
    let dns_query = build_dns_query("example.com");
    client.send_datagram(target, &dns_query).await.unwrap();
    
    // Получаем ответ
    let response = client.recv_datagram().await.unwrap();
    assert!(!response.is_empty());
    
    // Проверяем метрики
    let metrics = client.metrics();
    assert!(metrics.bytes_sent > 0);
    assert!(metrics.bytes_received > 0);
}

#[tokio::test]
async fn test_masque_multiple_contexts() {
    let server = spawn_test_server().await;
    let client = MasqueClient::connect(server.addr()).await.unwrap();
    client.handshake().await.unwrap();
    
    // Создаем несколько контекстов
    let targets = vec![
        "8.8.8.8:53".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
        "9.9.9.9:53".parse().unwrap(),
    ];
    
    let mut contexts = vec![];
    for target in targets {
        let ctx_id = client.create_context(target).await.unwrap();
        contexts.push(ctx_id);
    }
    
    // Отправляем данные через каждый контекст
    for (i, ctx_id) in contexts.iter().enumerate() {
        let data = format!("test data {}", i).into_bytes();
        client.send_with_context(*ctx_id, &data).await.unwrap();
    }
    
    // Проверяем, что все контексты активны
    for ctx_id in contexts {
        let ctx = client.get_context(ctx_id).await.unwrap();
        assert!(ctx.bytes_sent > 0);
    }
}

#[tokio::test]
async fn test_masque_context_cleanup() {
    let server = spawn_test_server().await;
    let client = MasqueClient::connect(server.addr()).await.unwrap();
    
    // Создаем контекст
    let ctx_id = client.create_context("8.8.8.8:53".parse().unwrap()).await.unwrap();
    
    // Ждем timeout
    tokio::time::sleep(Duration::from_secs(301)).await;
    
    // Запускаем cleanup
    client.cleanup_stale_contexts(Duration::from_secs(300)).await;
    
    // Проверяем, что контекст удален
    assert!(client.get_context(ctx_id).await.is_none());
}
```

**Проверка:**
```bash
cargo test -p masque-core --test masque_full_integration
# Все тесты должны пройти
```

---

### День 8-9: Routing & NAT завершение

**Задача:** Завершить реализацию routing и NAT

#### 8.1 Исправить clippy warnings в tun.rs

```rust
// Переименовать enum variants
pub enum RoutingPolicy {
    Full,   // было FullTunnel
    Split,  // было SplitTunnel
    Bypass, // было BypassTunnel
}

// Обновить все использования
impl RoutingPolicy {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "split" => Ok(Self::Split),
            "bypass" => Ok(Self::Bypass),
            _ => Err(anyhow!("Invalid routing policy: {}", s)),
        }
    }
}
```

#### 8.2 Реализовать полный NAT masquerading

**src/masque-core/src/nat.rs:**

```rust
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct NatTable {
    // Маппинг внутренний адрес:порт -> внешний порт
    mappings: Arc<RwLock<HashMap<SocketAddr, u16>>>,
    // Обратный маппинг внешний порт -> внутренний адрес:порт
    reverse: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    // Следующий доступный порт
    next_port: Arc<RwLock<u16>>,
    // Внешний IP адрес
    external_ip: IpAddr,
}

impl NatTable {
    pub fn new(external_ip: IpAddr) -> Self {
        Self {
            mappings: Arc::new(RwLock::new(HashMap::new())),
            reverse: Arc::new(RwLock::new(HashMap::new())),
            next_port: Arc::new(RwLock::new(10000)),
            external_ip,
        }
    }

    pub async fn translate_outbound(&self, internal: SocketAddr) -> Result<SocketAddr> {
        // Проверяем существующий маппинг
        {
            let mappings = self.mappings.read().await;
            if let Some(&external_port) = mappings.get(&internal) {
                return Ok(SocketAddr::new(self.external_ip, external_port));
            }
        }
        
        // Создаем новый маппинг
        let mut next_port = self.next_port.write().await;
        let external_port = *next_port;
        *next_port += 1;
        
        // Сохраняем маппинг
        {
            let mut mappings = self.mappings.write().await;
            mappings.insert(internal, external_port);
        }
        {
            let mut reverse = self.reverse.write().await;
            reverse.insert(external_port, internal);
        }
        
        Ok(SocketAddr::new(self.external_ip, external_port))
    }

    pub async fn translate_inbound(&self, external_port: u16) -> Option<SocketAddr> {
        let reverse = self.reverse.read().await;
        reverse.get(&external_port).copied()
    }

    pub async fn remove_mapping(&self, internal: SocketAddr) {
        let mut mappings = self.mappings.write().await;
        if let Some(external_port) = mappings.remove(&internal) {
            let mut reverse = self.reverse.write().await;
            reverse.remove(&external_port);
        }
    }
}
```


#### 8.3 Реализовать Split Tunnel

**src/masque-core/src/split_tunnel.rs:**

```rust
use ipnetwork::IpNetwork;
use std::collections::HashSet;

pub struct SplitTunnelConfig {
    // Сети, которые идут через VPN
    vpn_routes: HashSet<IpNetwork>,
    // Сети, которые идут напрямую (bypass)
    bypass_routes: HashSet<IpNetwork>,
    // DNS серверы для VPN
    vpn_dns: Vec<IpAddr>,
}

impl SplitTunnelConfig {
    pub fn new() -> Self {
        Self {
            vpn_routes: HashSet::new(),
            bypass_routes: HashSet::new(),
            vpn_dns: vec![],
        }
    }

    pub fn add_vpn_route(&mut self, network: IpNetwork) {
        self.vpn_routes.insert(network);
    }

    pub fn add_bypass_route(&mut self, network: IpNetwork) {
        self.bypass_routes.insert(network);
    }

    pub fn should_tunnel(&self, dest: IpAddr) -> bool {
        // Проверяем bypass routes
        for network in &self.bypass_routes {
            if network.contains(dest) {
                return false;
            }
        }
        
        // Проверяем VPN routes
        for network in &self.vpn_routes {
            if network.contains(dest) {
                return true;
            }
        }
        
        // По умолчанию не туннелируем
        false
    }

    pub fn apply(&self) -> Result<()> {
        // Добавляем маршруты для VPN сетей
        for network in &self.vpn_routes {
            add_route(network, RouteType::Vpn)?;
        }
        
        // Добавляем маршруты для bypass сетей
        for network in &self.bypass_routes {
            add_route(network, RouteType::Direct)?;
        }
        
        Ok(())
    }
}

fn add_route(network: &IpNetwork, route_type: RouteType) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(&[
            "route",
            "add",
            &network.to_string(),
            match route_type {
                RouteType::Vpn => "dev",
                RouteType::Direct => "via",
            },
            match route_type {
                RouteType::Vpn => "tun0",
                RouteType::Direct => "default",
            },
        ])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow!("Failed to add route: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    Ok(())
}
```

#### 8.4 Тесты для Routing & NAT

**src/masque-core/tests/routing_nat_full.rs:**

```rust
#[tokio::test]
async fn test_nat_outbound_translation() {
    let nat = NatTable::new("203.0.113.1".parse().unwrap());
    
    let internal = "10.0.0.5:12345".parse().unwrap();
    let external = nat.translate_outbound(internal).await.unwrap();
    
    assert_eq!(external.ip(), "203.0.113.1".parse::<IpAddr>().unwrap());
    assert!(external.port() >= 10000);
}

#[tokio::test]
async fn test_nat_inbound_translation() {
    let nat = NatTable::new("203.0.113.1".parse().unwrap());
    
    let internal = "10.0.0.5:12345".parse().unwrap();
    let external = nat.translate_outbound(internal).await.unwrap();
    
    // Обратный перевод
    let translated = nat.translate_inbound(external.port()).await.unwrap();
    assert_eq!(translated, internal);
}

#[tokio::test]
async fn test_nat_multiple_clients() {
    let nat = NatTable::new("203.0.113.1".parse().unwrap());
    
    let clients = vec![
        "10.0.0.5:12345".parse().unwrap(),
        "10.0.0.6:12346".parse().unwrap(),
        "10.0.0.7:12347".parse().unwrap(),
    ];
    
    let mut external_ports = HashSet::new();
    for client in clients {
        let external = nat.translate_outbound(client).await.unwrap();
        external_ports.insert(external.port());
    }
    
    // Все порты должны быть уникальными
    assert_eq!(external_ports.len(), 3);
}

#[test]
fn test_split_tunnel_vpn_route() {
    let mut config = SplitTunnelConfig::new();
    config.add_vpn_route("192.168.1.0/24".parse().unwrap());
    
    assert!(config.should_tunnel("192.168.1.5".parse().unwrap()));
    assert!(!config.should_tunnel("8.8.8.8".parse().unwrap()));
}

#[test]
fn test_split_tunnel_bypass_route() {
    let mut config = SplitTunnelConfig::new();
    config.add_vpn_route("0.0.0.0/0".parse().unwrap()); // Все через VPN
    config.add_bypass_route("192.168.0.0/16".parse().unwrap()); // Кроме локальной сети
    
    assert!(!config.should_tunnel("192.168.1.5".parse().unwrap()));
    assert!(config.should_tunnel("8.8.8.8".parse().unwrap()));
}
```

**Проверка:**
```bash
cargo test -p masque-core --test routing_nat_full
```


---

### День 10-12: VPN Client полная интеграция

**Задача:** Завершить интеграцию клиента с masque-core

#### 10.1 Полная интеграция с masque-core

**src/vpr-app/src-tauri/src/vpn_manager.rs:**

```rust
use masque_core::{MasqueClient, RoutingPolicy, SplitTunnelConfig};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct VpnManager {
    client: Arc<RwLock<Option<MasqueClient>>>,
    config: VpnConfig,
    state: Arc<RwLock<VpnState>>,
}

#[derive(Clone)]
pub struct VpnConfig {
    pub server_addr: String,
    pub noise_key: Vec<u8>,
    pub routing_policy: RoutingPolicy,
    pub split_tunnel: Option<SplitTunnelConfig>,
    pub dns_servers: Vec<IpAddr>,
    pub auto_reconnect: bool,
}

#[derive(Clone, Debug)]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected { assigned_ip: IpAddr, uptime: Duration },
    Reconnecting,
    Error(String),
}

impl VpnManager {
    pub fn new(config: VpnConfig) -> Self {
        Self {
            client: Arc::new(RwLock::new(None)),
            config,
            state: Arc::new(RwLock::new(VpnState::Disconnected)),
        }
    }

    pub async fn connect(&self) -> Result<()> {
        // Обновляем состояние
        *self.state.write().await = VpnState::Connecting;
        
        // Создаем клиента
        let client = MasqueClient::connect(&self.config.server_addr).await
            .context("Failed to connect to server")?;
        
        // Выполняем Noise handshake
        client.handshake(&self.config.noise_key).await
            .context("Handshake failed")?;
        
        // Запрашиваем IP адрес
        let assigned_ip = client.request_address().await
            .context("Failed to get IP address")?;
        
        // Настраиваем TUN устройство
        self.setup_tun(&assigned_ip).await?;
        
        // Настраиваем routing
        self.setup_routing().await?;
        
        // Настраиваем DNS
        self.setup_dns().await?;
        
        // Сохраняем клиента
        *self.client.write().await = Some(client);
        
        // Обновляем состояние
        *self.state.write().await = VpnState::Connected {
            assigned_ip,
            uptime: Duration::from_secs(0),
        };
        
        // Запускаем мониторинг
        self.start_monitoring().await;
        
        Ok(())
    }

    async fn setup_tun(&self, ip: &IpAddr) -> Result<()> {
        // Создаем TUN устройство
        let output = tokio::process::Command::new("ip")
            .args(&["tuntap", "add", "dev", "tun0", "mode", "tun"])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to create TUN device"));
        }
        
        // Назначаем IP адрес
        let output = tokio::process::Command::new("ip")
            .args(&["addr", "add", &format!("{}/24", ip), "dev", "tun0"])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to assign IP address"));
        }
        
        // Поднимаем интерфейс
        let output = tokio::process::Command::new("ip")
            .args(&["link", "set", "dev", "tun0", "up"])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to bring up TUN device"));
        }
        
        Ok(())
    }

    async fn setup_routing(&self) -> Result<()> {
        match self.config.routing_policy {
            RoutingPolicy::Full => {
                // Весь трафик через VPN
                self.add_default_route().await?;
            }
            RoutingPolicy::Split => {
                // Только указанные сети через VPN
                if let Some(ref split_config) = self.config.split_tunnel {
                    split_config.apply().await?;
                }
            }
            RoutingPolicy::Bypass => {
                // Ничего не делаем
            }
        }
        
        Ok(())
    }

    async fn add_default_route(&self) -> Result<()> {
        // Сохраняем текущий default route
        let output = tokio::process::Command::new("ip")
            .args(&["route", "show", "default"])
            .output()
            .await?;
        
        let old_route = String::from_utf8_lossy(&output.stdout);
        
        // Добавляем новый default route через VPN
        let output = tokio::process::Command::new("ip")
            .args(&["route", "add", "default", "dev", "tun0"])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to add default route"));
        }
        
        Ok(())
    }

    async fn setup_dns(&self) -> Result<()> {
        // Сохраняем текущий resolv.conf
        tokio::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.backup").await?;
        
        // Записываем новые DNS серверы
        let mut content = String::new();
        for dns in &self.config.dns_servers {
            content.push_str(&format!("nameserver {}\n", dns));
        }
        
        tokio::fs::write("/etc/resolv.conf", content).await?;
        
        Ok(())
    }

    async fn start_monitoring(&self) {
        let state = Arc::clone(&self.state);
        let client = Arc::clone(&self.client);
        
        tokio::spawn(async move {
            let start_time = Instant::now();
            
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                
                // Обновляем uptime
                if let VpnState::Connected { assigned_ip, .. } = &*state.read().await {
                    let uptime = start_time.elapsed();
                    *state.write().await = VpnState::Connected {
                        assigned_ip: *assigned_ip,
                        uptime,
                    };
                }
                
                // Проверяем соединение
                if let Some(ref client) = *client.read().await {
                    if !client.is_connected().await {
                        // Переподключаемся если включен auto_reconnect
                        // ...
                    }
                }
            }
        });
    }

    pub async fn disconnect(&self) -> Result<()> {
        // Останавливаем клиента
        if let Some(client) = self.client.write().await.take() {
            client.disconnect().await?;
        }
        
        // Восстанавливаем routing
        self.restore_routing().await?;
        
        // Восстанавливаем DNS
        self.restore_dns().await?;
        
        // Удаляем TUN устройство
        self.cleanup_tun().await?;
        
        // Обновляем состояние
        *self.state.write().await = VpnState::Disconnected;
        
        Ok(())
    }

    async fn restore_routing(&self) -> Result<()> {
        // Удаляем маршруты через VPN
        let _ = tokio::process::Command::new("ip")
            .args(&["route", "del", "default", "dev", "tun0"])
            .output()
            .await;
        
        Ok(())
    }

    async fn restore_dns(&self) -> Result<()> {
        // Восстанавливаем resolv.conf
        if tokio::fs::metadata("/etc/resolv.conf.backup").await.is_ok() {
            tokio::fs::copy("/etc/resolv.conf.backup", "/etc/resolv.conf").await?;
            tokio::fs::remove_file("/etc/resolv.conf.backup").await?;
        }
        
        Ok(())
    }

    async fn cleanup_tun(&self) -> Result<()> {
        let _ = tokio::process::Command::new("ip")
            .args(&["link", "set", "dev", "tun0", "down"])
            .output()
            .await;
        
        let _ = tokio::process::Command::new("ip")
            .args(&["tuntap", "del", "dev", "tun0", "mode", "tun"])
            .output()
            .await;
        
        Ok(())
    }

    pub async fn get_state(&self) -> VpnState {
        self.state.read().await.clone()
    }

    pub async fn get_metrics(&self) -> Option<VpnMetrics> {
        let client = self.client.read().await;
        client.as_ref().map(|c| c.metrics())
    }
}
```


#### 10.2 Tauri Commands для GUI

**src/vpr-app/src-tauri/src/main.rs:**

```rust
use tauri::State;
use std::sync::Arc;

#[tauri::command]
async fn connect_vpn(
    manager: State<'_, Arc<VpnManager>>,
) -> Result<(), String> {
    manager.connect().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn disconnect_vpn(
    manager: State<'_, Arc<VpnManager>>,
) -> Result<(), String> {
    manager.disconnect().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_vpn_state(
    manager: State<'_, Arc<VpnManager>>,
) -> Result<VpnState, String> {
    Ok(manager.get_state().await)
}

#[tauri::command]
async fn get_vpn_metrics(
    manager: State<'_, Arc<VpnManager>>,
) -> Result<Option<VpnMetrics>, String> {
    Ok(manager.get_metrics().await)
}

fn main() {
    // Загружаем конфигурацию
    let config = load_config().expect("Failed to load config");
    let manager = Arc::new(VpnManager::new(config));
    
    tauri::Builder::default()
        .manage(manager)
        .invoke_handler(tauri::generate_handler![
            connect_vpn,
            disconnect_vpn,
            get_vpn_state,
            get_vpn_metrics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

#### 10.3 Frontend интеграция

**src/vpr-app/frontend/src/App.tsx:**

```typescript
import { invoke } from '@tauri-apps/api/tauri';
import { useState, useEffect } from 'react';

interface VpnState {
  type: 'Disconnected' | 'Connecting' | 'Connected' | 'Reconnecting' | 'Error';
  assigned_ip?: string;
  uptime?: number;
  error?: string;
}

interface VpnMetrics {
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
}

function App() {
  const [state, setState] = useState<VpnState>({ type: 'Disconnected' });
  const [metrics, setMetrics] = useState<VpnMetrics | null>(null);

  useEffect(() => {
    // Обновляем состояние каждую секунду
    const interval = setInterval(async () => {
      try {
        const newState = await invoke<VpnState>('get_vpn_state');
        setState(newState);
        
        if (newState.type === 'Connected') {
          const newMetrics = await invoke<VpnMetrics | null>('get_vpn_metrics');
          setMetrics(newMetrics);
        }
      } catch (error) {
        console.error('Failed to get state:', error);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const handleConnect = async () => {
    try {
      await invoke('connect_vpn');
    } catch (error) {
      console.error('Failed to connect:', error);
    }
  };

  const handleDisconnect = async () => {
    try {
      await invoke('disconnect_vpn');
    } catch (error) {
      console.error('Failed to disconnect:', error);
    }
  };

  return (
    <div className="app">
      <h1>VPR - Stealth VPN</h1>
      
      <div className="status">
        <h2>Status: {state.type}</h2>
        {state.type === 'Connected' && (
          <>
            <p>IP: {state.assigned_ip}</p>
            <p>Uptime: {formatDuration(state.uptime || 0)}</p>
          </>
        )}
        {state.type === 'Error' && (
          <p className="error">{state.error}</p>
        )}
      </div>

      <div className="controls">
        {state.type === 'Disconnected' && (
          <button onClick={handleConnect}>Connect</button>
        )}
        {state.type === 'Connected' && (
          <button onClick={handleDisconnect}>Disconnect</button>
        )}
      </div>

      {metrics && (
        <div className="metrics">
          <h3>Metrics</h3>
          <p>Sent: {formatBytes(metrics.bytes_sent)}</p>
          <p>Received: {formatBytes(metrics.bytes_received)}</p>
          <p>Packets Sent: {metrics.packets_sent}</p>
          <p>Packets Received: {metrics.packets_received}</p>
        </div>
      )}
    </div>
  );
}

function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return `${hours}h ${minutes}m ${secs}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default App;
```

**Проверка:**
```bash
cd src/vpr-app
npm install
npm run tauri dev
# Проверить, что GUI работает и можно подключиться
```


---

## Фаза 4: Stealth & DPI Enhancement (3-4 дня)

### День 13-14: Adaptive Traffic Shaping

**Задача:** Интегрировать AI Traffic Morpher с реальным трафиком

#### 13.1 Интеграция с реальным трафиком

**src/vpr-ai/src/traffic_interceptor.rs:**

```rust
use tokio::sync::mpsc;
use std::sync::Arc;

pub struct TrafficInterceptor {
    morpher: Arc<TrafficMorpher>,
    tx: mpsc::Sender<TrafficSample>,
    rx: mpsc::Receiver<TrafficSample>,
}

#[derive(Clone)]
pub struct TrafficSample {
    pub timestamp: Instant,
    pub size: usize,
    pub direction: Direction,
    pub protocol: Protocol,
    pub features: Vec<f32>,
}

impl TrafficInterceptor {
    pub fn new(morpher: Arc<TrafficMorpher>) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        Self { morpher, tx, rx }
    }

    pub async fn intercept_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // Извлекаем features из пакета
        let features = extract_features(packet)?;
        
        // Создаем sample
        let sample = TrafficSample {
            timestamp: Instant::now(),
            size: packet.len(),
            direction: Direction::Outbound,
            protocol: detect_protocol(packet)?,
            features,
        };
        
        // Отправляем в очередь для обучения
        let _ = self.tx.try_send(sample.clone());
        
        // Применяем морфинг
        let morphed = self.morpher.morph(packet, &sample.features).await?;
        
        Ok(morphed)
    }

    pub async fn start_learning(&mut self) {
        let morpher = Arc::clone(&self.morpher);
        
        tokio::spawn(async move {
            let mut batch = Vec::new();
            
            loop {
                // Собираем batch
                while let Ok(sample) = self.rx.try_recv() {
                    batch.push(sample);
                    if batch.len() >= 32 {
                        break;
                    }
                }
                
                if !batch.is_empty() {
                    // Обучаем модель на batch
                    if let Err(e) = morpher.train_batch(&batch).await {
                        eprintln!("Training error: {}", e);
                    }
                    batch.clear();
                }
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
}

fn extract_features(packet: &[u8]) -> Result<Vec<f32>> {
    let mut features = Vec::with_capacity(128);
    
    // Размер пакета (нормализованный)
    features.push(packet.len() as f32 / 1500.0);
    
    // Энтропия
    features.push(calculate_entropy(packet));
    
    // Байтовое распределение (первые 16 байт)
    for i in 0..16 {
        features.push(packet.get(i).copied().unwrap_or(0) as f32 / 255.0);
    }
    
    // Паттерны (n-граммы)
    for window in packet.windows(2).take(32) {
        let bigram = (window[0] as u16) << 8 | window[1] as u16;
        features.push(bigram as f32 / 65535.0);
    }
    
    // Padding до 128 features
    while features.len() < 128 {
        features.push(0.0);
    }
    
    Ok(features)
}

fn calculate_entropy(data: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f32;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy / 8.0 // Нормализуем к [0, 1]
}
```

#### 13.2 Адаптивная настройка параметров

**src/vpr-ai/src/adaptive_config.rs:**

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AdaptiveConfig {
    params: Arc<RwLock<MorphingParams>>,
    metrics: Arc<RwLock<DpiMetrics>>,
}

#[derive(Clone)]
pub struct MorphingParams {
    pub padding_probability: f32,
    pub delay_mean: Duration,
    pub delay_stddev: Duration,
    pub cover_traffic_rate: f32,
}

#[derive(Clone, Default)]
pub struct DpiMetrics {
    pub suspicion_score: f32,
    pub blocked_count: u64,
    pub success_count: u64,
    pub last_update: Instant,
}

impl AdaptiveConfig {
    pub fn new() -> Self {
        Self {
            params: Arc::new(RwLock::new(MorphingParams::default())),
            metrics: Arc::new(RwLock::new(DpiMetrics::default())),
        }
    }

    pub async fn update_metrics(&self, suspicion: f32, blocked: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.suspicion_score = suspicion;
        if blocked {
            metrics.blocked_count += 1;
        } else {
            metrics.success_count += 1;
        }
        metrics.last_update = Instant::now();
        
        // Адаптируем параметры на основе метрик
        self.adapt_params(&metrics).await;
    }

    async fn adapt_params(&self, metrics: &DpiMetrics) {
        let mut params = self.params.write().await;
        
        // Если suspicion высокий, увеличиваем агрессивность
        if metrics.suspicion_score > 0.7 {
            params.padding_probability = (params.padding_probability * 1.2).min(0.9);
            params.cover_traffic_rate = (params.cover_traffic_rate * 1.3).min(0.5);
            params.delay_mean = params.delay_mean.mul_f32(1.1);
        }
        // Если suspicion низкий, уменьшаем overhead
        else if metrics.suspicion_score < 0.3 {
            params.padding_probability = (params.padding_probability * 0.9).max(0.1);
            params.cover_traffic_rate = (params.cover_traffic_rate * 0.8).max(0.05);
            params.delay_mean = params.delay_mean.mul_f32(0.95);
        }
        
        // Если много блокировок, максимальная агрессивность
        let block_rate = metrics.blocked_count as f32 / 
            (metrics.blocked_count + metrics.success_count).max(1) as f32;
        if block_rate > 0.1 {
            params.padding_probability = 0.9;
            params.cover_traffic_rate = 0.5;
        }
    }

    pub async fn get_params(&self) -> MorphingParams {
        self.params.read().await.clone()
    }
}
```


#### 13.3 DPI Feedback Loop

**src/masque-core/src/dpi_feedback.rs:**

```rust
use tokio::sync::mpsc;
use std::sync::Arc;

pub struct DpiFeedbackLoop {
    adaptive_config: Arc<AdaptiveConfig>,
    health_monitor: Arc<HealthMonitor>,
    tx: mpsc::Sender<FeedbackEvent>,
    rx: mpsc::Receiver<FeedbackEvent>,
}

#[derive(Clone)]
pub enum FeedbackEvent {
    ConnectionBlocked { reason: String },
    HighLatency { latency: Duration },
    SuspicionDetected { score: f32 },
    SuccessfulConnection,
}

impl DpiFeedbackLoop {
    pub fn new(
        adaptive_config: Arc<AdaptiveConfig>,
        health_monitor: Arc<HealthMonitor>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            adaptive_config,
            health_monitor,
            tx,
            rx,
        }
    }

    pub async fn report_event(&self, event: FeedbackEvent) {
        let _ = self.tx.send(event).await;
    }

    pub async fn start(&mut self) {
        loop {
            if let Some(event) = self.rx.recv().await {
                self.process_event(event).await;
            }
        }
    }

    async fn process_event(&self, event: FeedbackEvent) {
        match event {
            FeedbackEvent::ConnectionBlocked { reason } => {
                tracing::warn!("Connection blocked: {}", reason);
                
                // Обновляем метрики
                self.adaptive_config.update_metrics(1.0, true).await;
                
                // Записываем в health report
                self.health_monitor.record_block(&reason).await;
            }
            
            FeedbackEvent::HighLatency { latency } => {
                tracing::warn!("High latency detected: {:?}", latency);
                
                // Вычисляем suspicion на основе latency
                let suspicion = (latency.as_millis() as f32 / 1000.0).min(1.0);
                self.adaptive_config.update_metrics(suspicion, false).await;
            }
            
            FeedbackEvent::SuspicionDetected { score } => {
                tracing::warn!("Suspicion detected: {}", score);
                self.adaptive_config.update_metrics(score, false).await;
            }
            
            FeedbackEvent::SuccessfulConnection => {
                tracing::info!("Successful connection");
                self.adaptive_config.update_metrics(0.0, false).await;
            }
        }
    }
}
```

#### 13.4 Тесты для Adaptive Traffic Shaping

**src/vpr-ai/tests/adaptive_tests.rs:**

```rust
#[tokio::test]
async fn test_feature_extraction() {
    let packet = vec![0x45, 0x00, 0x00, 0x3c]; // IP header start
    let features = extract_features(&packet).unwrap();
    
    assert_eq!(features.len(), 128);
    assert!(features[0] > 0.0); // Size feature
    assert!(features[1] >= 0.0 && features[1] <= 1.0); // Entropy
}

#[tokio::test]
async fn test_adaptive_config_high_suspicion() {
    let config = AdaptiveConfig::new();
    
    // Симулируем высокий suspicion
    config.update_metrics(0.8, false).await;
    
    let params = config.get_params().await;
    assert!(params.padding_probability > 0.5);
    assert!(params.cover_traffic_rate > 0.1);
}

#[tokio::test]
async fn test_adaptive_config_low_suspicion() {
    let config = AdaptiveConfig::new();
    
    // Симулируем низкий suspicion
    config.update_metrics(0.2, false).await;
    
    let params = config.get_params().await;
    assert!(params.padding_probability < 0.5);
}

#[tokio::test]
async fn test_dpi_feedback_loop() {
    let config = Arc::new(AdaptiveConfig::new());
    let monitor = Arc::new(HealthMonitor::new());
    let mut feedback = DpiFeedbackLoop::new(config.clone(), monitor);
    
    // Запускаем loop в фоне
    tokio::spawn(async move {
        feedback.start().await;
    });
    
    // Отправляем события
    feedback.report_event(FeedbackEvent::ConnectionBlocked {
        reason: "DPI detected".to_string(),
    }).await;
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Проверяем, что метрики обновились
    let metrics = config.metrics.read().await;
    assert_eq!(metrics.blocked_count, 1);
}
```

**Проверка:**
```bash
cargo test -p vpr-ai --test adaptive_tests
```

---

### День 15-16: Bootstrap Manifest завершение

**Задача:** Завершить автоматическое распространение и rollback

#### 15.1 Автоматическое распространение

**src/masque-core/src/manifest_publisher.rs:**

```rust
use std::sync::Arc;
use tokio::time::{interval, Duration};

pub struct ManifestPublisher {
    rotator: Arc<ManifestRotator>,
    rss_encoder: Arc<StegoRssEncoder>,
    publish_interval: Duration,
}

impl ManifestPublisher {
    pub fn new(
        rotator: Arc<ManifestRotator>,
        rss_encoder: Arc<StegoRssEncoder>,
        publish_interval: Duration,
    ) -> Self {
        Self {
            rotator,
            rss_encoder,
            publish_interval,
        }
    }

    pub async fn start(&self) {
        let mut ticker = interval(self.publish_interval);
        
        loop {
            ticker.tick().await;
            
            if let Err(e) = self.publish_manifest().await {
                tracing::error!("Failed to publish manifest: {}", e);
            }
        }
    }

    async fn publish_manifest(&self) -> Result<()> {
        // Получаем текущий manifest
        let manifest = self.rotator.get_current_manifest().await?;
        
        // Кодируем в RSS
        let rss_feed = self.rss_encoder.encode(&manifest).await?;
        
        // Публикуем на все endpoints
        self.publish_to_endpoints(&rss_feed).await?;
        
        tracing::info!("Manifest published successfully");
        Ok(())
    }

    async fn publish_to_endpoints(&self, rss_feed: &str) -> Result<()> {
        // Публикуем на HTTP endpoint
        self.publish_http(rss_feed).await?;
        
        // Публикуем через ODoH
        self.publish_odoh(rss_feed).await?;
        
        // Публикуем через DoH
        self.publish_doh(rss_feed).await?;
        
        Ok(())
    }

    async fn publish_http(&self, rss_feed: &str) -> Result<()> {
        // Записываем в файл для HTTP сервера
        tokio::fs::write("/var/www/vpr/feed.xml", rss_feed).await?;
        Ok(())
    }

    async fn publish_odoh(&self, rss_feed: &str) -> Result<()> {
        // Публикуем через ODoH TXT record
        let txt_record = format!("vpr-manifest={}", base64::encode(rss_feed));
        // TODO: Обновить DNS TXT record
        Ok(())
    }

    async fn publish_doh(&self, rss_feed: &str) -> Result<()> {
        // Аналогично ODoH
        Ok(())
    }
}
```


#### 15.2 Rollback механизм

**src/masque-core/src/manifest_rollback.rs:**

```rust
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ManifestRollback {
    history: Arc<RwLock<VecDeque<ManifestSnapshot>>>,
    max_history: usize,
}

#[derive(Clone)]
pub struct ManifestSnapshot {
    pub manifest: Manifest,
    pub timestamp: SystemTime,
    pub version: u64,
    pub reason: String,
}

impl ManifestRollback {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            max_history,
        }
    }

    pub async fn save_snapshot(&self, manifest: Manifest, reason: String) {
        let snapshot = ManifestSnapshot {
            manifest: manifest.clone(),
            timestamp: SystemTime::now(),
            version: manifest.version,
            reason,
        };
        
        let mut history = self.history.write().await;
        history.push_back(snapshot);
        
        // Ограничиваем размер истории
        while history.len() > self.max_history {
            history.pop_front();
        }
    }

    pub async fn rollback_to_version(&self, version: u64) -> Result<Manifest> {
        let history = self.history.read().await;
        
        for snapshot in history.iter().rev() {
            if snapshot.version == version {
                tracing::info!(
                    "Rolling back to version {} ({})",
                    version,
                    snapshot.reason
                );
                return Ok(snapshot.manifest.clone());
            }
        }
        
        Err(anyhow!("Version {} not found in history", version))
    }

    pub async fn rollback_to_previous(&self) -> Result<Manifest> {
        let history = self.history.read().await;
        
        if history.len() < 2 {
            return Err(anyhow!("No previous version available"));
        }
        
        // Берем предпоследний snapshot
        let snapshot = &history[history.len() - 2];
        tracing::info!(
            "Rolling back to previous version {} ({})",
            snapshot.version,
            snapshot.reason
        );
        
        Ok(snapshot.manifest.clone())
    }

    pub async fn get_history(&self) -> Vec<ManifestSnapshot> {
        let history = self.history.read().await;
        history.iter().cloned().collect()
    }
}
```

#### 15.3 Интеграция rollback с rotator

**src/masque-core/src/manifest_rotator.rs (дополнение):**

```rust
impl ManifestRotator {
    pub async fn rotate_with_rollback(
        &self,
        new_manifest: Manifest,
        rollback: &ManifestRollback,
    ) -> Result<()> {
        // Сохраняем текущий manifest в историю
        let current = self.get_current_manifest().await?;
        rollback.save_snapshot(current, "Before rotation".to_string()).await;
        
        // Пытаемся применить новый manifest
        match self.rotate(new_manifest.clone()).await {
            Ok(_) => {
                tracing::info!("Rotation successful");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Rotation failed: {}, rolling back", e);
                
                // Откатываемся к предыдущей версии
                let previous = rollback.rollback_to_previous().await?;
                self.force_set_manifest(previous).await?;
                
                Err(e)
            }
        }
    }

    async fn force_set_manifest(&self, manifest: Manifest) -> Result<()> {
        // Принудительно устанавливаем manifest без проверок
        let mut current = self.current_manifest.write().await;
        *current = Some(manifest);
        Ok(())
    }
}
```

#### 15.4 Тесты для Bootstrap Manifest

**src/masque-core/tests/manifest_full_integration.rs:**

```rust
#[tokio::test]
async fn test_manifest_publish_and_fetch() {
    // Создаем publisher
    let rotator = Arc::new(ManifestRotator::new());
    let encoder = Arc::new(StegoRssEncoder::new(StegoMethod::Hybrid));
    let publisher = ManifestPublisher::new(
        rotator.clone(),
        encoder.clone(),
        Duration::from_secs(60),
    );
    
    // Публикуем manifest
    publisher.publish_manifest().await.unwrap();
    
    // Создаем client и fetching
    let client = ManifestClient::new();
    let fetched = client.fetch().await.unwrap();
    
    // Проверяем, что manifest совпадает
    let original = rotator.get_current_manifest().await.unwrap();
    assert_eq!(fetched.version, original.version);
}

#[tokio::test]
async fn test_manifest_rollback() {
    let rollback = ManifestRollback::new(10);
    
    // Создаем несколько версий
    let v1 = create_test_manifest(1);
    let v2 = create_test_manifest(2);
    let v3 = create_test_manifest(3);
    
    rollback.save_snapshot(v1.clone(), "Initial".to_string()).await;
    rollback.save_snapshot(v2.clone(), "Update 1".to_string()).await;
    rollback.save_snapshot(v3.clone(), "Update 2".to_string()).await;
    
    // Откатываемся к v2
    let rolled_back = rollback.rollback_to_version(2).await.unwrap();
    assert_eq!(rolled_back.version, 2);
    
    // Откатываемся к предыдущей
    let previous = rollback.rollback_to_previous().await.unwrap();
    assert_eq!(previous.version, 2); // Предпоследний
}

#[tokio::test]
async fn test_rotation_with_auto_rollback() {
    let rotator = Arc::new(ManifestRotator::new());
    let rollback = ManifestRollback::new(10);
    
    // Устанавливаем начальный manifest
    let v1 = create_test_manifest(1);
    rotator.force_set_manifest(v1.clone()).await.unwrap();
    
    // Пытаемся применить невалидный manifest
    let invalid = create_invalid_manifest();
    let result = rotator.rotate_with_rollback(invalid, &rollback).await;
    
    // Проверяем, что rotation failed
    assert!(result.is_err());
    
    // Проверяем, что откатились к v1
    let current = rotator.get_current_manifest().await.unwrap();
    assert_eq!(current.version, 1);
}
```

**Проверка:**
```bash
cargo test -p masque-core --test manifest_full_integration
```


---

## Фаза 5: Финальная Полировка (2-3 дня)

### День 17: Документация пользователя

**Задача:** Создать user guide для desktop client

#### 17.1 User Guide

**docs/user-guide.md:**

```markdown
# VPR User Guide

## Установка

### Linux

#### Debian/Ubuntu
```bash
sudo dpkg -i VPR_*.deb
```

#### Fedora/RHEL
```bash
sudo rpm -i VPR-*.rpm
```

#### AppImage
```bash
chmod +x VPR-*.AppImage
./VPR-*.AppImage
```

### macOS
```bash
# Открыть DMG и перетащить в Applications
open VPR-*.dmg
```

### Windows
```bash
# Запустить MSI installer
VPR-*.msi
```

## Первый запуск

1. Запустите VPR
2. Введите адрес сервера (предоставляется администратором)
3. Импортируйте ключ подключения (файл .key)
4. Нажмите "Connect"

## Настройки

### Routing Policy

**Full Tunnel** - весь трафик через VPN
- Максимальная приватность
- Все приложения защищены
- Может быть медленнее

**Split Tunnel** - только указанные сети через VPN
- Оптимальная производительность
- Локальный трафик напрямую
- Настраиваемые правила

**Bypass** - VPN не используется
- Для тестирования
- Временное отключение

### DNS Servers

Рекомендуемые DNS серверы:
- 1.1.1.1 (Cloudflare)
- 8.8.8.8 (Google)
- 9.9.9.9 (Quad9)

### Auto-connect

Включите для автоматического подключения при старте системы.

### Kill Switch

Блокирует весь трафик при разрыве VPN соединения.
Рекомендуется включить для максимальной безопасности.

## Troubleshooting

### Не удается подключиться

1. Проверьте интернет соединение
2. Проверьте адрес сервера
3. Проверьте ключ подключения
4. Проверьте firewall настройки

### Медленное соединение

1. Попробуйте другой сервер
2. Используйте Split Tunnel
3. Проверьте загрузку сети

### Ошибка "Permission denied"

VPR требует root/admin права для создания TUN устройства.

Linux:
```bash
sudo vpr-app
```

macOS:
```bash
sudo /Applications/VPR.app/Contents/MacOS/vpr-app
```

Windows: Запустите от имени администратора

## Безопасность

### Проверка подлинности сервера

VPR использует Noise protocol для аутентификации сервера.
Убедитесь, что ключ получен из надежного источника.

### Защита от утечек

- Kill Switch блокирует трафик при разрыве
- DNS leak protection включен по умолчанию
- IPv6 leak protection включен

### Логи

Логи хранятся в:
- Linux: `~/.local/share/vpr/logs/`
- macOS: `~/Library/Application Support/vpr/logs/`
- Windows: `%APPDATA%\vpr\logs\`

Логи не содержат чувствительной информации.

## FAQ

**Q: Работает ли VPR в Китае/России/Иране?**
A: Да, VPR разработан для обхода DPI и цензуры.

**Q: Какая скорость соединения?**
A: Зависит от сервера и вашего интернета. Обычно 50-100 Mbps.

**Q: Можно ли использовать для торрентов?**
A: Да, но проверьте политику вашего сервера.

**Q: Сколько стоит?**
A: VPR - open source. Стоимость зависит от провайдера сервера.

## Поддержка

- GitHub Issues: https://github.com/your-org/vpr/issues
- Email: support@vpr.example
- Telegram: @vpr_support
```


#### 17.2 Disaster Recovery Workflow

**docs/disaster-recovery.md:**

```markdown
# VPR Disaster Recovery Workflow

## Сценарии

### 1. Массовая блокировка серверов

**Признаки:**
- Клиенты не могут подключиться
- Высокий suspicion score
- Timeout при handshake

**Действия:**

1. **Немедленно** (0-5 минут):
   ```bash
   # Активировать резервные серверы
   ./scripts/activate_backup_servers.sh
   
   # Обновить manifest с новыми серверами
   ./scripts/update_manifest.sh --emergency
   ```

2. **Краткосрочно** (5-30 минут):
   ```bash
   # Развернуть новые серверы в других регионах
   cd infra/terraform
   terraform apply -var="region=eu-west-2"
   
   # Обновить DNS
   ./scripts/update_dns.sh --new-ips
   ```

3. **Среднесрочно** (30 минут - 2 часа):
   ```bash
   # Ротация TLS fingerprints
   ./scripts/rotate_tls_fingerprints.sh
   
   # Обновление domain fronting списка
   ./scripts/update_fronting_domains.sh
   ```

### 2. Компрометация ключей

**Признаки:**
- Подозрительная активность
- Неавторизованные подключения
- Утечка ключей

**Действия:**

1. **Немедленно**:
   ```bash
   # Отозвать скомпрометированные ключи
   ./scripts/revoke_keys.sh --key-id <ID>
   
   # Генерировать новые ключи
   ./scripts/gen-noise-keys.sh secrets/new
   ```

2. **Уведомить клиентов**:
   ```bash
   # Публикация emergency manifest
   ./scripts/publish_emergency_manifest.sh \
     --message "Key rotation required" \
     --new-keys secrets/new
   ```

3. **Ротация всех ключей**:
   ```bash
   # Полная ротация
   ./scripts/full_key_rotation.sh
   ```

### 3. DPI обнаружение протокола

**Признаки:**
- Suspicion score > 0.7
- Селективные блокировки
- Паттерны в логах

**Действия:**

1. **Анализ**:
   ```bash
   # Собрать логи
   ./scripts/collect_dpi_logs.sh
   
   # Анализ паттернов
   ./scripts/analyze_dpi_patterns.sh
   ```

2. **Адаптация**:
   ```bash
   # Обновить TLS fingerprints
   ./scripts/update_tls_profiles.sh --aggressive
   
   # Увеличить cover traffic
   ./scripts/adjust_cover_traffic.sh --rate 0.5
   ```

3. **Тестирование**:
   ```bash
   # Запустить DPI тесты
   ./scripts/e2e_dpi_test.sh
   ```

### 4. Отказ инфраструктуры

**Признаки:**
- Серверы недоступны
- Высокая latency
- Packet loss

**Действия:**

1. **Диагностика**:
   ```bash
   # Проверка health
   ./scripts/check_all_servers.sh
   
   # Проверка сети
   ./scripts/network_diagnostics.sh
   ```

2. **Failover**:
   ```bash
   # Автоматический failover
   ./scripts/auto_failover.sh
   
   # Или ручной
   ./scripts/manual_failover.sh --to-region us-west-1
   ```

3. **Восстановление**:
   ```bash
   # Перезапуск сервисов
   ansible-playbook -i inventory restart_services.yml
   
   # Проверка
   ./scripts/verify_recovery.sh
   ```

## Контакты экстренной связи

- **On-call инженер**: +X-XXX-XXX-XXXX
- **Backup канал**: Signal/Telegram @vpr_emergency
- **Status page**: https://status.vpr.example

## Чеклист готовности

- [ ] Резервные серверы развернуты и протестированы
- [ ] Backup ключи сгенерированы и сохранены
- [ ] Emergency manifest подготовлен
- [ ] Скрипты disaster recovery протестированы
- [ ] Контакты актуальны
- [ ] Runbook доступен offline
```

#### 17.3 Compliance Checklist

**docs/compliance-checklist.md:**

```markdown
# VPR Compliance Checklist

## Криптография

- [ ] Все ключи генерируются через OsRng
- [ ] ML-KEM секреты в Zeroizing<Vec<u8>>
- [ ] Forward secrecy через key rotation (≤60s или 1GB)
- [ ] Post-quantum готовность (ML-KEM768)
- [ ] Noise protocol правильно реализован
- [ ] HKDF для key derivation
- [ ] Constant-time операции где необходимо

## Безопасность

- [ ] Root CA оффлайн
- [ ] Intermediate CA для каждого узла
- [ ] Age encryption для всех секретов
- [ ] Replay protection (5-минутное окно)
- [ ] Probe protection реализован
- [ ] Все unsafe блоки задокументированы
- [ ] SAFETY комментарии присутствуют

## Тестирование

- [ ] Unit тесты ≥85% coverage
- [ ] Integration тесты для критичных путей
- [ ] Property-based тесты
- [ ] E2E тесты
- [ ] Chaos testing
- [ ] DPI resistance тесты

## Код

- [ ] Cyclomatic complexity ≤10
- [ ] Clippy без warnings
- [ ] Форматирование соответствует rustfmt
- [ ] Conventional commits
- [ ] Документация обновлена

## Операции

- [ ] CI/CD pipeline настроен
- [ ] Coverage reporting работает
- [ ] Security audit (cargo audit) проходит
- [ ] Backup серверы развернуты
- [ ] Disaster recovery план протестирован
- [ ] Monitoring настроен
- [ ] Alerting настроен

## Документация

- [ ] Architecture документация актуальна
- [ ] Security policies документированы
- [ ] User guide создан
- [ ] API документация полная
- [ ] Disaster recovery workflow документирован
- [ ] Compliance checklist заполнен

## Deployment

- [ ] Terraform модули протестированы
- [ ] Ansible playbooks работают
- [ ] One-button deployment функционирует
- [ ] Rollback механизм протестирован
- [ ] Health checks настроены

## Подписи

- [ ] Security Lead: _________________ Дата: _______
- [ ] Tech Lead: _________________ Дата: _______
- [ ] DevOps Lead: _________________ Дата: _______
```

**Проверка:**
```bash
# Проверить, что вся документация создана
ls -la docs/
# Должны быть: user-guide.md, disaster-recovery.md, compliance-checklist.md
```


---

### День 18-19: Финальное тестирование

**Задача:** Полное E2E тестирование всех компонентов

#### 18.1 Comprehensive E2E Test Suite

**scripts/e2e_comprehensive.sh:**

```bash
#!/bin/bash
set -euo pipefail

echo "=== VPR Comprehensive E2E Test Suite ==="
echo "Starting at $(date)"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED_TESTS=()
PASSED_TESTS=()

run_test() {
    local test_name=$1
    local test_script=$2
    
    echo -e "\n${YELLOW}Running: $test_name${NC}"
    
    if bash "$test_script"; then
        echo -e "${GREEN}✓ PASSED: $test_name${NC}"
        PASSED_TESTS+=("$test_name")
    else
        echo -e "${RED}✗ FAILED: $test_name${NC}"
        FAILED_TESTS+=("$test_name")
    fi
}

# 1. Компиляция
echo -e "\n${YELLOW}=== Phase 1: Compilation ===${NC}"
run_test "Workspace Build" "cargo build --workspace --release"

# 2. Unit тесты
echo -e "\n${YELLOW}=== Phase 2: Unit Tests ===${NC}"
run_test "vpr-crypto tests" "cargo test -p vpr-crypto --lib"
run_test "masque-core tests" "cargo test -p masque-core --lib"
run_test "doh-gateway tests" "cargo test -p doh-gateway --lib"
run_test "vpr-ai tests" "cargo test -p vpr-ai --lib"

# 3. Integration тесты
echo -e "\n${YELLOW}=== Phase 3: Integration Tests ===${NC}"
run_test "Noise handshake" "cargo test -p masque-core --test noise_handshake_integration"
run_test "Replay protection" "cargo test -p masque-core --test replay_integration"
run_test "MASQUE RFC 9298" "cargo test -p masque-core --test masque_rfc9298"
run_test "Routing & NAT" "cargo test -p masque-core --test routing_nat_integration"
run_test "Stego RSS" "cargo test -p masque-core --test stego_rss_integration"
run_test "Manifest" "cargo test -p masque-core --test manifest_integration"

# 4. Property-based тесты
echo -e "\n${YELLOW}=== Phase 4: Property Tests ===${NC}"
run_test "Property tests" "cargo test -p masque-core --test property_tests"

# 5. E2E тесты
echo -e "\n${YELLOW}=== Phase 5: E2E Tests ===${NC}"
run_test "PKI setup" "./scripts/e2e_pki.sh"
run_test "TUN device" "./scripts/e2e_tun.sh"
run_test "MASQUE flow" "./scripts/e2e_masque.sh"
run_test "VPN tunnel" "./scripts/e2e_vpn_test.sh"
run_test "Key rotation" "./scripts/e2e_rotation.sh"
run_test "Failover" "./scripts/e2e_failover.sh"
run_test "Health harness" "./scripts/e2e_harness.sh"

# 6. Code quality
echo -e "\n${YELLOW}=== Phase 6: Code Quality ===${NC}"
run_test "Clippy" "cargo clippy --workspace --lib -- -D warnings"
run_test "Format check" "cargo fmt --check"
run_test "Security audit" "cargo audit"

# 7. Coverage
echo -e "\n${YELLOW}=== Phase 7: Coverage ===${NC}"
echo "Generating coverage report..."
cargo llvm-cov --workspace --lib --html
COVERAGE=$(cargo llvm-cov --workspace --lib --summary-only | grep "TOTAL" | awk '{print $10}' | tr -d '%')
echo "Coverage: ${COVERAGE}%"

if (( $(echo "$COVERAGE >= 85" | bc -l) )); then
    echo -e "${GREEN}✓ Coverage target met (${COVERAGE}% >= 85%)${NC}"
    PASSED_TESTS+=("Coverage >= 85%")
else
    echo -e "${RED}✗ Coverage below target (${COVERAGE}% < 85%)${NC}"
    FAILED_TESTS+=("Coverage >= 85%")
fi

# 8. Performance тесты
echo -e "\n${YELLOW}=== Phase 8: Performance ===${NC}"
echo "Running performance benchmarks..."
cargo bench --workspace --no-run

# Итоги
echo -e "\n${YELLOW}=== Test Summary ===${NC}"
echo "Passed: ${#PASSED_TESTS[@]}"
echo "Failed: ${#FAILED_TESTS[@]}"

if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo -e "\n${GREEN}✓✓✓ ALL TESTS PASSED ✓✓✓${NC}"
    echo "VPR is FLAGSHIP READY!"
    exit 0
else
    echo -e "\n${RED}✗✗✗ SOME TESTS FAILED ✗✗✗${NC}"
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
fi
```

#### 18.2 Performance Benchmarks

**benches/throughput_bench.rs:**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use masque_core::*;

fn bench_noise_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise_handshake");
    
    let client_keypair = generate_test_keypair();
    let server_keypair = generate_test_keypair();
    
    group.bench_function("full_handshake", |b| {
        b.iter(|| {
            let result = perform_handshake(
                black_box(&client_keypair),
                black_box(&server_keypair),
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn bench_udp_forwarding(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_forwarding");
    group.throughput(Throughput::Bytes(1500));
    
    let forwarder = UdpForwarder::new();
    let packet = vec![0u8; 1500];
    let target = "8.8.8.8:53".parse().unwrap();
    
    group.bench_function("forward_1500_bytes", |b| {
        b.iter(|| {
            forwarder.forward_datagram(
                black_box(target),
                black_box(&packet),
            )
        });
    });
    
    group.finish();
}

fn bench_traffic_morphing(c: &mut Criterion) {
    let mut group = c.benchmark_group("traffic_morphing");
    group.throughput(Throughput::Bytes(1500));
    
    let morpher = TrafficMorpher::new();
    let packet = vec![0u8; 1500];
    
    group.bench_function("morph_1500_bytes", |b| {
        b.iter(|| {
            morpher.morph(black_box(&packet))
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_noise_handshake,
    bench_udp_forwarding,
    bench_traffic_morphing
);
criterion_main!(benches);
```

**Проверка:**
```bash
# Запустить comprehensive test suite
chmod +x scripts/e2e_comprehensive.sh
./scripts/e2e_comprehensive.sh

# Запустить benchmarks
cargo bench --workspace

# Проверить coverage
cargo llvm-cov --workspace --lib --html
open target/llvm-cov/html/index.html
```


---

## Итоговый Чеклист Flagship Готовности

### Код (100%)

- [x] Компиляция без ошибок
- [x] 0 clippy warnings
- [x] Форматирование соответствует rustfmt
- [x] Cyclomatic complexity ≤10
- [x] Все unsafe блоки задокументированы
- [x] Proper error handling (no unwrap в продакшене)

### Тестирование (100%)

- [x] Unit тесты ≥85% coverage
- [x] Integration тесты для всех критичных путей
- [x] Property-based тесты
- [x] E2E тесты (11 скриптов)
- [x] Performance benchmarks
- [x] Все тесты проходят

### Криптография (100%)

- [x] Hybrid Noise + ML-KEM768
- [x] OsRng для всех ключей
- [x] Zeroizing для секретов
- [x] Forward secrecy
- [x] Key rotation
- [x] Replay protection
- [x] Probe protection

### Компоненты (100%)

- [x] masque-core - MASQUE CONNECT-UDP полная реализация
- [x] vpr-crypto - Криптография
- [x] doh-gateway - DNS gateway
- [x] vpr-app - Desktop клиент с полной интеграцией
- [x] vpr-ai - AI Traffic Morpher с адаптацией
- [x] health-harness - Health monitoring
- [x] Routing & NAT - Полная реализация
- [x] Split tunnel - Реализован

### Stealth & DPI (100%)

- [x] TLS fingerprint customization
- [x] Traffic morphing с AI
- [x] Cover traffic генератор
- [x] Adaptive padding
- [x] DPI feedback loop
- [x] Probe protection
- [x] Replay protection

### Инфраструктура (100%)

- [x] CI/CD с coverage, audit, E2E
- [x] Terraform модули
- [x] Ansible playbooks
- [x] Systemd сервисы
- [x] Bootstrap manifest с rollback
- [x] Moving-target rotation

### Документация (100%)

- [x] Architecture
- [x] Security policies
- [x] User guide
- [x] Disaster recovery
- [x] Compliance checklist
- [x] Contributing guide
- [x] API документация
- [x] AI-агенты (9 файлов)

---

## Оценка Времени

| Фаза | Задачи | Дни | Статус |
|------|--------|-----|--------|
| 1 | Code Quality Cleanup | 2-3 | Готово к старту |
| 2 | Test Coverage | 3-4 | Готово к старту |
| 3 | Критичные компоненты | 5-7 | Готово к старту |
| 4 | Stealth & DPI | 3-4 | Готово к старту |
| 5 | Финальная полировка | 2-3 | Готово к старту |

**Итого: 15-21 день (3-4 недели) focused development**

---

## Критерии Успеха

### Минимальные требования (Must Have)

- ✅ Компиляция без ошибок
- ✅ 0 clippy warnings
- ✅ Все тесты проходят
- ✅ Coverage ≥85%
- ✅ MASQUE CONNECT-UDP полная реализация
- ✅ Routing & NAT работает
- ✅ VPN Client полная интеграция
- ✅ Документация полная

### Желательные (Should Have)

- ✅ Adaptive traffic shaping
- ✅ Bootstrap manifest с rollback
- ✅ DPI feedback loop
- ✅ Performance benchmarks
- ✅ Disaster recovery план

### Опциональные (Nice to Have)

- ⏳ DPDK ingress (P3)
- ⏳ Multipath QUIC (P3)
- ⏳ Hidden-master DNS (P2)
- ⏳ GUI packaging (P2)

---

## Принципы Реализации

### ✅ ДА (Делаем)

1. **Реальные реализации** - Только production-ready код
2. **Полное тестирование** - Unit + Integration + E2E + Property
3. **Proper error handling** - Result<T, E> везде
4. **Документация** - Inline + external docs
5. **Security-first** - Все политики соблюдены
6. **Performance** - Benchmarks и оптимизация

### ❌ НЕТ (Не делаем)

1. **Моки/фейки** - Только реальные компоненты
2. **Эвристики** - Только проверенные алгоритмы
3. **TODO placeholders** - Завершаем или удаляем
4. **unwrap()** - Только proper error handling
5. **Shortcuts** - Делаем правильно с первого раза
6. **Technical debt** - Не накапливаем

---

## Следующие Шаги

### Немедленно (Сегодня)

1. Создать ветку `flagship-completion`
2. Начать с Фазы 1: Code Quality Cleanup
3. Исправить clippy warnings
4. Создать файлы AI-агентов

### Эта неделя

1. Завершить Фазу 1 и 2
2. Начать Фазу 3 (критичные компоненты)
3. Daily progress tracking

### Следующая неделя

1. Завершить Фазу 3
2. Начать Фазу 4 (Stealth & DPI)
3. Mid-point review

### Через 2 недели

1. Завершить Фазу 4
2. Начать Фазу 5 (финальная полировка)
3. Pre-release testing

### Через 3 недели

1. Завершить Фазу 5
2. Comprehensive E2E testing
3. **FLAGSHIP READY! 🎉**

---

## Контакты и Поддержка

**Вопросы по плану:**
- Создать issue в GitHub
- Обсудить в команде

**Прогресс трекинг:**
- Ежедневные updates в FLAGSHIP_ACTION_PLAN.md
- Weekly reviews
- Milestone tracking

**Блокеры:**
- Немедленно эскалировать
- Документировать в issues
- Искать альтернативные решения

---

## Заключение

Этот план обеспечивает путь к 100% flagship готовности без компромиссов:

- ✅ Только реальные реализации
- ✅ Никаких моков или эвристик
- ✅ Полное тестирование
- ✅ Production-ready качество
- ✅ Comprehensive документация

**Время до flagship: 3-4 недели focused development**

**Готовы начать? Let's build something amazing! 🚀**

