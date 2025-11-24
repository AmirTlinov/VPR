# CODE REVIEW: vpr-ai Crate

**Date**: 2025-11-24
**Reviewer**: Claude Code (Automated Audit)
**Version**: 0.1.0
**Verdict**: REQUEST_CHANGES

---

## Summary

Крейт `vpr-ai` реализует AI-powered traffic morphing для обхода DPI. Архитектура в целом корректная, код чистый, но есть критические проблемы безопасности, связанные с криптографической случайностью и потенциальными timing side-channels.

---

## Risk Assessment

| Category       | Risk Level | Score | Notes |
|---------------|------------|-------|-------|
| **Security**   | HIGH       | 55/100 | Криптографические недостатки, timing attacks |
| **Correctness**| MEDIUM     | 75/100 | Корректная логика, но edge cases не покрыты |
| **Performance**| LOW        | 80/100 | Некоторые аллокации в hot path |
| **DX**         | LOW        | 85/100 | Хорошая документация, но тесты неполные |

---

## Gate Checklist

| Gate | Status | Details |
|------|--------|---------|
| Tests green | PASS | 20/20 tests pass |
| Diff coverage >= 90% | FAIL | 77.18% overall (morpher.rs: 62%) |
| Static/lint 0 errors | PASS | Clippy clean |
| Security 0 High/Critical | FAIL | 3 high-severity findings |
| No obvious perf issues | WARN | Vec allocations in hot paths |

---

## Findings

### BLOCKER: B-001 - Weak PRNG Seeding in CoverGenerator

**File**: `src/cover.rs:41-42`
**Severity**: BLOCKER
**Category**: Security/Cryptography

```rust
let rng = match seed {
    Some(s) => StdRng::seed_from_u64(s),
    None => StdRng::from_entropy(),
};
```

**Problem**: `StdRng::from_entropy()` использует `getrandom` syscall только один раз при создании. Для криптографически важного cover traffic это создает следующие риски:

1. **Seed correlation attack**: Если атакующий знает примерное время создания генератора, он может воспроизвести последовательность пакетов.
2. **State recovery**: После достаточного количества наблюдений ChaCha12 (внутри StdRng) state может быть восстановлен.

**Recommendation**: Периодический reseed или использование `rand::rngs::ThreadRng` который автоматически reseeds.

---

### BLOCKER: B-002 - Timing Side-Channel in Profile Matching

**File**: `src/morpher.rs:117-143`
**Severity**: BLOCKER
**Category**: Security/Side-Channel

```rust
fn calculate_confidence(&self, stats: &TrafficStats) -> f32 {
    if stats.packet_count < 4 {
        return 0.7;  // Early exit - timing leak
    }
    // ... expensive calculations
}
```

**Problem**: Early return создает observable timing difference. DPI может измерять время обработки и определять:
- Сколько пакетов уже обработано (< 4 vs >= 4)
- Насколько трафик похож на профиль (быстрый return = не похож)

**Recommendation**: Constant-time comparison или dummy operations для выравнивания времени.

---

### BLOCKER: B-003 - Cover Traffic Distinguishable by Entropy Patterns

**File**: `src/cover.rs:193-219`
**Severity**: BLOCKER
**Category**: Security/DPI Evasion

```rust
fn fill_game_like(&mut self, packet: &mut [u8]) {
    // ...
    for (i, byte) in packet[8..].iter_mut().enumerate() {
        if i % 4 == 0 {
            *byte = (self.sequence >> (i % 8)) as u8;  // DETERMINISTIC!
        } else {
            *byte = self.rng.gen();
        }
    }
}
```

**Problem**: Детерминистический паттерн `i % 4 == 0` создает обнаруживаемую структуру:
- Каждый 4-й байт имеет низкую энтропию (производная от sequence)
- DPI может построить статистику по позициям байтов

**Recommendation**: Использовать случайные интервалы для структурных байтов.

---

### MAJOR: M-001 - Hardcoded SSRC Constant

**File**: `src/cover.rs:186-187`
**Severity**: MAJOR
**Category**: Security/Fingerprinting

```rust
// SSRC (random but consistent per session)
let ssrc = 0xDEADBEEF_u32;
```

**Problem**: Константный SSRC является уникальным fingerprint для VPR трафика. Любой DPI может искать RTP пакеты с SSRC = 0xDEADBEEF.

---

### MAJOR: M-002 - Vec Allocations in Hot Path

**File**: `src/cover.rs:58-66`
**Severity**: MAJOR
**Category**: Performance

```rust
pub fn generate(&mut self) -> Vec<u8> {
    let size = self.sample_size();
    let mut packet = vec![0u8; size];  // ALLOCATION
    // ...
}
```

**Problem**: Каждый вызов `generate()` аллоцирует новый Vec. При высокой частоте cover traffic (gaming profile: ~300 pps) это создает GC pressure.

**Recommendation**: Pool-based allocation или reusable buffer.

---

### MAJOR: M-003 - Non-Constant-Time Float Operations

**File**: `src/cover.rs:122-130`
**Severity**: MAJOR
**Category**: Security/Timing

```rust
fn sample_gaussian_size(&mut self) -> usize {
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
    // ...
}
```

**Problem**: `ln()`, `sqrt()`, `cos()` имеют data-dependent timing на некоторых платформах. Box-Muller transform особенно уязвим при `u1` близком к 0.

---

### MAJOR: M-004 - Insufficient Test Coverage

**File**: `src/morpher.rs`
**Severity**: MAJOR
**Category**: Quality

Coverage: 62.01% lines, 59.05% regions

**Missing coverage**:
- OnnxMorpher полностью не протестирован (требует model file)
- Edge cases: пустой packet, максимальный размер packet
- Error paths в ONNX inference

---

### MINOR: N-001 - Magic Numbers

**File**: `src/cover.rs:84, 97, 130`
**Severity**: MINOR
**Category**: Maintainability

```rust
if self.rng.gen_bool(0.7) {  // Magic number
    // ...
}
return 64; // Fallback - magic number
size.clamp(32.0, 1500.0)  // Magic MTU bounds
```

**Recommendation**: Extract to named constants.

---

### MINOR: N-002 - Missing Const Generics for Context Window

**File**: `src/features.rs:10`
**Severity**: MINOR
**Category**: Architecture

```rust
pub const CONTEXT_WINDOW_SIZE: usize = 16;
```

Window size hardcoded. Should be configurable for different use cases.

---

### MINOR: N-003 - Clone in Hot Path

**File**: `src/features.rs:139`
**Severity**: MINOR
**Category**: Performance

```rust
self.packets.push_back(features.clone());
```

`PacketFeatures` cloned on every packet. Consider `Arc` or inline storage.

---

## Architecture Assessment

### Strengths

1. **Clean separation**: `cover`, `features`, `morpher`, `profiles` - четкое разделение ответственности
2. **Trait-based abstraction**: `TrafficMorpher` trait позволяет заменять реализации
3. **Configuration**: `MorpherConfig` presets (low_latency, high_anonymity, streaming)
4. **Good documentation**: Каждый модуль имеет doc-comments с примерами

### Weaknesses

1. **No hexagonal architecture**: Domain logic (morphing decisions) смешана с infrastructure (ONNX)
2. **Missing ports/adapters**: Cover generation должен быть за trait для тестирования
3. **No repository pattern**: ProfileStats hardcoded, should be loadable

### DDD Compliance: 60/100

- Domain entities: TrafficProfile, MorphDecision - OK
- Value objects: PacketFeatures, ProfileStats - OK
- Services: TrafficMorpher - OK
- Missing: Aggregates, Domain Events, Repositories

---

## Performance Analysis

### Complexity

| Function | Time | Space | Notes |
|----------|------|-------|-------|
| `add_packet` | O(1) | O(1) | Amortized (VecDeque) |
| `to_tensor` | O(n) | O(n) | n = CONTEXT_WINDOW_SIZE = 16 |
| `sample_common_size` | O(k) | O(k) | k = common_sizes.len() <= 6 |
| `calculate_confidence` | O(n) | O(n) | 2 Vec allocations |
| `generate` | O(m) | O(m) | m = packet size |

### Bottlenecks

1. **`calculate_confidence`**: Creates 2 temporary Vecs per call (sizes, delays)
2. **`to_tensor`**: Allocates new Vec on every call
3. **Float operations**: Box-Muller in `sample_gaussian_size`

### Memory

- `CoverGenerator`: ~72 bytes + ProfileStats
- `PacketContext`: ~16 * sizeof(PacketFeatures) = ~640 bytes
- `RuleBasedMorpher`: ~800 bytes total

---

## Security Model Analysis

### Threat Model Assumptions

1. Adversary: Nation-state DPI with ML capabilities
2. Adversary can observe: packet sizes, timing, direction, entropy
3. Adversary cannot: decrypt payload, inject packets

### Cover Traffic Distinguishability

| Attack Vector | Current Protection | Gap |
|---------------|-------------------|-----|
| Size distribution | Profile matching | OK |
| Timing patterns | Delay injection | OK |
| Byte-level entropy | High entropy fill | WEAK - patterns in game/RTP |
| Protocol headers | TLS/RTP mimicry | WEAK - static SSRC |
| Inter-packet correlation | Sequence numbers | WEAK - predictable |
| Burst patterns | Profile-based | OK |

### Cryptographic Correctness

| Aspect | Status | Issue |
|--------|--------|-------|
| PRNG quality | WARN | StdRng OK but no reseed |
| Seed entropy | PASS | `from_entropy` uses OS RNG |
| Deterministic mode | WARN | Allows full replay if seed known |

---

## Recommendations

### Critical (Must Fix)

1. **Reseed RNG periodically**: Add `reseed_interval` to CoverGenerator
2. **Randomize SSRC**: Generate per-session SSRC from RNG
3. **Remove deterministic patterns**: Randomize structure positions in game packets
4. **Add constant-time confidence**: Use dummy ops or bitwise operations

### Important (Should Fix)

1. **Buffer pooling**: Add `generate_into(&mut buf)` method
2. **Increase test coverage**: Add property-based tests with proptest
3. **Add ONNX integration tests**: Mock model or use test fixture

### Nice to Have

1. Extract magic numbers to constants
2. Add metrics/tracing for monitoring
3. Consider const generics for window size

---

## Test Recommendations

### Missing Tests

1. **Property-based**: Cover packet entropy distribution
2. **Fuzzing**: Malformed packet handling
3. **Integration**: Full morpher pipeline
4. **Timing**: Verify no observable timing differences

### Suggested proptest Properties

```rust
proptest! {
    #[test]
    fn cover_entropy_matches_profile(seed: u64, profile: TrafficProfile) {
        let mut gen = CoverGenerator::with_seed(profile, Some(seed));
        let packets: Vec<_> = (0..100).map(|_| gen.generate()).collect();

        // Shannon entropy should be > 7.5 bits/byte for encrypted-like content
        for pkt in &packets {
            let entropy = calculate_shannon_entropy(pkt);
            prop_assert!(entropy > 7.5, "Entropy too low: {}", entropy);
        }
    }
}
```

---

## Verdict

**REQUEST_CHANGES**

Три BLOCKER findings (B-001, B-002, B-003) должны быть исправлены перед использованием в production:

1. Cover traffic имеет детектируемые паттерны (SSRC, structured bytes)
2. Timing side-channels могут выдать информацию о состоянии
3. PRNG seeding недостаточно для криптографического применения

После исправления blockers, крейт будет готов к production use.

---

## Scores Summary

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Security | 55 | 35% | 19.25 |
| Architecture | 70 | 20% | 14.00 |
| Performance | 80 | 15% | 12.00 |
| Code Quality | 75 | 15% | 11.25 |
| Documentation | 85 | 10% | 8.50 |
| Testing | 65 | 5% | 3.25 |
| **TOTAL** | | 100% | **68.25/100** |
