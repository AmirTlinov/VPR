//! Performance benchmarks for VPN critical paths
//!
//! Benchmarks cover:
//! - Padding operations (hot path for every packet)
//! - Replay protection (nonce validation)
//! - Cover traffic generation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use masque_core::padding::{Padder, PaddingConfig, PaddingStrategy};
use masque_core::replay_protection::NonceCache;
use masque_core::cover_traffic::{CoverTrafficConfig, CoverTrafficGenerator, TrafficPattern};
use std::time::Duration;

/// Benchmark padding strategies
fn bench_padding(c: &mut Criterion) {
    let mut group = c.benchmark_group("padding");

    let strategies = [
        ("none", PaddingStrategy::None),
        ("bucket", PaddingStrategy::Bucket),
        ("mtu", PaddingStrategy::Mtu),
        ("random_bucket", PaddingStrategy::RandomBucket),
    ];

    let packet_sizes = [64, 256, 512, 1024, 1400];

    for (name, strategy) in &strategies {
        let config = PaddingConfig {
            strategy: *strategy,
            mtu: 1500,
            jitter_enabled: false,
            max_jitter_us: 0,
            min_packet_size: 64,
            adaptive: false,
            high_strategy: PaddingStrategy::Mtu,
            medium_strategy: PaddingStrategy::Bucket,
            low_strategy: PaddingStrategy::RandomBucket,
            high_threshold: 60,
            medium_threshold: 20,
            hysteresis: 5,
        };
        let padder = Padder::new(config);

        for &size in &packet_sizes {
            let data = vec![0u8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(*name, size),
                &data,
                |b, data| {
                    b.iter(|| {
                        let mut buf = data.clone();
                        padder.pad(black_box(&mut buf))
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark replay protection (nonce cache)
fn bench_nonce_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("nonce_cache");

    let cache = NonceCache::new();

    // Benchmark check_and_record with sequential messages
    group.bench_function("check_and_record_sequential", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let msg = counter.to_be_bytes();
            let _ = cache.check_and_record(black_box(&msg));
        })
    });

    // Benchmark check for replays (existing entries)
    let cache2 = NonceCache::new();
    let base_msg = [0x42u8; 64];
    let _ = cache2.check_and_record(&base_msg); // Insert once

    group.bench_function("check_replay_detection", |b| {
        b.iter(|| {
            // This should detect replay
            let _ = cache2.check_and_record(black_box(&base_msg));
        })
    });

    group.finish();
}

/// Benchmark cover traffic generation
fn bench_cover_traffic(c: &mut Criterion) {
    let mut group = c.benchmark_group("cover_traffic");

    let patterns = [
        ("https_burst", TrafficPattern::HttpsBurst),
        ("h3_multiplex", TrafficPattern::H3Multiplex),
        ("webrtc_cbr", TrafficPattern::WebRtcCbr),
        ("idle", TrafficPattern::Idle),
    ];

    for (name, pattern) in &patterns {
        let config = CoverTrafficConfig {
            pattern: *pattern,
            base_rate_pps: 10.0,
            rate_jitter: 0.1,
            min_packet_size: 64,
            max_packet_size: 1400,
            adaptive: false,
            min_interval: Duration::from_millis(1),
        };
        let mut generator = CoverTrafficGenerator::new(config);

        group.bench_function(*name, |b| {
            b.iter(|| {
                generator.generate_packet()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_padding,
    bench_nonce_cache,
    bench_cover_traffic,
);

criterion_main!(benches);
