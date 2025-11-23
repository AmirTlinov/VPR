Говори по русски.


ЦЕЛЬ: Создание программы для туннелирования интернет соединения для создания неизвестного ультра-производительного, высокосекретного, безопасного  протокола который нельзя было бы обнаружить или заблокировать. Который настраивался бы "одной кнопкой" на сервер и работал бы даже в Северной Корее,Татарстане,РФ,Китае и тд

• - Clarify constraints: define threat model (state-level surveillance, DPI,
    active probing, traffic correlation), performance targets (Gbps per tunnel,
    acceptable latency), supported platforms, and “one-button” deployment scope
    (single binary? container? IaC).
  - Map requirements to capabilities: split into transport obfuscation (hide
    “VPN-ness”), cryptographic assurances (forward secrecy, PQ readiness),
    network optimization (multi-path, congestion control), operational resilience
    (auto failover, self-update).
  - Survey existing building blocks: evaluate modern protocols (WireGuard,
    Masque/HTTP3, QUIC, L4S-aware congestion control, Noise-based handshakes) for
    reuse vs. custom layers; document gaps relative to goals (e.g., DPI evasion,
    stealth bootstrap).
  - Design layered architecture:
    • Covert bootstrap: pluggable transports (MASQUE over HTTPS/DoH, domain
    fronting fallback, decentralized rendezvous).
    • Core tunnel: stateless handshake (NoiseIK/NK variant) with hybrid PQ KEM +
    X25519, rotating session keys, padded packet framing.
    • Traffic shaping: adaptive cover traffic, mimic legitimate protocols (H3,
    WebRTC) with ML-based DPI feedback loop.
    • Performance plane: kernel bypass (DPDK/eBPF) on servers, NIC offload,
    multipath UDP, per-flow congestion control tuned for high-latency links.
  - Build automation path: “one button” should orchestrate provisioning
    (Terraform/Ansible), binary/config deployment, certificate/KEM material
    generation, telemetry hooks, and self-tests; package as reproducible images
    (Nix/OCI).
  - Threat-driven validation: red-team DPI emulation, active probe resistance
    tests, side-channel audits, fuzzing of handshake/state machines, KATs for
    crypto, chaos testing for link churn.
  - Iterate with telemetry: collect anonymized performance/suspicion metrics,
    feed into transport-selection heuristics; maintain rapid update channel to
    push new disguises/configs when censors react.
