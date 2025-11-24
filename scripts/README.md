# Scripts

- `tls-fp-sync.py` – обновление TLS отпечатков (TODO).
- `health-harness` (Rust, см. target/release) – локальный DoH/DoQ/ODoH прогоны без отключения основного VPN.
- `swap-node.sh` – управление DNS/manifest (TODO).
- `e2e_harness.sh` – поднятие netns, установка (cert/Noise/manifest/systemd), запуск сервисов и health-harness с проверкой suspicion.
- `e2e_tun.sh` – полный TUN e2e: vpn-server/cliente в netns, NAT, ping/HTTP/iperf-like и iptables leak-check.

Каждый скрипт будет запускаться через GUI `vpr Studio`.
