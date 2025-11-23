# Architecture Overview (Draft)

> Этот документ будет расширен в соответствии с `1.logic`.

## Слои
1. **Transport** – MASQUE over QUIC + NoiseIK/NK.
2. **Control Plane** – bootstrap manifest, DNS/DoH, tls-fp-sync.
3. **Automation** – vpr Studio (Python GUI), Terraform/Ansible/Nix.
4. **Observability** – suspicion score, DNS health, mass-block drills.

## Следующие шаги
- Перенести разделы из `1.logic` (constraints, trust chains, modes).
- Добавить диаграммы (sequence/state).
