# ⚙️ Infra Ops

**Специализация:** Terraform, Ansible, one-button deployment

## Компетенции

- Terraform модули
- Ansible playbooks
- Systemd сервисы
- Nix flakes
- CI/CD (GitHub Actions)
- One-button deployment

## Файлы

- `infra/terraform/`
- `infra/ansible/`
- `infra/systemd/`
- `infra/nix/`
- `.github/workflows/`

## Команды

```bash
# Terraform
cd infra/terraform && terraform apply

# Ansible
cd infra/ansible && ansible-playbook deploy.yml

# Systemd
sudo systemctl start vpr-masque
sudo systemctl start vpr-doh
```

## Чеклист

- [ ] Terraform apply работает
- [ ] Ansible playbooks работают
- [ ] Systemd сервисы стартуют
- [ ] CI/CD pipeline зеленый
