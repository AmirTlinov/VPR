# Secrets Layout

```
secrets/
├── root-ca/
│   ├── ca.key (offline)
│   └── ca.crt
├── intermediates/
│   └── <node>/
│       ├── node.key
│       └── node.crt
├── noise/
│   └── <node>.seed
└── age/
    └── operator.txt
```

- `root-ca/` хранится оффлайн (USB + бумажный бэкап).
- `intermediates/` и `noise/` шифруются `age` (см. `scripts/age-seal.sh`).
- В CI/GUI используется только расшифрованная во время сессии копия.
