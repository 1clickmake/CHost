# CHost

Lightweight, fast, and simple web server management panel built with Rust.

## Key Features

- **Zero Bloat Architecture**: Single Rust binary under 20MB RAM usage, no Python or Docker daemon required.
- **Domain & SSL Automation**: Add domains to `/www/wwwroot/{domain}` with automatic Nginx/Apache config generation and Certbot SSL issuance.
- **Multi-Version PHP & Language Presets**: Install and switch PHP (7.4 - 8.4) per site, and manage Rust, Python, Node.js, and PHP services via systemd presets.
- **Built-in Multi-DB Studio**: Inspect, query, and back up SQLite and MySQL/MariaDB databases directly inside the panel without installing phpMyAdmin.
- **Storage & Log Cleaner**: Automated log rotation (`copytruncate`) with preview mode, large-directory scan, and protected-path whitelists.
- **Security & Audit Logs**: Argon2/SHA-256 + JWT authentication, brute-force lock, audit trail, and one-click security checklist.
- **Multilingual UI (i18n)**: Built-in support for Korean (`ko`), English (`en`), Japanese (`ja`), Simplified Chinese (`zh-CN`), and Spanish (`es`).

## Quick Install (Ubuntu 22.04 / 24.04)

```bash
curl -sSL https://raw.githubusercontent.com/1clickmake/CHost/main/install.sh | sudo bash
```

## Build from Source

```bash
cargo build --release --bin chost
./target/release/chost
```

## Portal & Documentation

- Official Site: https://chost.cmake.work
- Developer Docs: https://chost.cmake.work/docs
- Community Forum: https://chost.cmake.work/forum

## License

MIT License
