# CHost (씨호스트)

Lightweight, fast, and simple K-Style modern web server management panel built with Rust.  
Rust 단일 바이너리로 동작하는 초경량 한국형 모던 웹 서버 관리 패널입니다.

---

## English

### Key Features
- **Zero Bloat Architecture**: Single Rust binary under 20MB RAM usage, no Python or Docker daemon required.
- **Domain & SSL Automation**: Add domains to `/www/wwwroot/{domain}` with automatic Nginx/Apache config generation and Certbot SSL issuance.
- **Multi-Version PHP & Language Presets**: Install and switch PHP (7.4 - 8.4) per site, and manage Rust, Python, Node.js, and PHP services via systemd presets.
- **Built-in Multi-DB Studio**: Inspect, query, and back up SQLite and MySQL/MariaDB databases directly inside the panel without installing phpMyAdmin.
- **Storage & Log Cleaner**: Automated log rotation (`copytruncate`) with preview mode, large-directory scan, and protected-path whitelists.
- **Security & Audit Logs**: SHA-256 + JWT authentication, audit trail, and one-click security safeguards.
- **Multilingual UI (i18n)**: Built-in support for Korean (`ko`), English (`en`), Japanese (`ja`), Simplified Chinese (`zh-CN`), and Spanish (`es`).

### Quick Install (Ubuntu 22.04 / 24.04)
```bash
curl -sSL https://raw.githubusercontent.com/1clickmake/CHost/main/install.sh | sudo bash
```

### Build from Source
```bash
cargo build --release --bin chost
./target/release/chost
```

---

## 한국어

### 주요 기능
- **초경량 단일 바이너리**: Axum + Tokio 기반 단일 Rust 바이너리로 메모리 20MB 미만으로 동작하며 무거운 런타임 의존성이 없습니다.
- **도메인 및 SSL 자동화**: `/www/wwwroot/{도메인}` 경로 기반 사이트 생성, Nginx 설정 및 Certbot HTTPS 자동 발급을 지원합니다.
- **PHP 다중 버전 및 언어 프리셋**: PHP 7.4~8.4 빠른 설치 및 사이트별 전환과 Rust/Python/Node.js/PHP 서비스(systemd) 통합 관리를 제공합니다.
- **내장 멀티 DB 스튜디오**: phpMyAdmin 설치 없이 패널 내부에서 SQLite 및 MySQL/MariaDB 조회, SQL 실행, 백업을 처리합니다.
- **안전한 로그 및 저장 공간 정리**: 보관 기간별 로그 로테이션(`copytruncate`), 삭제 전 용량 미리보기, DB·업로드 폴더 보호 화이트리스트를 제공합니다.
- **보안 및 감사 로그**: JWT 인증, 관리자 작업 감사 로그(`audit_logs`) 기록, 5개국어(`ko`, `en`, `ja`, `zh-CN`, `es`) UI를 기본 지원합니다.

### 빠른 설치 (Ubuntu 22.04 / 24.04)
```bash
curl -sSL https://raw.githubusercontent.com/1clickmake/CHost/main/install.sh | sudo bash
```

---

## Portal & Links

- Official Site: https://chost.cmake.work
- Developer Docs: https://chost.cmake.work/docs
- Community Forum: https://chost.cmake.work/forum

## License

MIT License
