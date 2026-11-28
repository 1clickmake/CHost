//! CHost 차세대 코어 엔진 (계획서 2편)
//! - 매직 프로젝트 자동 감지기 (Auto Project Detector)
//! - 공용 Composer 패키지 저장소 (라라벨 / 그누보드7 / CBoard 등 vendor 공유)
//! - 공용 파이썬 패키지 환경 (사이트별 venv 경량화)
//! - 스마트 헬스체크 (프록시 앱 응답 확인)

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub const SHARED_ROOT: &str = "/opt/chost/shared";

#[cfg(unix)]
fn make_symlink(src: &Path, dst: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}
#[cfg(not(unix))]
fn make_symlink(_src: &Path, _dst: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "symlink unsupported on this OS"))
}

// ───────────────────────── Git 가져오기 ─────────────────────────

pub fn validate_git_url(url: &str) -> bool {
    let u = url.trim();
    if u.len() > 300 || !(u.starts_with("https://") || u.starts_with("http://")) {
        return false;
    }
    !u.chars().any(|c| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '`' | '$' | '<' | '>' | '"' | '\'' | '\\'))
}

pub fn git_clone(url: &str, dest: &str) -> Result<(), String> {
    if !validate_git_url(url) {
        return Err("Invalid Git URL (only https:// addresses are allowed).".to_string());
    }
    let out = Command::new("git")
        .args(["clone", "--depth", "1", "--", url.trim(), dest])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("git execution failed: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let last: Vec<&str> = err.lines().rev().take(3).collect();
        Err(format!("git clone failed: {}", last.into_iter().rev().collect::<Vec<_>>().join(" ")))
    }
}

/// 소스를 임시 폴더에 받아 감지만 수행하고 삭제 (미리보기용)
pub fn detect_remote(url: &str) -> Result<Value, String> {
    let tmp = std::env::temp_dir().join(format!("chost-detect-{}", uuid::Uuid::new_v4()));
    let tmp_s = tmp.to_string_lossy().to_string();
    let res = git_clone(url, &tmp_s).map(|_| detect_project(&tmp));
    let _ = fs::remove_dir_all(&tmp);
    res
}

/// 사이트 루트에 소스를 clone하고 감지 결과를 반환 (미지원 언어면 정리 후 오류)
pub fn import_git(root: &str, url: &str) -> Result<Value, String> {
    git_clone(url, root)?;
    let det = detect_project(Path::new(root));
    if det.get("supported").and_then(|v| v.as_bool()) != Some(true) {
        let _ = fs::remove_dir_all(root);
        let _ = fs::create_dir_all(root);
        let label = det.get("label").and_then(|v| v.as_str()).unwrap_or("unknown");
        return Err(format!("Detected {} - automatic runtime setup is not supported yet.", label));
    }
    Ok(det)
}

// ───────────────────────── 매직 프로젝트 감지기 ─────────────────────────

pub fn detect_project(dir: &Path) -> Value {
    let has = |n: &str| dir.join(n).exists();
    let read = |n: &str| fs::read_to_string(dir.join(n)).unwrap_or_default();

    let mut language = "static";
    let mut framework = "blank";
    let mut site_type = "static";
    let mut port_hint: i64 = 0;
    let mut php_version = "";
    let mut label = "Static HTML".to_string();
    let mut supported = true;
    let mut shared = "";

    if has("composer.json") {
        let comp = read("composer.json").to_lowercase();
        language = "php";
        site_type = "php";
        php_version = "8.3";
        shared = "composer";
        if comp.contains("laravel/framework") {
            if comp.contains("gnuboard") || has("g7-setup.php") || has("g7-install") {
                framework = "gnuboard7";
                label = "Gnuboard7 (Laravel)".into();
            } else {
                framework = "laravel";
                label = "Laravel".into();
            }
        } else {
            framework = "php_composer";
            label = "PHP (Composer)".into();
        }
    } else if has("wp-config-sample.php") || has("wp-content") {
        language = "php";
        site_type = "php";
        framework = "wordpress";
        php_version = "8.3";
        label = "WordPress".into();
    } else if has("common.php") && has("bbs") && has("adm") {
        language = "php";
        site_type = "php";
        framework = "gnuboard5";
        php_version = "7.4";
        label = "Gnuboard5".into();
    } else if has("package.json") {
        let pkg: Value = serde_json::from_str(&read("package.json")).unwrap_or(Value::Null);
        let mut deps = String::new();
        for k in ["dependencies", "devDependencies"] {
            if let Some(o) = pkg.get(k).and_then(|v| v.as_object()) {
                for name in o.keys() {
                    deps.push_str(name);
                    deps.push(' ');
                }
            }
        }
        language = "node";
        site_type = "proxy";
        port_hint = 3000;
        if deps.split(' ').any(|d| d == "next") {
            framework = "nextjs";
            label = "Node.js (Next.js)".into();
        } else if deps.split(' ').any(|d| d == "express") {
            framework = "node_app";
            label = "Node.js (Express)".into();
        } else {
            framework = "node_app";
            label = "Node.js".into();
        }
    } else if has("Cargo.toml") {
        language = "rust";
        site_type = "proxy";
        port_hint = 8080;
        let name = cargo_bin_name(&dir.to_string_lossy()).unwrap_or_default();
        if name == "rust_board" {
            framework = "crust";
            label = "Rust (CRust)".into();
        } else {
            framework = "rust_app";
            label = "Rust".into();
        }
    } else if has("manage.py") || has("requirements.txt") || has("pyproject.toml") {
        language = "python";
        site_type = "proxy";
        port_hint = 8000;
        let reqs = format!("{}{}", read("requirements.txt"), read("pyproject.toml")).to_lowercase();
        if has("manage.py") {
            framework = "django";
            label = "Python (Django)".into();
        } else if reqs.contains("fastapi") {
            framework = "python_app";
            label = "Python (FastAPI)".into();
        } else if reqs.contains("flask") {
            framework = "python_app";
            label = "Python (Flask)".into();
        } else {
            framework = "python_app";
            label = "Python".into();
        }
    } else if has("go.mod") {
        language = "go";
        site_type = "proxy";
        framework = "go_app";
        label = "Go".into();
        supported = false;
    } else if has("pom.xml") || has("build.gradle") {
        language = "java";
        site_type = "proxy";
        framework = "java_app";
        label = "Java (Maven/Gradle)".into();
        supported = false;
    } else if has("Dockerfile") {
        language = "docker";
        site_type = "proxy";
        framework = "docker_app";
        label = "Docker".into();
        supported = false;
    } else if has("index.php") {
        language = "php";
        site_type = "php";
        php_version = "8.3";
        label = "PHP".into();
    }

    json!({
        "language": language,
        "framework": framework,
        "site_type": site_type,
        "port_hint": port_hint,
        "php_version": php_version,
        "label": label,
        "supported": supported,
        "shared_vendor": shared == "composer"
    })
}

// ───────────────────────── 공용 Composer 저장소 ─────────────────────────
//
// 구조: /opt/chost/shared/frameworks/{tag}/{composer.lock 해시}/
//         base/      ← vendor/composer, vendor/autoload.php, vendor/bin (사이트마다 복사, 수 MB 이하)
//         packages/  ← vendor/{org}/{pkg} 실제 패키지 (서버에 단 1벌)
// 사이트의 vendor/{org}/{pkg} 는 packages 로 심볼릭 링크되며, autoload 메타는 사이트별 복사본을
// 사용하므로 앱 코드(App\ 등) 경로가 정확히 유지된다. (vendor 폴더 통째 symlink 는 PHP __DIR__
// 실제경로 해석 때문에 autoload 가 깨지므로 사용하지 않는다.)
// composer.lock 해시별로 분리되므로 버전이 다른 사이트끼리 서로 영향을 주지 않는다.

fn run_sh(cmd: &str) -> Result<String, String> {
    let out = Command::new("sh").args(["-c", cmd]).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn ensure_composer() -> Result<(), String> {
    run_sh("if ! command -v composer >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq composer unzip; fi")
        .map(|_| ())
}

fn move_dir(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    let out = Command::new("mv").arg(src).arg(dst).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn copy_all(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    let out = Command::new("cp")
        .arg("-a")
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn composer_key(root: &Path) -> Result<String, String> {
    let bytes = fs::read(root.join("composer.lock"))
        .or_else(|_| fs::read(root.join("composer.json")))
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(&bytes))[..16].to_string())
}

fn share_composer_vendor(root: &str, tag: &str) -> Result<String, String> {
    let rp = Path::new(root);
    let key = composer_key(rp)?;
    let store = PathBuf::from(SHARED_ROOT).join("frameworks").join(tag).join(&key);
    let ready = store.join(".ready");
    let vendor = rp.join("vendor");

    // 1) 이미 공용 저장소가 있으면 즉시 연결 (composer install 불필요)
    if ready.exists() {
        let _ = fs::remove_dir_all(&vendor);
        copy_all(&store.join("base"), &vendor)?;
        let pk = store.join("packages");
        for org in fs::read_dir(&pk).map_err(|e| e.to_string())?.flatten() {
            let org_name = org.file_name();
            let org_dir = vendor.join(&org_name);
            fs::create_dir_all(&org_dir).map_err(|e| e.to_string())?;
            for pkg in fs::read_dir(org.path()).map_err(|e| e.to_string())?.flatten() {
                make_symlink(&pkg.path(), &org_dir.join(pkg.file_name())).map_err(|e| e.to_string())?;
            }
        }
        return Ok(format!("shared vendor linked instantly ({} / {})", tag, key));
    }

    // 2) 최초 1회: 일반 composer install 후 공용 저장소로 승격
    ensure_composer()?;
    let cmd = format!(
        "HOME=/root COMPOSER_HOME=/root/.composer COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader --no-interaction -d '{}'",
        root
    );
    run_sh(&cmd)?;
    if !vendor.join("autoload.php").exists() {
        return Err("composer install produced no vendor/autoload.php".to_string());
    }

    let base = store.join("base");
    let packages = store.join("packages");
    fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    fs::create_dir_all(&packages).map_err(|e| e.to_string())?;

    for entry in fs::read_dir(&vendor).map_err(|e| e.to_string())?.flatten() {
        let name = entry.file_name();
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        let name_s = name.to_string_lossy().to_string();
        if !ft.is_dir() || name_s == "composer" || name_s == "bin" {
            // 파일 / composer 메타 / bin → base 로 복사 (사이트에는 그대로 남김)
            let dst = base.join(&name);
            if ft.is_dir() {
                copy_all(&path, &dst)?;
            } else {
                fs::copy(&path, &dst).map_err(|e| e.to_string())?;
            }
            continue;
        }
        // {org}/{pkg} → packages 로 이동 후 symlink 로 대체
        for pkg in fs::read_dir(&path).map_err(|e| e.to_string())?.flatten() {
            let pkg_path = pkg.path();
            let is_dir = pkg.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                continue;
            }
            let target = packages.join(&name).join(pkg.file_name());
            move_dir(&pkg_path, &target)?;
            make_symlink(&target, &pkg_path).map_err(|e| e.to_string())?;
        }
    }
    fs::write(&ready, b"ok").map_err(|e| e.to_string())?;
    Ok(format!("shared vendor store created ({} / {}); next sites link instantly", tag, key))
}

/// 라라벨 계열이 요구하는 PHP 확장(sqlite3/intl/bcmath/redis)이 없으면 설치하고 FPM 을 재시작한다.
pub fn ensure_php_extensions(ver: &str) {
    if !cfg!(unix) || ver.is_empty() {
        return;
    }
    let cmd = format!(
        "MISS=''; for e in sqlite3 intl bcmath redis; do dpkg -s php{v}-$e >/dev/null 2>&1 || MISS=\"$MISS php{v}-$e\"; done; \
         if [ -n \"$MISS\" ]; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISS >/dev/null 2>&1; systemctl restart php{v}-fpm 2>/dev/null; fi; true",
        v = ver
    );
    let _ = run_sh(&cmd);
}

/// PHP 프로젝트 후처리: 공용 vendor 연결 + (라라벨 계열) .env/APP_KEY/권한 세팅
pub fn setup_php_project(root: &str, tag: &str) -> Vec<String> {
    let mut log: Vec<String> = Vec::new();
    if !cfg!(unix) {
        return log;
    }
    let p = Path::new(root);
    if let Ok(v) = run_sh("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'") {
        ensure_php_extensions(v.trim());
    }
    if p.join("composer.json").exists() {
        match share_composer_vendor(root, tag) {
            Ok(m) => log.push(m),
            Err(e) => log.push(format!("shared vendor skipped: {}", e)),
        }
    }
    if p.join("artisan").exists() {
        let cmd = format!(
            "cd '{r}' && ([ -f .env ] || ([ -f .env.example ] && cp .env.example .env) || true); \
             (php artisan key:generate --force; php artisan package:discover --ansi) >/dev/null 2>&1; \
             mkdir -p storage/framework/cache storage/framework/sessions storage/framework/views storage/logs bootstrap/cache; \
             chown -R www-data:www-data storage bootstrap/cache .env 2>/dev/null; chmod -R 775 storage bootstrap/cache 2>/dev/null; true",
            r = root
        );
        let _ = run_sh(&cmd);
        log.push("laravel .env / APP_KEY / permissions prepared".to_string());
        // 라라벨 기본 스켈레톤(sqlite)은 DB 파일 + migrate 가 있어야 첫 화면이 열린다.
        let env_txt = fs::read_to_string(p.join(".env")).unwrap_or_default();
        if env_txt.lines().any(|l| l.trim() == "DB_CONNECTION=sqlite") {
            let cmd = format!(
                "cd '{r}' && mkdir -p database && touch database/database.sqlite && php artisan migrate --force >/dev/null 2>&1; chown -R www-data:www-data database 2>/dev/null; chmod -R 775 database 2>/dev/null; true",
                r = root
            );
            let _ = run_sh(&cmd);
            log.push("laravel sqlite database created and migrated".to_string());
        }
    }
    let _ = run_sh(&format!("chown -R www-data:www-data '{r}' 2>/dev/null; chmod -R g+rwX '{r}' 2>/dev/null; true", r = root));
    log
}

// ───────────────────────── 공용 파이썬 환경 ─────────────────────────
//
// /opt/chost/shared/python/venv 에 django·gunicorn·uvicorn·requests 를 1벌만 설치하고,
// 사이트별 venv 의 site-packages 에 .pth 파일 1개로 연결한다.
// 사이트 자체 패키지(requirements.txt)가 먼저 적용되므로 사이트별 버전 고정도 가능하다.

pub fn python_setup_cmd(root: &str) -> String {
    format!(
        "SH='{sh}'; R='{r}'; \
         (python3 -c 'import ensurepip' >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1) && \
         ([ -x \"$SH/bin/pip\" ] || (rm -rf \"$SH\"; true) && [ -x \"$SH/bin/pip\" ] || (mkdir -p '{sr}' && python3 -m venv \"$SH\" && \"$SH/bin/pip\" install -q django gunicorn uvicorn requests)) && \
         ([ -x \"$R/venv/bin/pip\" ] || (rm -rf \"$R/venv\"; python3 -m venv \"$R/venv\")) && \
         SP=$(\"$R/venv/bin/python\" -c 'import sysconfig;print(sysconfig.get_paths()[\"purelib\"])') && \
         SHSP=$(\"$SH/bin/python\" -c 'import sysconfig;print(sysconfig.get_paths()[\"purelib\"])') && \
         echo \"$SHSP\" > \"$SP/chost_shared.pth\" && \
         ([ ! -f \"$R/requirements.txt\" ] || \"$R/venv/bin/pip\" install -q -r \"$R/requirements.txt\")",
        sh = format!("{}/python/venv", SHARED_ROOT),
        sr = format!("{}/python", SHARED_ROOT),
        r = root
    )
}

pub fn django_wsgi_module(root: &str) -> Option<String> {
    for e in fs::read_dir(root).ok()?.flatten() {
        if e.path().is_dir() && e.path().join("wsgi.py").exists() {
            return Some(format!("{}.wsgi:application", e.file_name().to_string_lossy()));
        }
    }
    None
}

/// 일반 파이썬 앱 실행 인자 (venv python 뒤에 붙음)
pub fn python_exec_args(root: &str, port: i64) -> String {
    let p = Path::new(root);
    let reqs = format!(
        "{}{}",
        fs::read_to_string(p.join("requirements.txt")).unwrap_or_default(),
        fs::read_to_string(p.join("pyproject.toml")).unwrap_or_default()
    )
    .to_lowercase();
    let module = if p.join("main.py").exists() {
        "main"
    } else if p.join("app.py").exists() {
        "app"
    } else if p.join("server.py").exists() {
        "server"
    } else {
        "app"
    };
    if reqs.contains("fastapi") {
        format!("-m uvicorn {}:app --host 127.0.0.1 --port {}", module, port)
    } else if reqs.contains("flask") {
        format!("-m gunicorn --bind 127.0.0.1:{} --workers 2 {}:app", port, module)
    } else {
        format!("{}/{}.py", root, module)
    }
}

pub fn cargo_bin_name(root: &str) -> Option<String> {
    let txt = fs::read_to_string(Path::new(root).join("Cargo.toml")).ok()?;
    let mut in_pkg = false;
    for l in txt.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_pkg = t == "[package]";
            continue;
        }
        if in_pkg && t.starts_with("name") {
            if let Some(v) = t.split('=').nth(1) {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

// ───────────────────────── 스마트 헬스체크 ─────────────────────────

/// 127.0.0.1:port 로 짧은 HTTP 요청을 보내 상태 코드를 확인한다. (None = 응답 없음)
pub fn probe_http(port: i64, host: &str) -> Option<u16> {
    if port <= 0 || port > 65535 {
        return None;
    }
    let addr = format!("127.0.0.1:{}", port).to_socket_addrs().ok()?.next()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(2500)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(1500)));
    let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    head.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok())
}

// ───────────────────────── 안전 기동 (Safe Start) ─────────────────────────

pub const STARTING_PAGE_PATH: &str = "/opt/chost/shared/starting.html";

const STARTING_PAGE_HTML: &str = r#"<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5"><title>Starting...</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif}.c{max-width:520px;padding:36px;text-align:center;border:1px solid #1e293b;border-radius:16px;background:#111c33}h1{font-size:22px;margin:0 0 12px}p{color:#94a3b8;line-height:1.7;margin:6px 0}.s{display:inline-block;width:34px;height:34px;border:4px solid #334155;border-top-color:#38bdf8;border-radius:50%;animation:r 1s linear infinite;margin-bottom:16px}@keyframes r{to{transform:rotate(360deg)}}.f{margin-top:18px;font-size:12px;color:#64748b}</style></head><body><div class="c"><div class="s"></div><h1>🚀 사이트를 준비하고 있어요 / Site is starting</h1><p>앱을 빌드하고 실행하는 중입니다. 잠시 후 자동으로 새로고침됩니다.</p><p>The app is being built and started. This page refreshes automatically.</p><div class="f">Powered by CHost</div></div></body></html>"#;

/// 앱이 아직 응답하지 않을 때(502/503/504) 방문자에게 보여줄 안내 페이지를 준비한다.
pub fn ensure_starting_page() {
    if !cfg!(unix) {
        return;
    }
    let p = Path::new(STARTING_PAGE_PATH);
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::read_to_string(p).map(|t| t != STARTING_PAGE_HTML).unwrap_or(true) {
        let _ = fs::write(p, STARTING_PAGE_HTML);
    }
}

pub fn journal_tail(svc: &str) -> String {
    Command::new("journalctl")
        .args(["-u", svc, "-n", "6", "--no-pager", "-o", "cat"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).replace('\n', " | "))
        .unwrap_or_default()
}

// ───────────────────────── Git 소스 관리 ─────────────────────────

fn git_out(root: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(["-c", "safe.directory=*", "-C", root])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// .git 이 있는 사이트의 현재 커밋 / 브랜치 / 원격 / 최근 이력
pub fn git_info(root: &str) -> Option<Value> {
    if !Path::new(root).join(".git").exists() {
        return None;
    }
    let commit = git_out(root, &["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    let full_commit = git_out(root, &["rev-parse", "HEAD"]).unwrap_or_default();
    let branch = git_out(root, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_default();
    let remote = git_out(root, &["remote", "get-url", "origin"]).unwrap_or_default();
    let log = git_out(root, &["log", "-n", "12", "--date=short", "--pretty=format:%h  %ad  %s"]).unwrap_or_default();
    let raw_commits = git_out(root, &["log", "-n", "12", "--date=short", "--pretty=format:%H\t%h\t%ad\t%s"]).unwrap_or_default();
    let commits: Vec<Value> = raw_commits
        .lines()
        .filter_map(|line| {
            let mut it = line.splitn(4, '\t');
            let (Some(h), Some(sh), Some(d), Some(m)) = (it.next(), it.next(), it.next(), it.next()) else {
                return None;
            };
            Some(json!({ "hash": h, "short": sh, "date": d, "msg": m, "current": h == full_commit }))
        })
        .collect();
    Some(json!({ "commit": commit, "full_commit": full_commit, "branch": branch, "remote": remote, "log": log, "commits": commits }))
}

/// git pull --ff-only 로 최신 소스를 받는다. (이전/이후 커밋 반환)
pub fn git_update(root: &str) -> Result<Value, String> {
    let old = git_out(root, &["rev-parse", "HEAD"])?;
    let output = git_out(root, &["pull", "--ff-only"])?;
    let new = git_out(root, &["rev-parse", "HEAD"])?;
    Ok(json!({ "old": old, "new": new, "changed": old != new, "output": output }))
}

/// 지정한 커밋 해시로 안전하게 롤백 (git reset --hard <hash>)
pub fn valid_git_hash(hash: &str) -> bool {
    (7..=40).contains(&hash.len()) && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn git_rollback(root: &str, hash: &str) -> Result<Value, String> {
    let h = hash.trim();
    if !valid_git_hash(h) {
        return Err("Invalid commit hash.".to_string());
    }
    let old = git_out(root, &["rev-parse", "HEAD"])?;
    let target_ref = format!("{}^{{commit}}", h);
    let resolved = git_out(root, &["rev-parse", "--verify", &target_ref])?;
    let output = git_out(root, &["reset", "--hard", &resolved])?;
    let new = git_out(root, &["rev-parse", "HEAD"])?;
    Ok(json!({ "old": old, "new": new, "changed": old != new, "output": output }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("chost-test-{}-{}", name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        for (f, c) in files {
            let p = d.join(f);
            if let Some(par) = p.parent() {
                fs::create_dir_all(par).unwrap();
            }
            fs::write(p, c).unwrap();
        }
        d
    }

    #[test]
    fn detects_frameworks() {
        let g7 = tmp("g7", &[("composer.json", r#"{"name":"gnuboard/g7","require":{"laravel/framework":"^12"}}"#)]);
        assert_eq!(detect_project(&g7)["framework"], "gnuboard7");
        let g7b = tmp("g7b", &[("composer.json", r#"{"name":"laravel/laravel","require":{"laravel/framework":"^12"}}"#), ("g7-setup.php", "")]);
        assert_eq!(detect_project(&g7b)["framework"], "gnuboard7");
        let lv = tmp("lv", &[("composer.json", r#"{"require":{"laravel/framework":"^11"}}"#)]);
        let d = detect_project(&lv);
        assert_eq!(d["framework"], "laravel");
        assert_eq!(d["shared_vendor"], true);
        let next = tmp("next", &[("package.json", r#"{"dependencies":{"next":"15"}}"#)]);
        assert_eq!(detect_project(&next)["framework"], "nextjs");
        let ex = tmp("ex", &[("package.json", r#"{"dependencies":{"express":"4"}}"#)]);
        assert_eq!(detect_project(&ex)["framework"], "node_app");
        let rs = tmp("rs", &[("Cargo.toml", "[package]\nname = \"myapp\"\n")]);
        let d = detect_project(&rs);
        assert_eq!(d["framework"], "rust_app");
        assert_eq!(cargo_bin_name(&rs.to_string_lossy()).unwrap(), "myapp");
        let crust = tmp("crust", &[("Cargo.toml", "[package]\nname = \"rust_board\"\n")]);
        assert_eq!(detect_project(&crust)["framework"], "crust");
        let dj = tmp("dj", &[("manage.py", ""), ("mysite/wsgi.py", "")]);
        assert_eq!(detect_project(&dj)["framework"], "django");
        assert_eq!(django_wsgi_module(&dj.to_string_lossy()).unwrap(), "mysite.wsgi:application");
        let go = tmp("go", &[("go.mod", "module x")]);
        assert_eq!(detect_project(&go)["supported"], false);
        let st = tmp("st", &[("index.html", "hi")]);
        assert_eq!(detect_project(&st)["site_type"], "static");
    }

    #[test]
    fn python_entry_and_url_guard() {
        let fa = tmp("fa", &[("requirements.txt", "fastapi\nuvicorn"), ("main.py", "")]);
        assert!(python_exec_args(&fa.to_string_lossy(), 8001).contains("uvicorn main:app"));
        let fl = tmp("fl", &[("requirements.txt", "Flask"), ("app.py", "")]);
        assert!(python_exec_args(&fl.to_string_lossy(), 8002).contains("gunicorn"));
        assert!(validate_git_url("https://github.com/user/repo.git"));
        assert!(!validate_git_url("git@github.com:user/repo.git"));
        assert!(!validate_git_url("https://x.com/a;rm -rf /"));
        assert!(!validate_git_url("--upload-pack=evil"));
    }
}
