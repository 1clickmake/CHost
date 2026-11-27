mod db;
mod engine;
mod ops;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use db::{hash_password, verify_password, Database};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::SystemTime,
};
use sysinfo::{Disks, System};
use tower_http::cors::CorsLayer;
use walkdir::WalkDir;

struct AppState {
    db: Database,
    jwt_secret: String,
    data_dir: PathBuf,
    install_running: AtomicBool,
    login_guard: std::sync::Mutex<std::collections::HashMap<String, LoginGuard>>,
}

#[derive(Default, Clone)]
struct LoginGuard {
    fails: u32,
    window_start: i64,
    locked_until: i64,
}

const LOGIN_MAX_FAILS: u32 = 5;
const LOGIN_WINDOW_SECS: i64 = 900;
const LOGIN_LOCK_SECS: i64 = 900;

fn client_ip(addr: &std::net::SocketAddr, headers: &HeaderMap) -> String {
    let peer = addr.ip();
    if peer.is_loopback() {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                let f = first.trim();
                if !f.is_empty() && f.len() < 64 {
                    return f.to_string();
                }
            }
        }
    }
    peer.to_string()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    password: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct InstallRuntimesReq {
    items: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CreateSiteReq {
    domain: String,
    site_type: String,
    proxy_port: Option<i64>,
    php_version: Option<String>,
    framework: Option<String>,
    issue_ssl: Option<bool>,
    create_ssh: Option<bool>,
    create_db: Option<bool>,
    ftp_user: Option<String>,
    ftp_pass: Option<String>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_pass: Option<String>,
    git_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateSubdomainReq {
    parent_domain: String,
    prefix: String,
    language: String,
    framework: String,
    proxy_port: Option<i64>,
    php_version: Option<String>,
    issue_ssl: Option<bool>,
    create_ssh: Option<bool>,
    create_db: Option<bool>,
    ftp_user: Option<String>,
    ftp_pass: Option<String>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_pass: Option<String>,
    git_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SwitchPhpReq {
    php_version: String,
}

#[derive(Debug, Deserialize)]
struct CreateAppReq {
    name: String,
    language: String,
    work_dir: String,
    exec_cmd: String,
    port: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AppActionReq {
    action: String,
}

#[derive(Debug, Deserialize)]
struct SqliteQueryReq {
    db_path: String,
    sql: String,
}

#[derive(Debug, Deserialize)]
struct StorageCleanReq {
    days: u64,
    preview: bool,
    compress: bool,
}

#[derive(Debug, Deserialize)]
struct FileSaveReq {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct TerminalReq {
    cmd: String,
}

#[derive(Debug, Deserialize)]
struct QueryPath {
    path: Option<String>,
    days: Option<u64>,
}

fn is_authed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut token_opt = None;
    for part in cookie_hdr.split(';') {
        let p = part.trim();
        if let Some(val) = p.strip_prefix("chost_token=") {
            token_opt = Some(val.to_string());
            break;
        }
    }
    let Some(token) = token_opt else {
        return false;
    };
    decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .is_ok()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "success": false, "error": "Authentication required." })),
    )
        .into_response()
}

async fn serve_panel() -> Response {
    match fs::read_to_string("panel/index.html") {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "panel/index.html not found").into_response(),
    }
}

async fn handle_auth_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    Json(json!({
        "success": true,
        "authenticated": is_authed(&state, &headers)
    }))
    .into_response()
}

async fn handle_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let ip = client_ip(&addr, &headers);
    let now = Utc::now().timestamp();
    {
        let g = state.login_guard.lock().unwrap();
        if let Some(e) = g.get(&ip) {
            if e.locked_until > now {
                let wait = e.locked_until - now;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "success": false,
                        "code": "login_locked",
                        "retry_after": wait,
                        "error": format!("Too many failed attempts. Try again in {} min.", (wait + 59) / 60)
                    })),
                )
                    .into_response();
            }
        }
    }
    let stored = state.db.get_setting("admin_pw_hash", "");
    if !verify_password(&stored, req.password.trim()) {
        let (locked, left) = {
            let mut g = state.login_guard.lock().unwrap();
            let e = g.entry(ip.clone()).or_default();
            if now - e.window_start > LOGIN_WINDOW_SECS {
                e.fails = 0;
                e.window_start = now;
            }
            e.fails += 1;
            let left = LOGIN_MAX_FAILS.saturating_sub(e.fails);
            if e.fails >= LOGIN_MAX_FAILS {
                e.locked_until = now + LOGIN_LOCK_SECS;
                e.fails = 0;
                (true, 0)
            } else {
                (false, left)
            }
        };
        state.db.log_audit("anonymous", "LOGIN_FAILED", "panel", &format!("Invalid password attempt from {}", ip));
        if locked {
            state.db.log_audit("system", "LOGIN_LOCKED", "panel", &format!("{} locked for {} min", ip, LOGIN_LOCK_SECS / 60));
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "success": false,
                    "code": "login_locked",
                    "retry_after": LOGIN_LOCK_SECS,
                    "error": format!("Too many failed attempts. Try again in {} min.", LOGIN_LOCK_SECS / 60)
                })),
            )
                .into_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Invalid password.", "attempts_left": left })),
        )
            .into_response();
    }
    state.login_guard.lock().unwrap().remove(&ip);
    if !stored.starts_with("$argon2") {
        // 구버전 SHA-256 해시 → Argon2id 로 자동 업그레이드
        let _ = state.db.set_setting("admin_pw_hash", &hash_password(req.password.trim()));
    }
    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let token = encode(
        &Header::default(),
        &Claims {
            sub: "admin".to_string(),
            exp,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .unwrap_or_default();

    state.db.log_audit("admin", "LOGIN_SUCCESS", "panel", "Signed in to CHost");
    let cookie = format!("chost_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800", token);
    ([(header::SET_COOKIE, cookie)], Json(json!({ "success": true }))).into_response()
}

async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let stored = state.db.get_setting("admin_pw_hash", "");
    if !verify_password(&stored, req.current_password.trim()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "현재 비밀번호가 일치하지 않습니다." })),
        )
            .into_response();
    }
    let new_pw = req.new_password.trim();
    if new_pw.len() < 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "새 비밀번호는 4자 이상 입력해 주세요." })),
        )
            .into_response();
    }
    if let Err(e) = state.db.set_setting("admin_pw_hash", &hash_password(new_pw)) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response();
    }
    state.db.log_audit("admin", "PASSWORD_CHANGED", "panel", "Admin password updated");
    Json(json!({ "success": true })).into_response()
}

async fn handle_logout() -> Response {
    let cookie = "chost_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    ([(header::SET_COOKIE, cookie)], Json(json!({ "success": true }))).into_response()
}

async fn handle_locale(Path(lang): Path<String>) -> Response {
    let safe = match lang.as_str() {
        "ko" | "en" | "ja" | "zh-CN" | "es" => lang,
        _ => "ko".to_string(),
    };
    let path = format!("locales/{}.json", safe);
    match fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(v) => Json(json!({ "success": true, "lang": safe, "dict": v })).into_response(),
            Err(_) => Json(json!({ "success": false })).into_response(),
        },
        Err(_) => Json(json!({ "success": false })).into_response(),
    }
}

async fn handle_system_stats(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let mut sys = System::new_all();
    sys.refresh_all();
    std::thread::sleep(std::time::Duration::from_millis(120));
    sys.refresh_cpu_all();

    let cpu_usage = sys.global_cpu_usage();
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();

    let disks = Disks::new_with_refreshed_list();
    let mut disk_total: u64 = 0;
    let mut disk_avail: u64 = 0;
    for d in disks.list() {
        disk_total += d.total_space();
        disk_avail += d.available_space();
    }
    let disk_used = disk_total.saturating_sub(disk_avail);
    let disk_pct = if disk_total > 0 {
        (disk_used as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    Json(json!({
        "success": true,
        "hostname": System::host_name().unwrap_or_else(|| "localhost".into()),
        "os": System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into()),
        "uptime_secs": System::uptime(),
        "cpu_percent": ((cpu_usage as f64) * 10.0).round() / 10.0,
        "mem_total_mb": total_mem / (1024 * 1024),
        "mem_used_mb": used_mem / (1024 * 1024),
        "disk_total_gb": (disk_total as f64 / 1073741824.0 * 10.0).round() / 10.0,
        "disk_used_gb": (disk_used as f64 / 1073741824.0 * 10.0).round() / 10.0,
        "disk_percent": (disk_pct * 10.0).round() / 10.0,
        "disk_warning": disk_pct >= 80.0
    }))
    .into_response()
}

async fn handle_list_sites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let sites = state.db.list_sites().unwrap_or_default();
    Json(json!({ "success": true, "sites": sites })).into_response()
}

fn service_is_active(svc: &str) -> bool {
    if !cfg!(unix) {
        return false;
    }
    Command::new("systemctl")
        .args(["is-active", "--quiet", svc])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Detect active webserver ("apache2" if apache2 is running and nginx is not, else "nginx").
fn detect_active_webserver() -> &'static str {
    if service_is_active("apache2") && !service_is_active("nginx") {
        "apache2"
    } else {
        "nginx"
    }
}

fn write_nginx_site_conf(
    domain: &str,
    site_type: &str,
    root_path: &str,
    proxy_port: i64,
    php_version: &str,
) -> String {
    let body = match site_type {
        "proxy" => format!(
            "    error_page 502 503 504 /__chost_starting.html;\n    location = /__chost_starting.html {{\n        internal;\n        alias /opt/chost/shared/starting.html;\n    }}\n    location / {{\n        proxy_pass http://127.0.0.1:{};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }}\n",
            proxy_port
        ),
        "php" => {
            let ver = if php_version.is_empty() { "8.3" } else { php_version };
            format!(
                "    index index.php index.html;\n    location / {{\n        try_files $uri $uri/ /index.php?$query_string;\n    }}\n    location ~ \\.php$ {{\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php{}-fpm.sock;\n    }}\n",
                ver
            )
        }
        _ => "    index index.html index.htm;\n    location / {\n        try_files $uri $uri/ =404;\n    }\n"
            .to_string(),
    };
    format!(
        "server {{\n    listen 80;\n    server_name {};\n    root {};\n    access_log /www/wwwlogs/{}.access.log;\n    error_log /www/wwwlogs/{}.error.log;\n{}\n}}\n",
        domain, root_path, domain, domain, body
    )
}

fn write_apache_site_conf(
    domain: &str,
    site_type: &str,
    root_path: &str,
    proxy_port: i64,
    php_version: &str,
) -> String {
    let extra = match site_type {
        "proxy" => format!(
            "    Alias /__chost_starting.html /opt/chost/shared/starting.html\n    <Directory \"/opt/chost/shared\">\n        Require all granted\n    </Directory>\n    ErrorDocument 502 /__chost_starting.html\n    ErrorDocument 503 /__chost_starting.html\n    ProxyPass /__chost_starting.html !\n    ProxyPreserveHost On\n    ProxyPass / http://127.0.0.1:{}/\n    ProxyPassReverse / http://127.0.0.1:{}/\n",
            proxy_port, proxy_port
        ),
        "php" => {
            let ver = if php_version.is_empty() { "8.3" } else { php_version };
            format!(
                "    <FilesMatch \\.php$>\n        SetHandler \"proxy:unix:/run/php/php{}-fpm.sock|fcgi://localhost\"\n    </FilesMatch>\n",
                ver
            )
        }
        _ => String::new(),
    };
    format!(
        "<VirtualHost *:80>\n    ServerName {}\n    DocumentRoot \"{}\"\n    <Directory \"{}\">\n        Options FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n    ErrorLog \"/www/wwwlogs/{}.error.log\"\n    CustomLog \"/www/wwwlogs/{}.access.log\" combined\n{}\n</VirtualHost>\n",
        domain, root_path, root_path, domain, domain, extra
    )
}

fn reload_active_webserver(ws: &str) -> Result<(), String> {
    if !cfg!(unix) {
        return Ok(());
    }
    if ws == "apache2" {
        let _ = Command::new("sh")
            .args(["-c", "systemctl disable --now nginx 2>/dev/null || true"])
            .output();
        let test = Command::new("apache2ctl").arg("configtest").output();
        match test {
            Ok(o) if o.status.success() => {}
            Ok(o) => return Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => return Err(format!("apache2ctl failed: {}", e)),
        }
        let act = if service_is_active("apache2") {
            Command::new("systemctl").args(["reload", "apache2"]).output()
        } else {
            Command::new("systemctl").args(["enable", "--now", "apache2"]).output()
        };
        return match act {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(format!("systemctl apache2 failed: {}", e)),
        };
    }

    let _ = Command::new("sh")
        .args(["-c", "systemctl disable --now apache2 2>/dev/null || true"])
        .output();
    match Command::new("nginx").arg("-t").output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        Err(e) => return Err(format!("nginx -t failed: {}", e)),
    }
    let act_out = if service_is_active("nginx") {
        Command::new("systemctl").args(["reload", "nginx"]).output()
    } else {
        Command::new("systemctl").args(["enable", "--now", "nginx"]).output()
    };
    match act_out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(format!("systemctl nginx failed: {}", e)),
    }
}

/// 다른 웹서버 설정 파일에서 추가 도메인(alias) 목록을 읽어온다. (Apache ServerAlias / Nginx server_name)
fn read_aliases_from_other_ws(domain: &str, active_ws: &str) -> Vec<String> {
    let path = if active_ws == "nginx" {
        format!("/etc/apache2/sites-available/{}.conf", domain)
    } else {
        format!("/etc/nginx/sites-available/{}.conf", domain)
    };
    let txt = fs::read_to_string(&path).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for line in txt.lines() {
        let t = line.trim().trim_end_matches(';');
        let list: Vec<&str> = if let Some(r) = t.strip_prefix("ServerAlias ") {
            r.split_whitespace().collect()
        } else if let Some(r) = t.strip_prefix("server_name ") {
            r.split_whitespace().collect()
        } else {
            continue;
        };
        for a in list {
            let a = a.trim().to_lowercase();
            if !a.is_empty() && a != domain && !out.contains(&a) && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*') {
                out.push(a);
            }
        }
    }
    out
}

/// Apache <-> Nginx 전환 후, DB 에 등록된 모든 사이트의 설정을 현재 활성 웹서버 형식으로 다시 만들고 SSL 을 재연결한다.
fn migrate_sites_to_active_webserver(db: &Database) -> Value {
    if !cfg!(unix) {
        return json!({ "webserver": "n/a", "sites": [] });
    }
    let ws = detect_active_webserver();
    let _ = fs::create_dir_all("/www/wwwlogs");
    engine::ensure_starting_page();
    let sites = db.list_sites().unwrap_or_default();
    let mut report: Vec<Value> = Vec::new();
    for s in &sites {
        let aliases = read_aliases_from_other_ws(&s.domain, ws);
        let web_root = if FsPath::new(&s.root_path).join("public").join("index.php").exists() {
            format!("{}/public", s.root_path)
        } else {
            s.root_path.clone()
        };
        let mut conf = if ws == "apache2" {
            write_apache_site_conf(&s.domain, &s.site_type, &web_root, s.proxy_port, &s.php_version)
        } else {
            write_nginx_site_conf(&s.domain, &s.site_type, &web_root, s.proxy_port, &s.php_version)
        };
        if !aliases.is_empty() {
            if ws == "nginx" {
                conf = conf.replace(
                    &format!("server_name {};", s.domain),
                    &format!("server_name {} {};", s.domain, aliases.join(" ")),
                );
            } else {
                conf = conf.replace(
                    &format!("ServerName {}\n", s.domain),
                    &format!("ServerName {}\n    ServerAlias {}\n", s.domain, aliases.join(" ")),
                );
            }
        }
        if ws == "apache2" {
            let _ = fs::write(format!("/etc/apache2/sites-available/{}.conf", s.domain), &conf);
            let _ = Command::new("a2ensite").arg(format!("{}.conf", s.domain)).output();
        } else {
            let avail = format!("/etc/nginx/sites-available/{}.conf", s.domain);
            let _ = fs::write(&avail, &conf);
            let _ = Command::new("ln")
                .args(["-sf", &avail, &format!("/etc/nginx/sites-enabled/{}.conf", s.domain)])
                .output();
        }
        report.push(json!({ "domain": s.domain, "type": s.site_type, "aliases": aliases, "ssl": s.ssl_enabled }));
    }
    let reload = reload_active_webserver(ws);
    let mut ssl_results: Vec<Value> = Vec::new();
    if reload.is_ok() {
        for s in sites.iter().filter(|s| s.ssl_enabled) {
            let r = run_certbot_auto(&s.domain);
            ssl_results.push(json!({ "domain": s.domain, "ok": r.is_ok(), "error": r.err() }));
        }
    }
    json!({
        "webserver": ws,
        "reload": reload.map(|_| "ok".to_string()).unwrap_or_else(|e| e),
        "sites": report,
        "ssl": ssl_results
    })
}

async fn handle_webserver_migrate(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let st = state.clone();
    match tokio::task::spawn_blocking(move || migrate_sites_to_active_webserver(&st.db)).await {
        Ok(rep) => {
            state.db.log_audit("admin", "WEBSERVER_MIGRATE", "sites", &rep["webserver"].to_string());
            Json(json!({ "success": true, "report": rep })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn provision_webserver_site(
    domain: &str,
    site_type: &str,
    web_root: &str,
    proxy_port: i64,
    php_ver: &str,
) {
    if !cfg!(unix) {
        return;
    }
    let _ = fs::create_dir_all("/www/wwwlogs");
    engine::ensure_starting_page();
    let ws = detect_active_webserver();
    if ws == "apache2" {
        let conf = write_apache_site_conf(domain, site_type, web_root, proxy_port, php_ver);
        let avail = format!("/etc/apache2/sites-available/{}.conf", domain);
        let _ = fs::write(&avail, &conf);
        let _ = Command::new("a2enmod")
            .args(["rewrite", "proxy", "proxy_http", "proxy_fcgi", "setenvif", "ssl"])
            .output();
        let _ = Command::new("a2ensite").arg(format!("{}.conf", domain)).output();
        let _ = reload_active_webserver("apache2");
    } else {
        let conf = write_nginx_site_conf(domain, site_type, web_root, proxy_port, php_ver);
        let avail = format!("/etc/nginx/sites-available/{}.conf", domain);
        let enabled = format!("/etc/nginx/sites-enabled/{}.conf", domain);
        let _ = fs::write(&avail, &conf);
        let _ = Command::new("ln").args(["-sf", &avail, &enabled]).output();
        let _ = reload_active_webserver("nginx");
    }
}

/// Issue a Let's Encrypt certificate via certbot for the active webserver (nginx or apache2).
fn run_certbot_auto(domain: &str) -> Result<(), String> {
    if !cfg!(unix) {
        return Ok(());
    }
    let ws = detect_active_webserver();
    reload_active_webserver(ws)?;
    let plugin = if ws == "apache2" { "--apache" } else { "--nginx" };
    let out = Command::new("certbot")
        .args([
            plugin,
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
        ])
        .output()
        .map_err(|e| format!("certbot execution failed: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if err.is_empty() {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        } else {
            err
        };
        Err(if msg.is_empty() {
            format!("certbot exited with {:?}", out.status.code())
        } else {
            msg
        })
    }
}

fn render_default_welcome_html(domain: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Welcome to {domain} — CHost</title>
  <style>
    body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b1220; color:#e2e8f0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:24px; }}
    .card {{ max-width:540px; width:100%; background:#111b2e; border:1px solid #24324a; border-radius:16px; padding:34px 30px; box-shadow:0 20px 50px rgba(0,0,0,.35); }}
    .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; background:rgba(56,189,248,.15); color:#7dd3fc; border:1px solid rgba(56,189,248,.35); margin-bottom:14px; }}
    h1 {{ margin:0 0 10px; font-size:26px; color:#fff; word-break:break-all; }}
    p {{ margin:0 0 12px; color:#94a3b8; line-height:1.65; font-size:15px; }}
    code {{ background:#0b1220; border:1px solid #24324a; padding:2px 6px; border-radius:6px; color:#7dd3fc; font-size:13px; }}
    .foot {{ margin-top:20px; padding-top:14px; border-top:1px solid #1e293b; font-size:12px; color:#64748b; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">CHost Ready</span>
    <h1>Welcome to {domain}</h1>
    <p>Your website has been successfully provisioned and is now live.</p>
    <p>Upload your site files or replace <code>index.html</code> in your web root directory to get started.</p>
    <div class="foot">Powered by CHost Web Server Panel</div>
  </div>
</body>
</html>
"#,
        domain = domain
    )
}

fn gen_random_secret(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn sanitize_ident(raw: Option<&str>, max_len: usize) -> String {
    raw.unwrap_or("")
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(max_len)
        .collect()
}

fn domain_prefix_slug(domain: &str, max_len: usize) -> String {
    let first_label = domain.trim().split('.').next().unwrap_or("");
    let slug: String = first_label
        .chars()
        .map(|c| if c == '-' { '_' } else { c.to_ascii_lowercase() })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(max_len)
        .collect();
    if slug.is_empty() { "site".to_string() } else { slug }
}

fn provision_sftp_user(domain: &str, root_path: &str, custom_user: Option<&str>, custom_pass: Option<&str>) -> serde_json::Value {
    let cu = sanitize_ident(custom_user, 24);
    let user = if !cu.is_empty() {
        cu
    } else {
        format!("{}_ftp", domain_prefix_slug(domain, 20))
    };
    let cp_raw = custom_pass.unwrap_or("").trim();
    let pass = if !cp_raw.is_empty() { cp_raw.to_string() } else { gen_random_secret(14) };
    if !cfg!(unix) {
        return json!({ "created": false, "note": "Unix only" });
    }
    let _ = Command::new("useradd")
        .args(["-d", root_path, "-s", "/bin/bash", &user])
        .output();
    let chpasswd_cmd = format!("echo '{}:{}' | chpasswd", user, pass.replace('\'', ""));
    let cp = Command::new("sh").args(["-c", &chpasswd_cmd]).output();
    let _ = Command::new("chown")
        .args(["-R", &format!("{}:www-data", user), root_path])
        .output();
    let _ = Command::new("chmod")
        .args(["-R", "g+rwX", root_path])
        .output();
    let ok = cp.map(|o| o.status.success()).unwrap_or(false);
    json!({
        "created": ok,
        "protocol": "SFTP (SSH Port 22)",
        "user": user,
        "password": pass,
        "root_path": root_path
    })
}

fn provision_database(domain: &str, custom_db: Option<&str>, custom_user: Option<&str>, custom_pass: Option<&str>) -> serde_json::Value {
    let prefix = domain_prefix_slug(domain, 20);
    let cdb = sanitize_ident(custom_db, 32);
    let cu = sanitize_ident(custom_user, 24);
    let db_name = if !cdb.is_empty() { cdb } else { format!("{}_db", prefix) };
    let db_user = if !cu.is_empty() { cu } else { format!("{}_db", prefix) };
    let cp_raw = custom_pass.unwrap_or("").trim();
    let db_pass = if !cp_raw.is_empty() { cp_raw.to_string() } else { gen_random_secret(14) };
    let db_pass_sql = db_pass.replace('\'', "");
    if !cfg!(unix) {
        return json!({ "created": false, "note": "Unix only" });
    }
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}'; GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost'; FLUSH PRIVILEGES;",
        db_name, db_user, db_pass_sql, db_name, db_user
    );
    match Command::new("mysql").args(["-e", &sql]).output() {
        Ok(o) if o.status.success() => json!({
            "created": true,
            "engine": "MariaDB / MySQL",
            "host": "localhost",
            "db_name": db_name,
            "db_user": db_user,
            "db_pass": db_pass
        }),
        _ => json!({
            "created": false,
            "note": "MariaDB/MySQL이 설치되어 있지 않거나 root 소켓 접속이 필요합니다."
        }),
    }
}

fn app_service_name(domain: &str) -> String {
    let slug = sanitize_ident(Some(domain), 40);
    let s = if slug.is_empty() { "site".to_string() } else { slug };
    format!("chost-app-{}.service", s)
}

fn allocate_proxy_port(db: &Database, requested: Option<i64>) -> i64 {
    let used: std::collections::HashSet<i64> = db
        .list_sites()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.site_type == "proxy" && s.proxy_port > 0)
        .map(|s| s.proxy_port)
        .collect();

    let is_port_free = |p: i64| -> bool {
        if p <= 0 || p > 65535 || p == 8800 || used.contains(&p) {
            return false;
        }
        std::net::TcpListener::bind(("127.0.0.1", p as u16)).is_ok()
    };

    if let Some(p) = requested {
        if is_port_free(p) {
            return p;
        }
    }
    for p in 8080..=8999 {
        if is_port_free(p) {
            return p;
        }
    }
    8080
}

fn ensure_php_fpm_installed(php_ver: &str) {
    if !cfg!(unix) || php_ver.is_empty() {
        return;
    }
    let bin = format!("/usr/sbin/php-fpm{}", php_ver);
    let sock = format!("/run/php/php{}-fpm.sock", php_ver);
    if FsPath::new(&bin).exists() || FsPath::new(&sock).exists() {
        let _ = Command::new("systemctl").args(["start", &format!("php{}-fpm", php_ver)]).output();
        return;
    }
    let cmd = format!(
        "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php{v}-fpm php{v}-mysql php{v}-mbstring php{v}-xml php{v}-curl php{v}-gd php{v}-zip && systemctl enable --now php{v}-fpm",
        v = php_ver
    );
    let _ = Command::new("sh").args(["-c", &cmd]).output();
}

fn provision_proxy_app(domain: &str, root_path: &str, language: &str, framework: &str, proxy_port: i64) -> (Option<String>, bool) {
    if !cfg!(unix) || proxy_port <= 0 {
        return (None, false);
    }
    let svc = app_service_name(domain);
    let unit_path = format!("/etc/systemd/system/{}", svc);

    match (language, framework) {
        ("rust", "crust") => {
            let cfg_path = FsPath::new(root_path).join("config.toml");
            if !cfg_path.exists() {
                let ex_path = FsPath::new(root_path).join("config.example.toml");
                let cfg_body = if let Ok(raw) = fs::read_to_string(&ex_path) {
                    raw.replace("port = 3000", &format!("port = {}", proxy_port))
                } else {
                    format!(
                        "[server]\nhost = \"127.0.0.1\"\nport = {}\ndev_mode = false\n\n[database]\nurl = \"sqlite://rust_board.db?mode=rwc\"\nmax_connections = 10\n",
                        proxy_port
                    )
                };
                let _ = fs::write(&cfg_path, cfg_body);
            }
            let unit = format!(
                "[Unit]\nDescription=CHost Rust App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={root}/target/release/rust_board\nRestart=always\nRestartSec=3\nEnvironment=RUST_LOG=info\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain,
                root = root_path
            );
            let _ = fs::write(&unit_path, unit);
            let bin_exists = FsPath::new(root_path).join("target/release/rust_board").exists();
            if bin_exists {
                let _ = Command::new("sh").args(["-c", &format!("systemctl daemon-reload && systemctl enable --now {}", svc)]).output();
                return (Some(svc), false);
            }
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::spawn(async move {
                let build_cmd = format!(
                    "export PATH=\"/root/.cargo/bin:$PATH\"; cd '{}' && cargo build --release && systemctl daemon-reload && systemctl enable '{}' && systemctl restart '{}'",
                    root_owned, svc_owned, svc_owned
                );
                let _ = Command::new("sh").args(["-c", &build_cmd]).output();
            });
            return (Some(svc), true);
        }
        ("rust", "rust_app") => {
            let bin_name = engine::cargo_bin_name(root_path).unwrap_or_else(|| "app".to_string());
            let unit = format!(
                "[Unit]\nDescription=CHost Rust App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={root}/target/release/{bin}\nEnvironment=PORT={port}\nEnvironment=HOST=127.0.0.1\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, bin = bin_name, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::task::spawn_blocking(move || {
                let cmd = format!(
                    "export PATH=\"/root/.cargo/bin:$PATH\"; cd '{}' && cargo build --release && systemctl daemon-reload && systemctl enable '{}' && systemctl restart '{}'",
                    root_owned, svc_owned, svc_owned
                );
                let _ = Command::new("sh").args(["-c", &cmd]).output();
            });
            return (Some(svc), true);
        }
        ("python", "django") => {
            let wsgi = engine::django_wsgi_module(root_path).unwrap_or_else(|| "mysite.wsgi:application".to_string());
            let unit = format!(
                "[Unit]\nDescription=CHost Django App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={root}/venv/bin/python -m gunicorn --bind 127.0.0.1:{port} --workers 2 {wsgi}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, port = proxy_port, wsgi = wsgi
            );
            let _ = fs::write(&unit_path, unit);
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::task::spawn_blocking(move || {
                let setup_cmd = format!(
                    "{base} && cd '{r}' && ([ -f '{r}/manage.py' ] || ('{r}/venv/bin/python' -m django startproject mysite . && sed -i \"s/ALLOWED_HOSTS = \\\\[\\\\]/ALLOWED_HOSTS = ['*']/\" '{r}/mysite/settings.py')); systemctl daemon-reload && systemctl enable '{s}' && systemctl restart '{s}'",
                    base = engine::python_setup_cmd(&root_owned), r = root_owned, s = svc_owned
                );
                let _ = Command::new("sh").args(["-c", &setup_cmd]).output();
            });
            return (Some(svc), true);
        }
        ("python", "python_app") => {
            let args = engine::python_exec_args(root_path, proxy_port);
            let unit = format!(
                "[Unit]\nDescription=CHost Python App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={root}/venv/bin/python {args}\nEnvironment=PORT={port}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, args = args, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::task::spawn_blocking(move || {
                let cmd = format!(
                    "{base} && systemctl daemon-reload && systemctl enable '{s}' && systemctl restart '{s}'",
                    base = engine::python_setup_cmd(&root_owned), s = svc_owned
                );
                let _ = Command::new("sh").args(["-c", &cmd]).output();
            });
            return (Some(svc), true);
        }
        ("node", "node_app") => {
            let unit = format!(
                "[Unit]\nDescription=CHost Node.js App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart=/usr/bin/env npm start\nEnvironment=PORT={port}\nEnvironment=HOST=127.0.0.1\nEnvironment=NODE_ENV=production\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::task::spawn_blocking(move || {
                let cmd = format!(
                    "cd '{r}' && (command -v node >/dev/null 2>&1 || (curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y -qq nodejs)) && npm install --silent && npm run build --if-present && systemctl daemon-reload && systemctl enable '{s}' && systemctl restart '{s}'",
                    r = root_owned, s = svc_owned
                );
                let _ = Command::new("sh").args(["-c", &cmd]).output();
            });
            return (Some(svc), true);
        }
        ("python", _) => {
            let app_py = FsPath::new(root_path).join("app.py");
            if !app_py.exists() {
                let code = format!(
                    "import os, http.server, socketserver\nPORT = int(os.environ.get('PORT', {port}))\nclass H(http.server.BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200)\n        self.send_header('Content-type', 'text/html; charset=utf-8')\n        self.end_headers()\n        self.wfile.write(b'<h1>{domain}</h1><p>Python App running on CHost (Port {port})</p>')\n    def log_message(self, *a): pass\nwith socketserver.TCPServer(('127.0.0.1', PORT), H) as httpd:\n    httpd.serve_forever()\n",
                    port = proxy_port, domain = domain
                );
                let _ = fs::write(&app_py, code);
            }
            let py_bin = if FsPath::new(&format!("{}/venv/bin/python", root_path)).exists() {
                format!("{}/venv/bin/python", root_path)
            } else {
                "/usr/bin/python3".to_string()
            };
            let unit = format!(
                "[Unit]\nDescription=CHost Python App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={py} {root}/app.py\nEnvironment=PORT={port}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, py = py_bin, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let _ = Command::new("sh").args(["-c", &format!("systemctl daemon-reload && systemctl enable --now {}", svc)]).output();
            return (Some(svc), false);
        }
        ("node", "express") => {
            let unit = format!(
                "[Unit]\nDescription=CHost Express App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart=/usr/bin/node {root}/server.js\nEnvironment=PORT={port}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let server_js = FsPath::new(root_path).join("server.js");
            if !server_js.exists() {
                let code = format!(
                    "const express = require('express');\nconst app = express();\nconst port = process.env.PORT || {port};\napp.get('/', (req, res) => {{\n  res.send('<h1>{domain}</h1><p>Express.js App running on CHost (Port ' + port + ')</p>');\n}});\napp.listen(port, '127.0.0.1', () => console.log('Listening on', port));\n",
                    port = proxy_port, domain = domain
                );
                let _ = fs::write(&server_js, code);
            }
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::spawn(async move {
                let cmd = format!(
                    "cd '{r}' && (command -v node >/dev/null 2>&1 || (curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y -qq nodejs)) && ([ -f package.json ] || npm init -y >/dev/null 2>&1) && ([ -d node_modules/express ] || npm install --silent express) && systemctl daemon-reload && systemctl enable '{s}' && systemctl restart '{s}'",
                    r = root_owned, s = svc_owned
                );
                let _ = Command::new("sh").args(["-c", &cmd]).output();
            });
            return (Some(svc), true);
        }
        ("node", "nextjs") => {
            let unit = format!(
                "[Unit]\nDescription=CHost Next.js App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart=/usr/bin/npx next start -H 127.0.0.1 -p {port}\nEnvironment=NODE_ENV=production\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let pkg_json = FsPath::new(root_path).join("package.json");
            if !pkg_json.exists() {
                let pkg = "{\n  \"name\": \"chost-nextjs\",\n  \"private\": true,\n  \"scripts\": { \"dev\": \"next dev\", \"build\": \"next build\", \"start\": \"next start\" },\n  \"dependencies\": { \"next\": \"^15.0.0\", \"react\": \"^19.0.0\", \"react-dom\": \"^19.0.0\" },\n  \"devDependencies\": { \"typescript\": \"^5.0.0\", \"@types/node\": \"^22.0.0\", \"@types/react\": \"^19.0.0\" }\n}\n";
                let _ = fs::write(&pkg_json, pkg);
                let app_dir = FsPath::new(root_path).join("app");
                let _ = fs::create_dir_all(&app_dir);
                let _ = fs::write(app_dir.join("layout.tsx"), "export default function RootLayout({ children }: { children: React.ReactNode }) {\n  return <html lang=\"en\"><body>{children}</body></html>;\n}\n");
                let _ = fs::write(
                    app_dir.join("page.tsx"),
                    format!("export default function Page() {{\n  return <main style={{{{ padding: 40, fontFamily: 'sans-serif' }}}}><h1>{domain}</h1><p>Next.js (TypeScript) running on CHost</p></main>;\n}}\n", domain = domain),
                );
            }
            let root_owned = root_path.to_string();
            let svc_owned = svc.clone();
            tokio::spawn(async move {
                let cmd = format!(
                    "cd '{r}' && (command -v node >/dev/null 2>&1 || (curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y -qq nodejs)) && npm install --silent && npm run build && systemctl daemon-reload && systemctl enable '{s}' && systemctl restart '{s}'",
                    r = root_owned, s = svc_owned
                );
                let _ = Command::new("sh").args(["-c", &cmd]).output();
            });
            return (Some(svc), true);
        }
        ("node", _) => {
            let server_js = FsPath::new(root_path).join("server.js");
            if !server_js.exists() {
                let code = format!(
                    "const http = require('http');\nconst port = process.env.PORT || {port};\nhttp.createServer((req, res) => {{\n  res.writeHead(200, {{ 'Content-Type': 'text/html; charset=utf-8' }});\n  res.end('<h1>{domain}</h1><p>Node.js App running on CHost (Port ' + port + ')</p>');\n}}).listen(port, '127.0.0.1');\n",
                    port = proxy_port, domain = domain
                );
                let _ = fs::write(&server_js, code);
            }
            let node_bin = if FsPath::new("/usr/bin/node").exists() { "/usr/bin/node" } else { "/usr/local/bin/node" };
            let unit = format!(
                "[Unit]\nDescription=CHost Node.js App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart={node} {root}/server.js\nEnvironment=PORT={port}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                domain = domain, root = root_path, node = node_bin, port = proxy_port
            );
            let _ = fs::write(&unit_path, unit);
            let _ = Command::new("sh").args(["-c", &format!("systemctl daemon-reload && systemctl enable --now {}", svc)]).output();
            return (Some(svc), false);
        }
        ("java", _) => {
            let jar = FsPath::new(root_path).join("app.jar");
            if jar.exists() {
                let unit = format!(
                    "[Unit]\nDescription=CHost Java App ({domain})\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={root}\nExecStart=/usr/bin/java -jar {root}/app.jar --server.port={port}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                    domain = domain, root = root_path, port = proxy_port
                );
                let _ = fs::write(&unit_path, unit);
                let _ = Command::new("sh").args(["-c", &format!("systemctl daemon-reload && systemctl enable --now {}", svc)]).output();
                return (Some(svc), false);
            }
        }
        _ => {}
    }
    (None, false)
}

async fn handle_create_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateSiteReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let domain = req.domain.trim().to_lowercase();
    if domain.is_empty() || domain.contains('/') || domain.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid domain name." })),
        )
            .into_response();
    }
    let root_path = format!("/www/wwwroot/{}", domain);
    let _ = fs::create_dir_all(&root_path);

    let mut site_type = req.site_type.clone();
    let mut fw_str = req.framework.as_deref().unwrap_or("blank").trim().to_string();
    let mut git_lang: Option<String> = None;
    let mut php_ver_override: Option<String> = None;
    let mut detected: Option<Value> = None;
    match try_git_import(&root_path, req.git_url.as_deref()).await {
        Ok(Some(det)) => {
            site_type = det["site_type"].as_str().unwrap_or("static").to_string();
            fw_str = det["framework"].as_str().unwrap_or("blank").to_string();
            git_lang = det["language"].as_str().map(|v| v.to_string());
            php_ver_override = det["php_version"].as_str().filter(|v| !v.is_empty()).map(|v| v.to_string());
            detected = Some(det);
        }
        Ok(None) => {
            if !fw_str.is_empty() && fw_str != "blank" {
                provision_framework(&root_path, &fw_str, &domain);
            }
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": e })),
            )
                .into_response();
        }
    }

    let index_file = FsPath::new(&root_path).join("index.html");
    let index_php = FsPath::new(&root_path).join("index.php");
    let pub_php = FsPath::new(&root_path).join("public").join("index.php");
    if !index_file.exists() && !index_php.exists() && !pub_php.exists() {
        let _ = fs::write(&index_file, render_default_welcome_html(&domain));
    }

    let proxy_port = if site_type == "proxy" {
        allocate_proxy_port(&state.db, req.proxy_port)
    } else {
        req.proxy_port.unwrap_or(0)
    };
    let php_ver = php_ver_override.or(req.php_version).unwrap_or_default();
    if site_type == "php" {
        ensure_php_fpm_installed(&php_ver);
        engine::ensure_php_extensions(&php_ver);
    }
    let web_root = if pub_php.exists() { format!("{}/public", root_path) } else { root_path.clone() };
    provision_webserver_site(&domain, &site_type, &web_root, proxy_port, &php_ver);

    let app_lang = if let Some(l) = git_lang.as_deref() { l } else if fw_str == "crust" { "rust" } else if fw_str == "django" { "python" } else if fw_str == "express" || fw_str == "nextjs" { "node" } else if fw_str == "springboot" { "java" } else { site_type.as_str() };
    let (app_service, app_building) = if site_type == "proxy" {
        provision_proxy_app(&domain, &root_path, app_lang, &fw_str, proxy_port)
    } else {
        (None, false)
    };

    let ftp_info = if req.create_ssh.unwrap_or(false) {
        Some(provision_sftp_user(&domain, &root_path, req.ftp_user.as_deref(), req.ftp_pass.as_deref()))
    } else {
        None
    };
    let db_info = if req.create_db.unwrap_or(false) {
        Some(provision_database(&domain, req.db_name.as_deref(), req.db_user.as_deref(), req.db_pass.as_deref()))
    } else {
        None
    };

    match state
        .db
        .create_site(&domain, &site_type, &root_path, proxy_port, &php_ver)
    {
        Ok(id) => {
            let fu = ftp_info.as_ref().and_then(|v| v.get("user")).and_then(|v| v.as_str()).unwrap_or("");
            let fp = ftp_info.as_ref().and_then(|v| v.get("password")).and_then(|v| v.as_str()).unwrap_or("");
            let dn = db_info.as_ref().and_then(|v| v.get("db_name")).and_then(|v| v.as_str()).unwrap_or("");
            let du = db_info.as_ref().and_then(|v| v.get("db_user")).and_then(|v| v.as_str()).unwrap_or("");
            let dp = db_info.as_ref().and_then(|v| v.get("db_pass")).and_then(|v| v.as_str()).unwrap_or("");
            if !fu.is_empty() || !dn.is_empty() {
                let _ = state.db.update_site_credentials(id, fu, fp, dn, du, dp);
            }
            let mut ssl_enabled = false;
            let mut ssl_error: Option<String> = None;
            if req.issue_ssl.unwrap_or(false) && cfg!(unix) {
                match run_certbot_auto(&domain) {
                    Ok(()) => {
                        let _ = state.db.update_site_ssl(id, true);
                        ssl_enabled = true;
                    }
                    Err(e) => {
                        ssl_error = Some(e);
                    }
                }
            }
            if let Some(svc) = app_service.clone() {
                spawn_health_watch(state.clone(), domain.clone(), proxy_port, svc, false);
            }
            state
                .db
                .log_audit("admin", "CREATE_SITE", &domain, &format!("type={}, port={}", site_type, proxy_port));
            Json(json!({
                "success": true,
                "id": id,
                "domain": domain,
                "root_path": root_path,
                "proxy_port": proxy_port,
                "app_service": app_service,
                "app_building": app_building,
                "ssl_enabled": ssl_enabled,
                "ssl_error": ssl_error,
                "ftp_info": ftp_info,
                "db_info": db_info,
                "detected": detected
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn provision_framework(root_path: &str, framework: &str, domain: &str) {
    if !cfg!(unix) {
        return;
    }
    match framework {
        "cmake_board" => {
            let _ = Command::new("git")
                .args(["clone", "--depth", "1", "https://github.com/1clickmake/CBoard.git", root_path])
                .output();
            let _ = engine::setup_php_project(root_path, "cmake_board");
        }
        "laravel" | "gnuboard7" => {
            let repo = if framework == "laravel" {
                "https://github.com/laravel/laravel.git"
            } else {
                "https://github.com/gnuboard/g7.git"
            };
            let _ = Command::new("git").args(["clone", "--depth", "1", repo, root_path]).output();
            let _ = engine::setup_php_project(root_path, framework);
        }
        "crust" => {
            let _ = Command::new("git")
                .args(["clone", "--depth", "1", "https://github.com/1clickmake/CRust.git", root_path])
                .output();
        }
        "gnuboard5" => {
            let _ = Command::new("git")
                .args(["clone", "--depth", "1", "https://github.com/gnuboard/gnuboard5.git", root_path])
                .output();
            let cmd = format!("mkdir -p '{r}/data' && chown -R www-data:www-data '{r}' && chmod -R g+rwX '{r}' && chmod -R 775 '{r}/data'", r = root_path);
            let _ = Command::new("sh").args(["-c", &cmd]).output();
        }
        "wordpress" => {
            let cmd = format!(
                "curl -sSL https://wordpress.org/latest.tar.gz | tar -xz --strip-components=1 -C '{r}' && chown -R www-data:www-data '{r}' && chmod -R g+rwX '{r}'",
                r = root_path
            );
            let _ = Command::new("sh").args(["-c", &cmd]).output();
        }
        "django" => {}
        "springboot" => {
            let run_sh = FsPath::new(root_path).join("run.sh");
            let _ = fs::write(&run_sh, "#!/bin/bash\njava -jar app.jar\n");
        }
        _ => {}
    }
    let idx = FsPath::new(root_path).join("index.html");
    let idx_php = FsPath::new(root_path).join("index.php");
    let pub_php = FsPath::new(root_path).join("public").join("index.php");
    if !idx.exists() && !idx_php.exists() && !pub_php.exists() {
        let _ = fs::write(
            &idx,
            format!(
                "<!doctype html><html><head><meta charset='utf-8'><title>{}</title></head><body><h1>{}</h1><p>Framework: {} | Provisioned by CHost</p></body></html>",
                domain, domain, framework
            ),
        );
    }
}

async fn handle_create_subdomain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateSubdomainReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let mut prefix = req.prefix.trim().to_lowercase();
    let mut parent = req.parent_domain.trim().to_lowercase();
    if parent.is_empty() {
        if let Some((p, rest)) = prefix.split_once('.') {
            let p_str = p.to_string();
            parent = rest.to_string();
            prefix = p_str;
        }
    }
    if prefix.is_empty()
        || parent.is_empty()
        || prefix.contains('/')
        || prefix.contains("..")
        || parent.contains('/')
        || parent.contains("..")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid subdomain or parent domain." })),
        )
            .into_response();
    }

    let full_domain = format!("{}.{}", prefix, parent);
    let root_path = format!("/www/wwwroot/{}", full_domain);
    let _ = fs::create_dir_all(&root_path);

    let mut language = req.language.trim().to_string();
    let mut framework = req.framework.trim().to_string();
    let mut php_ver_override: Option<String> = None;
    let mut detected: Option<Value> = None;
    match try_git_import(&root_path, req.git_url.as_deref()).await {
        Ok(Some(det)) => {
            language = det["language"].as_str().unwrap_or("static").to_string();
            framework = det["framework"].as_str().unwrap_or("blank").to_string();
            php_ver_override = det["php_version"].as_str().filter(|v| !v.is_empty()).map(|v| v.to_string());
            detected = Some(det);
        }
        Ok(None) => provision_framework(&root_path, &framework, &full_domain),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": e })),
            )
                .into_response();
        }
    }

    let index_file = FsPath::new(&root_path).join("index.html");
    let index_php = FsPath::new(&root_path).join("index.php");
    let pub_php = FsPath::new(&root_path).join("public").join("index.php");
    if !index_file.exists() && !index_php.exists() && !pub_php.exists() {
        let _ = fs::write(&index_file, render_default_welcome_html(&full_domain));
    }

    let site_type = match language.as_str() {
        "php" => "php",
        "rust" | "python" | "node" | "java" => "proxy",
        _ => "static",
    };
    let proxy_port = if site_type == "proxy" {
        allocate_proxy_port(&state.db, req.proxy_port)
    } else {
        req.proxy_port.unwrap_or(0)
    };
    let php_ver = php_ver_override.or(req.php_version).unwrap_or_else(|| "8.3".to_string());
    if site_type == "php" {
        ensure_php_fpm_installed(&php_ver);
        engine::ensure_php_extensions(&php_ver);
    }
    let web_root = if pub_php.exists() { format!("{}/public", root_path) } else { root_path.clone() };
    provision_webserver_site(&full_domain, site_type, &web_root, proxy_port, &php_ver);
    let (app_service, app_building) = if site_type == "proxy" {
        provision_proxy_app(&full_domain, &root_path, language.as_str(), framework.as_str(), proxy_port)
    } else {
        (None, false)
    };
    let ftp_info = if req.create_ssh.unwrap_or(false) {
        Some(provision_sftp_user(&full_domain, &root_path, req.ftp_user.as_deref(), req.ftp_pass.as_deref()))
    } else {
        None
    };
    let db_info = if req.create_db.unwrap_or(false) {
        Some(provision_database(&full_domain, req.db_name.as_deref(), req.db_user.as_deref(), req.db_pass.as_deref()))
    } else {
        None
    };

    match state
        .db
        .create_site(&full_domain, site_type, &root_path, proxy_port, &php_ver)
    {
        Ok(id) => {
            let fu = ftp_info.as_ref().and_then(|v| v.get("user")).and_then(|v| v.as_str()).unwrap_or("");
            let fp = ftp_info.as_ref().and_then(|v| v.get("password")).and_then(|v| v.as_str()).unwrap_or("");
            let dn = db_info.as_ref().and_then(|v| v.get("db_name")).and_then(|v| v.as_str()).unwrap_or("");
            let du = db_info.as_ref().and_then(|v| v.get("db_user")).and_then(|v| v.as_str()).unwrap_or("");
            let dp = db_info.as_ref().and_then(|v| v.get("db_pass")).and_then(|v| v.as_str()).unwrap_or("");
            if !fu.is_empty() || !dn.is_empty() {
                let _ = state.db.update_site_credentials(id, fu, fp, dn, du, dp);
            }
            let mut ssl_enabled = false;
            let mut ssl_error: Option<String> = None;
            if req.issue_ssl.unwrap_or(false) && cfg!(unix) {
                match run_certbot_auto(&full_domain) {
                    Ok(()) => {
                        let _ = state.db.update_site_ssl(id, true);
                        ssl_enabled = true;
                    }
                    Err(e) => {
                        ssl_error = Some(e);
                    }
                }
            }
            if let Some(svc) = app_service.clone() {
                spawn_health_watch(state.clone(), full_domain.clone(), proxy_port, svc, false);
            }
            state.db.log_audit(
                "admin",
                "CREATE_SUBDOMAIN",
                &full_domain,
                &format!("lang={}, fw={}, port={}", language, framework, proxy_port),
            );
            Json(json!({
                "success": true,
                "id": id,
                "domain": full_domain,
                "root_path": root_path,
                "proxy_port": proxy_port,
                "app_service": app_service,
                "app_building": app_building,
                "ssl_enabled": ssl_enabled,
                "ssl_error": ssl_error,
                "ftp_info": ftp_info,
                "db_info": db_info,
                "detected": detected
            }))
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn try_git_import(root_path: &str, git_url: Option<&str>) -> Result<Option<Value>, String> {
    let Some(url) = git_url.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    let (u, rp) = (url.to_string(), root_path.to_string());
    let det = tokio::task::spawn_blocking(move || engine::import_git(&rp, &u))
        .await
        .map_err(|e| e.to_string())??;
    if det["site_type"] == "php" && cfg!(unix) {
        let rp2 = root_path.to_string();
        let tag = det["framework"].as_str().unwrap_or("php").to_string();
        let _ = tokio::task::spawn_blocking(move || engine::setup_php_project(&rp2, &tag)).await;
    }
    Ok(Some(det))
}

#[derive(Deserialize)]
struct DetectReq {
    git_url: String,
}

async fn handle_detect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DetectReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let url = req.git_url.trim().to_string();
    match tokio::task::spawn_blocking(move || engine::detect_remote(&url)).await {
        Ok(Ok(det)) => Json(json!({ "success": true, "detected": det })).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": e }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn svc_active_ts(svc: &str) -> String {
    Command::new("systemctl")
        .args(["show", "-p", "ActiveEnterTimestampMonotonic", "--value", svc])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn spawn_health_watch(state: Arc<AppState>, domain: String, port: i64, svc: String, wait_restart: bool) {
    if !cfg!(unix) || port <= 0 {
        return;
    }
    tokio::spawn(async move {
        let mut elapsed: u64 = 0;
        let ts0 = if wait_restart { svc_active_ts(&svc) } else { String::new() };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            elapsed += 5;
            if wait_restart && elapsed < 1200 && svc_active_ts(&svc) == ts0 {
                // 새 빌드가 끝나 서비스가 재시작될 때까지 기존 앱은 그대로 서비스 중
                continue;
            }
            let (p, d) = (port, domain.clone());
            let code = tokio::task::spawn_blocking(move || engine::probe_http(p, &d))
                .await
                .ok()
                .flatten();
            if let Some(c) = code.filter(|c| *c < 500) {
                state.db.log_audit("system", "HEALTHCHECK_OK", &domain, &format!("http={} after {}s", c, elapsed));
                return;
            }
            let svc_c = svc.clone();
            let st = tokio::task::spawn_blocking(move || {
                Command::new("systemctl")
                    .args(["is-active", &svc_c])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            if st == "failed" || elapsed >= 1200 {
                let svc_c = svc.clone();
                let tail = tokio::task::spawn_blocking(move || engine::journal_tail(&svc_c)).await.unwrap_or_default();
                state.db.log_audit(
                    "system",
                    "HEALTHCHECK_FAIL",
                    &domain,
                    &format!("service={} after {}s :: {}", st, elapsed, tail),
                );
                return;
            }
        }
    });
}

async fn handle_site_git_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Ok(Some(site)) = state.db.get_site(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response();
    };
    let root = site.root_path.clone();
    let info = tokio::task::spawn_blocking(move || engine::git_info(&root)).await.ok().flatten();
    match info {
        Some(i) => Json(json!({ "success": true, "has_git": true, "git": i })).into_response(),
        None => Json(json!({ "success": true, "has_git": false })).into_response(),
    }
}

async fn handle_site_git_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Ok(Some(site)) = state.db.get_site(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response();
    };
    let root = site.root_path.clone();
    if !FsPath::new(&root).join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "This site was not installed from Git." })),
        )
            .into_response();
    }
    let rp = root.clone();
    let res = tokio::task::spawn_blocking(move || engine::git_update(&rp)).await;
    let upd = match res {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": e }))).into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let mut deployed = "none";
    if upd["changed"] == true && cfg!(unix) {
        let det = engine::detect_project(FsPath::new(&root));
        let fw = det["framework"].as_str().unwrap_or("blank").to_string();
        let lang = det["language"].as_str().unwrap_or("static").to_string();
        if site.site_type == "php" {
            let rp = root.clone();
            let tag = fw.clone();
            let _ = tokio::task::spawn_blocking(move || engine::setup_php_project(&rp, &tag)).await;
            deployed = "php";
        } else if site.site_type == "proxy" {
            if lang == "rust" {
                let bin = if fw == "crust" { "rust_board".to_string() } else { engine::cargo_bin_name(&root).unwrap_or_default() };
                if !bin.is_empty() {
                    let _ = fs::remove_file(FsPath::new(&root).join("target/release").join(bin));
                }
            }
            let (service, _building) = provision_proxy_app(&site.domain, &root, &lang, &fw, site.proxy_port);
            if let Some(svc) = service {
                spawn_health_watch(state.clone(), site.domain.clone(), site.proxy_port, svc, true);
            }
            deployed = "proxy";
        }
    }
    state.db.log_audit(
        "admin",
        "GIT_UPDATE",
        &site.domain,
        &format!("{} -> {} (changed={})", upd["old"].as_str().unwrap_or(""), upd["new"].as_str().unwrap_or(""), upd["changed"]),
    );
    Json(json!({ "success": true, "update": upd, "deployed": deployed })).into_response()
}

async fn handle_dashboard_sites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let sites = state.db.list_sites().unwrap_or_default();
    let apps = state.db.list_apps().unwrap_or_default();
    let handles: Vec<_> = sites
        .into_iter()
        .map(|s| {
            std::thread::spawn(move || {
                let (code, service) = if s.site_type == "proxy" {
                    let svc = app_service_name(&s.domain);
                    let st = if cfg!(unix) {
                        Command::new("systemctl")
                            .args(["is-active", &svc])
                            .output()
                            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    (engine::probe_http(s.proxy_port, &s.domain), st)
                } else {
                    (engine::probe_http(80, &s.domain), String::new())
                };
                let status = match (code, service.as_str()) {
                    (Some(c), _) if c < 500 => "healthy",
                    (Some(_), _) => "error",
                    (None, "active") | (None, "activating") => "starting",
                    _ => "down",
                };
                json!({
                    "id": s.id, "domain": s.domain, "type": s.site_type,
                    "port": if s.site_type == "proxy" { s.proxy_port } else { 0 },
                    "ssl": s.ssl_enabled, "status": status, "http": code
                })
            })
        })
        .collect();
    let mut out: Vec<Value> = Vec::new();
    for h in handles {
        if let Ok(v) = h.join() {
            out.push(v);
        }
    }
    let app_list: Vec<Value> = apps
        .into_iter()
        .map(|a| json!({ "id": a.id, "name": a.name, "language": a.language, "port": a.port, "status": a.status }))
        .collect();
    Json(json!({ "success": true, "sites": out, "apps": app_list })).into_response()
}

#[derive(Deserialize)]
struct AlertSettingsReq {
    enabled: bool,
    webhook_url: String,
    telegram_token: String,
    telegram_chat: String,
}

async fn handle_alerts_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let tok = state.db.get_setting("alert_tg_token", "");
    Json(json!({
        "success": true,
        "enabled": state.db.get_setting("alert_enabled", "0") == "1",
        "webhook_url": state.db.get_setting("alert_webhook_url", ""),
        "telegram_token": if tok.is_empty() { "".to_string() } else { "********".to_string() },
        "telegram_chat": state.db.get_setting("alert_tg_chat", "")
    }))
    .into_response()
}

async fn handle_alerts_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AlertSettingsReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": m }))).into_response();
    let url = req.webhook_url.trim().to_string();
    if !url.is_empty() && !ops::valid_http_url(&url) {
        return bad("Invalid webhook URL (http:// or https:// only).");
    }
    let mut token = req.telegram_token.trim().to_string();
    if token == "********" {
        token = state.db.get_setting("alert_tg_token", "");
    }
    if !token.is_empty() && !ops::valid_tg_token(&token) {
        return bad("Invalid Telegram bot token.");
    }
    let chat = req.telegram_chat.trim().to_string();
    if !chat.is_empty() && !ops::valid_tg_chat(&chat) {
        return bad("Invalid Telegram chat id.");
    }
    let _ = state.db.set_setting("alert_enabled", if req.enabled { "1" } else { "0" });
    let _ = state.db.set_setting("alert_webhook_url", &url);
    let _ = state.db.set_setting("alert_tg_token", &token);
    let _ = state.db.set_setting("alert_tg_chat", &chat);
    state.db.log_audit("admin", "ALERT_SETTINGS", "panel", &format!("enabled={}", req.enabled));
    Json(json!({ "success": true })).into_response()
}

async fn handle_alerts_test(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let (w, t, c) = (
        state.db.get_setting("alert_webhook_url", ""),
        state.db.get_setting("alert_tg_token", ""),
        state.db.get_setting("alert_tg_chat", ""),
    );
    let host = System::host_name().unwrap_or_else(|| "server".into());
    let res = tokio::task::spawn_blocking(move || ops::send_alert(&w, &t, &c, &format!("✅ [CHost] Test alert from {}", host)))
        .await
        .unwrap_or_default();
    let ok = res.iter().any(|r| r.ends_with(":ok"));
    Json(json!({ "success": ok, "results": res })).into_response()
}

struct AlertCheck {
    key: String,
    bad: Option<bool>,
    bad_text: String,
    ok_text: String,
    need: u32,
}

fn collect_alert_checks(db: &Database, check_ssl: bool) -> Vec<AlertCheck> {
    let host = System::host_name().unwrap_or_else(|| "server".into());
    let mut out: Vec<AlertCheck> = Vec::new();
    // disk
    let disks = Disks::new_with_refreshed_list();
    let (mut total, mut avail) = (0u64, 0u64);
    for d in disks.list() {
        total += d.total_space();
        avail += d.available_space();
    }
    if total > 0 {
        let pct = (total.saturating_sub(avail)) as f64 / total as f64 * 100.0;
        out.push(AlertCheck {
            key: "disk".into(),
            bad: Some(pct >= 90.0),
            bad_text: format!("🚨 [CHost:{}] Disk usage is {:.1}% (>= 90%)", host, pct),
            ok_text: format!("✅ [CHost:{}] Disk usage is back to {:.1}%", host, pct),
            need: 2,
        });
    }
    for s in db.list_sites().unwrap_or_default() {
        let (code, svc_state) = if s.site_type == "proxy" {
            let svc = app_service_name(&s.domain);
            let st = Command::new("systemctl")
                .args(["is-active", &svc])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            (engine::probe_http(s.proxy_port, &s.domain), st)
        } else {
            (engine::probe_http(80, &s.domain), String::new())
        };
        let bad = match (code, svc_state.as_str()) {
            (Some(c), _) if c < 500 => Some(false),
            (None, "activating") => None,
            _ => Some(true),
        };
        out.push(AlertCheck {
            key: format!("site:{}", s.domain),
            bad,
            bad_text: format!("🚨 [CHost:{}] Site DOWN: {} (http={:?}, service={})", host, s.domain, code, svc_state),
            ok_text: format!("✅ [CHost:{}] Site recovered: {}", host, s.domain),
            need: 2,
        });
        if check_ssl && s.ssl_enabled {
            if let Some(days) = ops::cert_days_left(&s.domain) {
                out.push(AlertCheck {
                    key: format!("ssl:{}", s.domain),
                    bad: Some(days <= 14),
                    bad_text: format!("⚠️ [CHost:{}] SSL certificate of {} expires in {} days", host, s.domain, days),
                    ok_text: format!("✅ [CHost:{}] SSL certificate of {} renewed ({} days left)", host, s.domain, days),
                    need: 1,
                });
            }
        }
    }
    out
}

fn spawn_alert_monitor(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut seen: std::collections::HashMap<String, (u32, bool)> = std::collections::HashMap::new();
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            tick += 1;
            if state.db.get_setting("alert_enabled", "0") != "1" {
                continue;
            }
            let st = state.clone();
            let check_ssl = tick % 60 == 1;
            let checks = tokio::task::spawn_blocking(move || collect_alert_checks(&st.db, check_ssl))
                .await
                .unwrap_or_default();
            let (w, t, c) = (
                state.db.get_setting("alert_webhook_url", ""),
                state.db.get_setting("alert_tg_token", ""),
                state.db.get_setting("alert_tg_chat", ""),
            );
            for ck in checks {
                let Some(bad) = ck.bad else { continue };
                let e = seen.entry(ck.key.clone()).or_insert((0, false));
                let mut msg: Option<String> = None;
                if bad {
                    e.0 += 1;
                    if e.0 >= ck.need && !e.1 {
                        e.1 = true;
                        msg = Some(ck.bad_text.clone());
                    }
                } else {
                    if e.1 {
                        msg = Some(ck.ok_text.clone());
                    }
                    *e = (0, false);
                }
                if let Some(m) = msg {
                    let (w2, t2, c2, key) = (w.clone(), t.clone(), c.clone(), ck.key.clone());
                    let m2 = m.clone();
                    let res = tokio::task::spawn_blocking(move || ops::send_alert(&w2, &t2, &c2, &m2)).await.unwrap_or_default();
                    state.db.log_audit("system", if bad { "ALERT_SENT" } else { "ALERT_RECOVERED" }, &key, &format!("{} :: {}", m, res.join(",")));
                }
            }
        }
    });
}

async fn handle_firewall_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let st = tokio::task::spawn_blocking(ops::ufw_status).await.unwrap_or(json!({}));
    Json(json!({ "success": true, "ufw": st })).into_response()
}

#[derive(Deserialize)]
struct FirewallReq {
    enable: bool,
}

async fn handle_firewall_apply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FirewallReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let panel_port: u16 = std::env::var("CHOST_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8800);
    let enable = req.enable;
    let res = tokio::task::spawn_blocking(move || if enable { ops::ufw_enable(panel_port) } else { ops::ufw_disable() })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    match res {
        Ok(msg) => {
            state.db.log_audit("admin", if enable { "UFW_ENABLE" } else { "UFW_DISABLE" }, "firewall", &msg);
            Json(json!({ "success": true, "message": msg })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct PhpIniQuery {
    version: String,
}

async fn handle_php_ini_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PhpIniQuery>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    if !ops::valid_php_version(&q.version) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": "Invalid PHP version." }))).into_response();
    }
    let v = q.version.clone();
    let info = tokio::task::spawn_blocking(move || ops::php_ini_get(&v)).await.unwrap_or(json!({}));
    Json(json!({ "success": true, "ini": info })).into_response()
}

#[derive(Deserialize)]
struct PhpIniReq {
    version: String,
    upload_max_filesize: String,
    post_max_size: String,
    memory_limit: String,
    max_execution_time: String,
}

async fn handle_php_ini_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PhpIniReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": m }))).into_response();
    if !ops::valid_php_version(&req.version) {
        return bad("Invalid PHP version.");
    }
    let vals = vec![
        ("upload_max_filesize".to_string(), req.upload_max_filesize.trim().to_string()),
        ("post_max_size".to_string(), req.post_max_size.trim().to_string()),
        ("memory_limit".to_string(), req.memory_limit.trim().to_string()),
        ("max_execution_time".to_string(), req.max_execution_time.trim().to_string()),
    ];
    for (k, v) in &vals {
        if !ops::valid_ini_value(k, v) {
            return bad(&format!("Invalid value for {} (e.g. 64M / 300).", k));
        }
    }
    let ver = req.version.clone();
    let res = tokio::task::spawn_blocking(move || ops::php_ini_set(&ver, &vals)).await.unwrap_or_else(|e| Err(e.to_string()));
    match res {
        Ok(()) => {
            state.db.log_audit("admin", "PHP_INI", &format!("php{}", req.version), "core options updated");
            Json(json!({ "success": true })).into_response()
        }
        Err(e) => bad(&e),
    }
}

async fn handle_site_health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Ok(Some(site)) = state.db.get_site(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response();
    };
    if site.site_type != "proxy" {
        return Json(json!({ "success": true, "applicable": false })).into_response();
    }
    let svc = app_service_name(&site.domain);
    let service = if cfg!(unix) {
        Command::new("systemctl")
            .args(["is-active", &svc])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let (port, host) = (site.proxy_port, site.domain.clone());
    let code = tokio::task::spawn_blocking(move || engine::probe_http(port, &host))
        .await
        .ok()
        .flatten();
    let status = match (code, service.as_str()) {
        (Some(c), _) if c < 500 => "healthy",
        (Some(_), _) => "error",
        (None, "active") | (None, "activating") => "starting",
        _ => "down",
    };
    Json(json!({
        "success": true,
        "applicable": true,
        "status": status,
        "http_status": code,
        "service": service,
        "port": port
    }))
    .into_response()
}

async fn handle_switch_site_php(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<SwitchPhpReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let ver = req.php_version.trim();
    if let Ok(Some(site)) = state.db.get_site(id) {
        if cfg!(unix) {
            let ws = detect_active_webserver();
            let conf_path = if ws == "apache2" {
                format!("/etc/apache2/sites-available/{}.conf", site.domain)
            } else {
                format!("/etc/nginx/sites-available/{}.conf", site.domain)
            };
            if let Ok(txt) = fs::read_to_string(&conf_path) {
                let mut updated = txt;
                for v in ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"] {
                    updated = updated.replace(&format!("php{}-fpm.sock", v), &format!("php{}-fpm.sock", ver));
                }
                let _ = fs::write(&conf_path, updated);
                let _ = reload_active_webserver(ws);
            }
        }
    }
    let _ = state.db.update_site_php(id, ver);
    state.db.log_audit(
        "admin",
        "SWITCH_PHP",
        &format!("site:{}", id),
        &format!("php={}", ver),
    );
    Json(json!({ "success": true })).into_response()
}

async fn handle_issue_ssl(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let sites = state.db.list_sites().unwrap_or_default();
    let Some(site) = sites.into_iter().find(|s| s.id == id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response();
    };
    if cfg!(unix) {
        if let Err(err) = run_certbot_auto(&site.domain) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": err })),
            )
                .into_response();
        }
    }
    let _ = state.db.update_site_ssl(id, true);
    state.db.log_audit("admin", "ISSUE_SSL", &site.domain, "SSL enabled");
    Json(json!({ "success": true })).into_response()
}

#[derive(Deserialize, Default)]
struct DeleteSiteQuery {
    del_ftp: Option<bool>,
    del_db: Option<bool>,
    del_files: Option<bool>,
}

async fn handle_delete_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<DeleteSiteQuery>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let site = state.db.get_site(id).ok().flatten();
    if let Some(ref s) = site {
        if cfg!(unix) {
            let _ = fs::remove_file(format!("/etc/nginx/sites-enabled/{}.conf", s.domain));
            let _ = fs::remove_file(format!("/etc/nginx/sites-available/{}.conf", s.domain));
            let _ = Command::new("a2dissite").arg(format!("{}.conf", s.domain)).output();
            let _ = Command::new("a2dissite").arg(format!("{}-le-ssl.conf", s.domain)).output();
            let _ = fs::remove_file(format!("/etc/apache2/sites-available/{}.conf", s.domain));
            let _ = fs::remove_file(format!("/etc/apache2/sites-available/{}-le-ssl.conf", s.domain));
            let _ = reload_active_webserver(detect_active_webserver());

            // 이 사이트 전용 Let's Encrypt 인증서도 정리 (남겨두면 갱신 실패 알림의 원인이 됨)
            if s.ssl_enabled
                && !s.domain.contains('/')
                && !s.domain.contains("..")
                && FsPath::new(&format!("/etc/letsencrypt/live/{}", s.domain)).exists()
            {
                let _ = Command::new("certbot")
                    .args(["delete", "--cert-name", &s.domain, "--non-interactive"])
                    .output();
            }

            let app_svc = app_service_name(&s.domain);
            let app_unit = format!("/etc/systemd/system/{}", app_svc);
            if FsPath::new(&app_unit).exists() {
                let _ = Command::new("systemctl").args(["disable", "--now", &app_svc]).output();
                let _ = fs::remove_file(&app_unit);
                let _ = Command::new("systemctl").arg("daemon-reload").output();
            }

            if q.del_ftp.unwrap_or(false) {
                let safe_fu = sanitize_ident(Some(&s.ftp_user), 24);
                if !safe_fu.is_empty() {
                    let _ = Command::new("userdel").arg(&safe_fu).output();
                }
            }
            if q.del_db.unwrap_or(false) {
                let safe_dn = sanitize_ident(Some(&s.db_name), 32);
                let safe_du = sanitize_ident(Some(&s.db_user), 24);
                if !safe_dn.is_empty() || !safe_du.is_empty() {
                    let mut sql = String::new();
                    if !safe_dn.is_empty() {
                        sql.push_str(&format!("DROP DATABASE IF EXISTS `{}`; ", safe_dn));
                    }
                    if !safe_du.is_empty() {
                        sql.push_str(&format!("DROP USER IF EXISTS '{}'@'localhost'; ", safe_du));
                    }
                    sql.push_str("FLUSH PRIVILEGES;");
                    let _ = Command::new("mysql").args(["-e", &sql]).output();
                }
            }
            if q.del_files.unwrap_or(false) && s.root_path.starts_with("/www/wwwroot/") && s.root_path.len() > 14 {
                let _ = fs::remove_dir_all(&s.root_path);
            }
        }
        state.db.log_audit(
            "admin",
            "DELETE_SITE",
            &s.domain,
            &format!(
                "ftp={}, db={}, files={}",
                q.del_ftp.unwrap_or(false),
                q.del_db.unwrap_or(false),
                q.del_files.unwrap_or(false)
            ),
        );
    }
    let _ = state.db.delete_site(id);
    Json(json!({ "success": true })).into_response()
}

fn cmd_exists(bin: &str) -> bool {
    if !cfg!(unix) {
        return false;
    }
    Command::new("sh")
        .args([
            "-c",
            &format!(
                "export PATH=\"/root/.cargo/bin:$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH\"; command -v {} >/dev/null 2>&1",
                bin
            ),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn handle_runtimes_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let setup_completed = state.db.get_setting("setup_completed", "0") == "1";
    let nginx_active = service_is_active("nginx");
    let apache_active = service_is_active("apache2");
    let items = json!([
        { "id": "nginx", "name": "Nginx", "category": "web", "desc": "고성능 웹서버 & 리버스 프록시 (권장)", "installed": nginx_active, "binary_present": cmd_exists("nginx"), "active": nginx_active },
        { "id": "apache2", "name": "Apache2", "category": "web", "desc": ".htaccess 호환 전통 웹서버", "installed": apache_active, "binary_present": cmd_exists("apache2"), "active": apache_active },
        { "id": "mariadb", "name": "MariaDB (MySQL)", "category": "db", "desc": "MySQL 호환 관계형 데이터베이스", "installed": cmd_exists("mariadb") || cmd_exists("mysql") },
        { "id": "certbot", "name": "Certbot (SSL)", "category": "web", "desc": "Let's Encrypt 무료 HTTPS 자동발급", "installed": cmd_exists("certbot") },
        { "id": "php8.3", "name": "PHP 8.3", "category": "lang", "desc": "최신 PHP-FPM 런타임 (CBoard/WordPress 권장)", "installed": FsPath::new("/usr/sbin/php-fpm8.3").exists() || cmd_exists("php8.3") },
        { "id": "php8.2", "name": "PHP 8.2", "category": "lang", "desc": "안정화 PHP-FPM 런타임", "installed": FsPath::new("/usr/sbin/php-fpm8.2").exists() || cmd_exists("php8.2") },
        { "id": "php8.4", "name": "PHP 8.4", "category": "lang", "desc": "최신 PHP / 신규 프레임워크", "installed": FsPath::new("/usr/sbin/php-fpm8.4").exists() || cmd_exists("php8.4") },
        { "id": "php8.1", "name": "PHP 8.1", "category": "lang", "desc": "안정 PHP / 호환용", "installed": FsPath::new("/usr/sbin/php-fpm8.1").exists() || cmd_exists("php8.1") },
        { "id": "php7.4", "name": "PHP 7.4", "category": "lang", "desc": "레거시 그누보드5 / 구형 PHP 호환", "installed": FsPath::new("/usr/sbin/php-fpm7.4").exists() || cmd_exists("php7.4") },
        { "id": "python3", "name": "Python 3 (pip/venv)", "category": "lang", "desc": "FastAPI / Django / Flask 런타임", "installed": cmd_exists("python3") && cmd_exists("pip3") },
        { "id": "node", "name": "Node.js 22 LTS", "category": "lang", "desc": "Next.js / Express / React 런타임", "installed": cmd_exists("node") },
        { "id": "rust", "name": "Rust (cargo)", "category": "lang", "desc": "CRust / 초고속 시스템 웹 런타임", "installed": FsPath::new("/root/.cargo/bin/cargo").exists() || cmd_exists("cargo") },
        { "id": "java", "name": "OpenJDK 21 LTS", "category": "lang", "desc": "Spring Boot / Java 런타임", "installed": cmd_exists("java") }
    ]);
    Json(json!({
        "success": true,
        "setup_completed": setup_completed,
        "running": state.install_running.load(Ordering::SeqCst),
        "items": items
    }))
    .into_response()
}

async fn handle_runtimes_log(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let log_path = state.data_dir.join("install.log");
    let log = fs::read_to_string(&log_path).unwrap_or_default();
    Json(json!({
        "success": true,
        "running": state.install_running.load(Ordering::SeqCst),
        "log": log
    }))
    .into_response()
}

async fn handle_runtimes_skip_setup(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let _ = state.db.set_setting("setup_completed", "1");
    Json(json!({ "success": true })).into_response()
}

async fn handle_runtimes_install(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<InstallRuntimesReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    if req.items.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "설치할 패키지를 하나 이상 선택해 주세요." })),
        )
            .into_response();
    }
    if state.install_running.swap(true, Ordering::SeqCst) {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "success": false, "error": "이미 패키지 설치가 진행 중입니다." })),
        )
            .into_response();
    }

    let items = req.items.clone();
    let log_path = state.data_dir.join("install.log");
    let _ = fs::write(&log_path, format!("=== CHost Runtime Installer Started ({}) ===\nSelected: {}\n\n", Utc::now().format("%Y-%m-%d %H:%M:%S"), items.join(", ")));
    state.db.log_audit("admin", "RUNTIME_INSTALL", "runtimes", &items.join(","));

    let st = state.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let append = |msg: &str| {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                let _ = writeln!(f, "{}", msg);
            }
        };

        if cfg!(unix) {
            let run_step = |label: &str, cmd: &str| {
                append(&format!("\n>>> [{}] 설치 중...", label));
                match Command::new("bash").args(["-c", cmd]).output() {
                    Ok(o) => {
                        let out = String::from_utf8_lossy(&o.stdout);
                        let err = String::from_utf8_lossy(&o.stderr);
                        let tail_out: Vec<&str> = out.lines().rev().take(12).collect();
                        for l in tail_out.into_iter().rev() {
                            append(l);
                        }
                        if !o.status.success() {
                            let tail_err: Vec<&str> = err.lines().rev().take(12).collect();
                            for l in tail_err.into_iter().rev() {
                                append(&format!("[ERR] {}", l));
                            }
                            append(&format!(">>> [{}] 실패 (code: {:?})", label, o.status.code()));
                        } else {
                            append(&format!(">>> [{}] 완료!", label));
                        }
                    }
                    Err(e) => append(&format!(">>> [{}] 실행 오류: {}", label, e)),
                }
            };

            run_step("APT Update", "DEBIAN_FRONTEND=noninteractive apt-get update -y");

            let need_php_ppa = items.iter().any(|x| x.starts_with("php"));
            if need_php_ppa {
                run_step(
                    "PHP PPA (ondrej/php)",
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common ca-certificates && (grep -rq 'ondrej/php' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php) && apt-get update -y",
                );
            }

            for item in &items {
                match item.as_str() {
                    "nginx" => run_step("Nginx (80/443)", "systemctl disable --now apache2 2>/dev/null || true; DEBIAN_FRONTEND=noninteractive apt-get install -y nginx && systemctl enable --now nginx"),
                    "apache2" => run_step("Apache2 (80/443)", "systemctl disable --now nginx 2>/dev/null || true; DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 && a2enmod rewrite proxy proxy_http proxy_fcgi setenvif ssl && systemctl enable --now apache2"),
                    "mariadb" => run_step("MariaDB", "DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && systemctl enable --now mariadb"),
                    "certbot" => run_step("Certbot", "DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx python3-certbot-apache && (if systemctl is-active --quiet apache2 && ! systemctl is-active --quiet nginx; then systemctl disable --now nginx 2>/dev/null || true; else systemctl disable --now apache2 2>/dev/null || true; fi)"),
                    "php8.3" => run_step("PHP 8.3", "DEBIAN_FRONTEND=noninteractive apt-get install -y php8.3-fpm php8.3-mysql php8.3-mbstring php8.3-xml php8.3-curl php8.3-zip php8.3-gd && systemctl enable --now php8.3-fpm && (systemctl is-enabled --quiet nginx 2>/dev/null && systemctl disable --now apache2 2>/dev/null || true)"),
                    "php8.4" => run_step("PHP 8.4", "DEBIAN_FRONTEND=noninteractive apt-get install -y php8.4-fpm php8.4-mysql php8.4-mbstring php8.4-xml php8.4-curl php8.4-zip php8.4-gd && systemctl enable --now php8.4-fpm && (systemctl is-enabled --quiet nginx 2>/dev/null && systemctl disable --now apache2 2>/dev/null || true)"),
                    "php8.1" => run_step("PHP 8.1", "DEBIAN_FRONTEND=noninteractive apt-get install -y php8.1-fpm php8.1-mysql php8.1-mbstring php8.1-xml php8.1-curl php8.1-zip php8.1-gd && systemctl enable --now php8.1-fpm && (systemctl is-enabled --quiet nginx 2>/dev/null && systemctl disable --now apache2 2>/dev/null || true)"),
                    "php8.2" => run_step("PHP 8.2", "DEBIAN_FRONTEND=noninteractive apt-get install -y php8.2-fpm php8.2-mysql php8.2-mbstring php8.2-xml php8.2-curl php8.2-zip php8.2-gd && systemctl enable --now php8.2-fpm && (systemctl is-enabled --quiet nginx 2>/dev/null && systemctl disable --now apache2 2>/dev/null || true)"),
                    "php7.4" => run_step("PHP 7.4", "DEBIAN_FRONTEND=noninteractive apt-get install -y php7.4-fpm php7.4-mysql php7.4-mbstring php7.4-xml php7.4-curl php7.4-zip php7.4-gd && systemctl enable --now php7.4-fpm && (systemctl is-enabled --quiet nginx 2>/dev/null && systemctl disable --now apache2 2>/dev/null || true)"),
                    "python3" => run_step("Python 3", "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv"),
                    "node" => run_step("Node.js 22 LTS", "curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs"),
                    "rust" => run_step("Rust", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"),
                    "java" => run_step("OpenJDK 21", "DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-21-jdk"),
                    _ => {}
                }
            }
            if items.iter().any(|x| x == "nginx" || x == "apache2") {
                append("\n>>> 기존 사이트 설정을 새 웹서버 형식으로 이전합니다...");
                let rep = migrate_sites_to_active_webserver(&st.db);
                append(&format!(">>> 이전 결과: {}", rep));
            }
            append("\n=== 모든 선택 패키지 설치 작업이 종료되었습니다 ===");
        } else {
            append("Non-Unix environment: simulated install complete.");
        }

        let _ = st.db.set_setting("setup_completed", "1");
        st.install_running.store(false, Ordering::SeqCst);
    });

    Json(json!({ "success": true, "started": true })).into_response()
}

async fn handle_php_versions(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let versions = ["7.4", "8.1", "8.2", "8.3", "8.4"];
    let items: Vec<Value> = versions
        .iter()
        .map(|v| {
            let sock = format!("/run/php/php{}-fpm.sock", v);
            let bin = format!("/usr/bin/php{}", v);
            let installed = FsPath::new(&sock).exists() || FsPath::new(&bin).exists();
            json!({ "version": v, "installed": installed })
        })
        .collect();
    Json(json!({ "success": true, "versions": items })).into_response()
}

async fn handle_list_apps(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let apps = state.db.list_apps().unwrap_or_default();
    Json(json!({ "success": true, "apps": apps })).into_response()
}

async fn handle_create_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateAppReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    match state.db.create_app(
        req.name.trim(),
        req.language.trim(),
        req.work_dir.trim(),
        req.exec_cmd.trim(),
        req.port.unwrap_or(0),
    ) {
        Ok(id) => {
            state
                .db
                .log_audit("admin", "CREATE_APP", req.name.trim(), req.language.trim());
            Json(json!({ "success": true, "id": id })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn handle_app_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<AppActionReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let new_status = match req.action.as_str() {
        "start" | "restart" => "running",
        "stop" => "stopped",
        _ => "stopped",
    };
    let _ = state.db.update_app_status(id, new_status);
    state.db.log_audit(
        "admin",
        "APP_ACTION",
        &format!("app:{}", id),
        &req.action,
    );
    Json(json!({ "success": true, "status": new_status })).into_response()
}

async fn handle_delete_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let _ = state.db.delete_app(id);
    Json(json!({ "success": true })).into_response()
}

async fn handle_sqlite_tables(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<QueryPath>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let db_path = q.path.unwrap_or_else(|| {
        state.data_dir.join("chost.db").to_string_lossy().to_string()
    });
    let Ok(conn) = Connection::open(&db_path) else {
        return Json(json!({ "success": false, "error": "Cannot open SQLite database." })).into_response();
    };
    let Ok(mut stmt) = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name") else {
        return Json(json!({ "success": false, "error": "Failed to query tables." })).into_response();
    };
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default();
    Json(json!({ "success": true, "db_path": db_path, "tables": tables })).into_response()
}

async fn handle_sqlite_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SqliteQueryReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Ok(conn) = Connection::open(req.db_path.trim()) else {
        return Json(json!({ "success": false, "error": "Cannot open SQLite file." })).into_response();
    };
    let sql = req.sql.trim();
    if sql.to_lowercase().starts_with("select") || sql.to_lowercase().starts_with("pragma") {
        let Ok(mut stmt) = conn.prepare(sql) else {
            return Json(json!({ "success": false, "error": "Invalid SQL." })).into_response();
        };
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let col_cnt = cols.len();
        let rows_res = stmt.query_map([], |r| {
            let mut vals = Vec::with_capacity(col_cnt);
            for i in 0..col_cnt {
                let v = r.get_ref(i)?;
                let s = match v {
                    rusqlite::types::ValueRef::Null => "NULL".to_string(),
                    rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                    rusqlite::types::ValueRef::Real(f) => f.to_string(),
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                    rusqlite::types::ValueRef::Blob(b) => format!("<BLOB {} bytes>", b.len()),
                };
                vals.push(s);
            }
            Ok(vals)
        });
        let rows: Vec<Vec<String>> = rows_res
            .map(|it| it.filter_map(Result::ok).take(100).collect())
            .unwrap_or_default();
        Json(json!({ "success": true, "columns": cols, "rows": rows })).into_response()
    } else {
        match conn.execute(sql, []) {
            Ok(n) => {
                state.db.log_audit("admin", "DB_EXEC", req.db_path.trim(), sql);
                Json(json!({ "success": true, "affected": n })).into_response()
            }
            Err(e) => Json(json!({ "success": false, "error": e.to_string() })).into_response(),
        }
    }
}

fn is_protected_path(p: &FsPath) -> bool {
    let s = p.to_string_lossy().to_lowercase();
    s.contains("uploads") || s.ends_with(".db") || s.contains("/var/lib/mysql") || s.contains("chost.db")
}

async fn handle_storage_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<QueryPath>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let days = q.days.unwrap_or(30);
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(days * 86400))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let scan_roots = if cfg!(unix) {
        vec!["/var/log", "/www/wwwlogs", "/tmp"]
    } else {
        vec!["."]
    };

    let mut candidates = Vec::new();
    let mut total_bytes: u64 = 0;

    for root in scan_roots {
        if !FsPath::new(root).exists() {
            continue;
        }
        for entry in WalkDir::new(root).max_depth(3).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let p = entry.path();
            if is_protected_path(p) {
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !(name.ends_with(".log") || name.ends_with(".gz") || name.ends_with(".tmp")) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified < cutoff {
                        total_bytes += meta.len();
                        candidates.push(json!({
                            "path": p.to_string_lossy(),
                            "size_kb": (meta.len() / 1024).max(1)
                        }));
                    }
                }
            }
            if candidates.len() >= 100 {
                break;
            }
        }
    }

    Json(json!({
        "success": true,
        "days": days,
        "total_mb": (total_bytes as f64 / 1048576.0 * 100.0).round() / 100.0,
        "count": candidates.len(),
        "candidates": candidates
    }))
    .into_response()
}

async fn handle_storage_clean(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<StorageCleanReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    if req.preview {
        return Json(json!({ "success": true, "preview": true, "message": "Preview mode completed." })).into_response();
    }
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(req.days * 86400))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let scan_roots = if cfg!(unix) {
        vec!["/var/log", "/www/wwwlogs", "/tmp"]
    } else {
        vec![]
    };
    let mut cleaned_count: usize = 0;
    let mut freed_bytes: u64 = 0;
    for root in scan_roots {
        if !FsPath::new(root).exists() {
            continue;
        }
        for entry in WalkDir::new(root).max_depth(3).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let p = entry.path();
            if is_protected_path(p) {
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !(name.ends_with(".log") || name.ends_with(".gz") || name.ends_with(".tmp")) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified < cutoff {
                        let sz = meta.len();
                        if req.compress && name.ends_with(".log") {
                            if Command::new("gzip").args(["-f", &p.to_string_lossy()]).status().map(|s| s.success()).unwrap_or(false) {
                                cleaned_count += 1;
                                freed_bytes += sz / 2;
                            }
                        } else if fs::remove_file(p).is_ok() {
                            cleaned_count += 1;
                            freed_bytes += sz;
                        }
                    }
                }
            }
        }
    }
    state.db.log_audit(
        "admin",
        "STORAGE_CLEAN",
        "logs",
        &format!("days={}, compress={}, count={}", req.days, req.compress, cleaned_count),
    );
    Json(json!({
        "success": true,
        "preview": false,
        "cleaned_count": cleaned_count,
        "freed_mb": (freed_bytes as f64 / 1048576.0 * 100.0).round() / 100.0,
        "message": format!("Safe log cleanup completed ({} files).", cleaned_count)
    }))
    .into_response()
}

async fn handle_file_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<QueryPath>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let path = q.path.unwrap_or_default();
    match fs::read_to_string(&path) {
        Ok(content) => Json(json!({ "success": true, "path": path, "content": content })).into_response(),
        Err(e) => Json(json!({ "success": false, "error": e.to_string() })).into_response(),
    }
}

async fn handle_file_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FileSaveReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    match fs::write(&req.path, &req.content) {
        Ok(_) => {
            state.db.log_audit("admin", "FILE_SAVE", &req.path, "Saved via panel");
            Json(json!({ "success": true })).into_response()
        }
        Err(e) => Json(json!({ "success": false, "error": e.to_string() })).into_response(),
    }
}

async fn handle_terminal_exec(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TerminalReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let cmd_str = req.cmd.trim();
    if cmd_str.is_empty() {
        return Json(json!({ "success": false, "output": "" })).into_response();
    }
    let output = if cfg!(windows) {
        Command::new("cmd").args(["/C", cmd_str]).output()
    } else {
        Command::new("sh").args(["-c", cmd_str]).output()
    };
    state.db.log_audit("admin", "TERMINAL_CMD", "shell", cmd_str);
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            Json(json!({
                "success": o.status.success(),
                "output": format!("{}{}", stdout, stderr)
            }))
            .into_response()
        }
        Err(e) => Json(json!({ "success": false, "output": e.to_string() })).into_response(),
    }
}

async fn handle_audits(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let logs = state.db.list_audits(100).unwrap_or_default();
    Json(json!({ "success": true, "logs": logs })).into_response()
}

#[derive(Deserialize)]
struct UpdateSiteCredsReq {
    ftp_user: Option<String>,
    ftp_pass: Option<String>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_pass: Option<String>,
    create_ftp: Option<bool>,
    create_db: Option<bool>,
}

async fn handle_update_site_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateSiteCredsReq>,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let site = match state.db.get_site(id) {
        Ok(Some(s)) => s,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "error": "Site not found" })),
            )
                .into_response()
        }
    };

    let mut ftp_user = site.ftp_user.clone();
    let mut ftp_pass = site.ftp_pass.clone();
    let mut db_name = site.db_name.clone();
    let mut db_user = site.db_user.clone();
    let mut db_pass = site.db_pass.clone();

    let req_fu = sanitize_ident(req.ftp_user.as_deref(), 24);
    let req_fp = req.ftp_pass.as_deref().unwrap_or("").trim().to_string();
    if ftp_user.is_empty() && (req.create_ftp.unwrap_or(false) || !req_fu.is_empty()) {
        let info = provision_sftp_user(
            &site.domain,
            &site.root_path,
            if req_fu.is_empty() { None } else { Some(&req_fu) },
            if req_fp.is_empty() { None } else { Some(&req_fp) },
        );
        ftp_user = info.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
        ftp_pass = info.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
    } else if !ftp_user.is_empty() && !req_fp.is_empty() && req_fp != ftp_pass {
        if cfg!(unix) {
            let cmd = format!("echo '{}:{}' | chpasswd", ftp_user, req_fp.replace('\'', ""));
            let _ = Command::new("sh").args(["-c", &cmd]).output();
        }
        ftp_pass = req_fp;
    }

    let req_dn = sanitize_ident(req.db_name.as_deref(), 32);
    let req_du = sanitize_ident(req.db_user.as_deref(), 24);
    let req_dp = req.db_pass.as_deref().unwrap_or("").trim().to_string();
    if (db_name.is_empty() || db_user.is_empty()) && (req.create_db.unwrap_or(false) || !req_dn.is_empty() || !req_du.is_empty()) {
        let info = provision_database(
            &site.domain,
            if req_dn.is_empty() { None } else { Some(&req_dn) },
            if req_du.is_empty() { None } else { Some(&req_du) },
            if req_dp.is_empty() { None } else { Some(&req_dp) },
        );
        if info.get("created").and_then(|v| v.as_bool()).unwrap_or(false) {
            db_name = info.get("db_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            db_user = info.get("db_user").and_then(|v| v.as_str()).unwrap_or("").to_string();
            db_pass = info.get("db_pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": info.get("note").and_then(|v| v.as_str()).unwrap_or("DB 생성 실패") })),
            )
                .into_response();
        }
    } else if !db_user.is_empty() && !req_dp.is_empty() && req_dp != db_pass {
        if cfg!(unix) {
            let sql = format!(
                "ALTER USER '{}'@'localhost' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;",
                db_user,
                req_dp.replace('\'', "")
            );
            let out = Command::new("mysql").args(["-e", &sql]).output();
            if !out.map(|o| o.status.success()).unwrap_or(false) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": "MariaDB 비밀번호 변경 실패" })),
                )
                    .into_response();
            }
        }
        db_pass = req_dp;
    }

    let _ = state.db.update_site_credentials(id, &ftp_user, &ftp_pass, &db_name, &db_user, &db_pass);
    state.db.log_audit("admin", "UPDATE_SITE_CREDS", &site.domain, "Updated FTP/DB credentials");
    let updated = state.db.get_site(id).ok().flatten();
    Json(json!({ "success": true, "site": updated })).into_response()
}

fn dir_size_bytes(path: &str) -> u64 {
    if !cfg!(unix) || !FsPath::new(path).exists() {
        return 0;
    }
    if let Ok(o) = Command::new("du").args(["-sb", path]).output() {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Some(tok) = s.split_whitespace().next() {
                if let Ok(n) = tok.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    0
}

fn mariadb_db_size_bytes(db_name: &str) -> u64 {
    let safe = sanitize_ident(Some(db_name), 32);
    if !cfg!(unix) || safe.is_empty() {
        return 0;
    }
    let sql = format!(
        "SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{}';",
        safe
    );
    if let Ok(o) = Command::new("mysql").args(["-N", "-B", "-e", &sql]).output() {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            return s.parse::<u64>().unwrap_or(0);
        }
    }
    0
}

fn active_site_conf_path(domain: &str) -> (&'static str, String) {
    let ws = detect_active_webserver();
    if ws == "apache2" {
        ("apache2", format!("/etc/apache2/sites-available/{}.conf", domain))
    } else {
        ("nginx", format!("/etc/nginx/sites-available/{}.conf", domain))
    }
}

async fn handle_get_site_conf(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Some(site) = state.db.get_site(id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false, "error": "Site not found" }))).into_response();
    };
    let (ws, conf_path) = active_site_conf_path(&site.domain);
    let content = fs::read_to_string(&conf_path).unwrap_or_default();
    let web_bytes = dir_size_bytes(&site.root_path);
    let db_bytes = mariadb_db_size_bytes(&site.db_name);

    // Parse aliases from server_name / ServerAlias
    let mut aliases: Vec<String> = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if ws == "nginx" && t.starts_with("server_name ") {
            for tok in t.trim_start_matches("server_name ").trim_end_matches(';').split_whitespace() {
                if tok != site.domain && !aliases.contains(&tok.to_string()) {
                    aliases.push(tok.to_string());
                }
            }
        } else if ws == "apache2" && t.starts_with("ServerAlias ") {
            for tok in t.trim_start_matches("ServerAlias ").split_whitespace() {
                if tok != site.domain && !aliases.contains(&tok.to_string()) {
                    aliases.push(tok.to_string());
                }
            }
        }
    }

    let ssl_expiry = if cfg!(unix) && site.ssl_enabled {
        let cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", site.domain);
        if FsPath::new(&cert_path).exists() {
            Command::new("openssl")
                .args(["x509", "-enddate", "-noout", "-in", &cert_path])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace("notAfter=", ""))
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Json(json!({
        "success": true,
        "site": site,
        "webserver": ws,
        "conf_path": conf_path,
        "content": content,
        "aliases": aliases,
        "ssl_expiry": ssl_expiry,
        "web_size_bytes": web_bytes,
        "db_size_bytes": db_bytes
    }))
    .into_response()
}

#[derive(Deserialize)]
struct SaveSiteConfReq {
    content: String,
}

async fn handle_save_site_conf(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<SaveSiteConfReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Some(site) = state.db.get_site(id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false, "error": "Site not found" }))).into_response();
    };
    let (ws, conf_path) = active_site_conf_path(&site.domain);
    let backup = fs::read_to_string(&conf_path).unwrap_or_default();
    if let Err(e) = fs::write(&conf_path, &req.content) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "success": false, "error": e.to_string() }))).into_response();
    }
    if let Err(err) = reload_active_webserver(ws) {
        let _ = fs::write(&conf_path, backup);
        return (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": format!("문법 오류로 자동 복구됨: {}", err) }))).into_response();
    }
    state.db.log_audit("admin", "SAVE_SITE_CONF", &site.domain, &format!("ws={}", ws));
    Json(json!({ "success": true })).into_response()
}

#[derive(Deserialize)]
struct SaveSiteDomainsReq {
    aliases: String,
}

async fn handle_save_site_domains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<SaveSiteDomainsReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Some(site) = state.db.get_site(id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false, "error": "Site not found" }))).into_response();
    };
    let clean_aliases: Vec<String> = req
        .aliases
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && *s != site.domain && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*'))
        .collect();
    let (ws, conf_path) = active_site_conf_path(&site.domain);
    let orig = fs::read_to_string(&conf_path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in orig.lines() {
        let t = line.trim();
        if ws == "nginx" && t.starts_with("server_name ") {
            let joined = if clean_aliases.is_empty() {
                site.domain.clone()
            } else {
                format!("{} {}", site.domain, clean_aliases.join(" "))
            };
            lines.push(format!("    server_name {};", joined));
            replaced = true;
        } else if ws == "apache2" && t.starts_with("ServerAlias ") {
            if !clean_aliases.is_empty() {
                lines.push(format!("    ServerAlias {}", clean_aliases.join(" ")));
            }
            replaced = true;
        } else {
            lines.push(line.to_string());
            if ws == "apache2" && t.starts_with("ServerName ") && !clean_aliases.is_empty() && !orig.contains("ServerAlias ") {
                lines.push(format!("    ServerAlias {}", clean_aliases.join(" ")));
                replaced = true;
            }
        }
    }
    if !replaced {
        return (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": "server_name / ServerName 지시어를 찾을 수 없습니다." }))).into_response();
    }
    let next = lines.join("\n") + "\n";
    let _ = fs::write(&conf_path, &next);
    if let Err(err) = reload_active_webserver(ws) {
        let _ = fs::write(&conf_path, &orig);
        return (StatusCode::BAD_REQUEST, Json(json!({ "success": false, "error": err }))).into_response();
    }
    state.db.log_audit("admin", "UPDATE_SITE_DOMAINS", &site.domain, &clean_aliases.join(","));
    Json(json!({ "success": true, "aliases": clean_aliases })).into_response()
}

#[derive(Deserialize)]
struct SiteLogQuery {
    kind: Option<String>,
    lines: Option<usize>,
}

async fn handle_get_site_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<SiteLogQuery>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Some(site) = state.db.get_site(id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false, "error": "Site not found" }))).into_response();
    };
    let kind = if q.kind.as_deref() == Some("access") { "access" } else { "error" };
    let n = q.lines.unwrap_or(150).clamp(10, 1000);
    let log_path = format!("/www/wwwlogs/{}.{}.log", site.domain, kind);
    let content = if cfg!(unix) && FsPath::new(&log_path).exists() {
        Command::new("tail")
            .args(["-n", &n.to_string(), &log_path])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Json(json!({
        "success": true,
        "log_path": log_path,
        "content": content
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ClearSiteLogReq {
    kind: String,
}

async fn handle_clear_site_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ClearSiteLogReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let Some(site) = state.db.get_site(id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(json!({ "success": false, "error": "Site not found" }))).into_response();
    };
    let kind = if req.kind == "access" { "access" } else { "error" };
    let log_path = format!("/www/wwwlogs/{}.{}.log", site.domain, kind);
    if FsPath::new(&log_path).exists() {
        let _ = fs::write(&log_path, "");
    }
    state.db.log_audit("admin", "CLEAR_SITE_LOG", &site.domain, kind);
    Json(json!({ "success": true })).into_response()
}

async fn handle_mariadb_databases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    if !cfg!(unix) {
        return Json(json!({ "success": true, "databases": [] })).into_response();
    }
    let out = Command::new("mysql").args(["-N", "-B", "-e", "SHOW DATABASES;"]).output();
    let dbs: Vec<String> = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !matches!(s.as_str(), "information_schema" | "performance_schema" | "mysql" | "sys"))
            .collect(),
        _ => Vec::new(),
    };
    Json(json!({ "success": true, "databases": dbs })).into_response()
}

#[derive(Deserialize)]
struct MariaDbQueryParam {
    db: String,
}

async fn handle_mariadb_tables(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<MariaDbQueryParam>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let safe = sanitize_ident(Some(&q.db), 32);
    if safe.is_empty() || !cfg!(unix) {
        return Json(json!({ "success": false, "tables": [] })).into_response();
    }
    let sql = format!("SHOW TABLES FROM `{}`;", safe);
    let out = Command::new("mysql").args(["-N", "-B", "-e", &sql]).output();
    let tables: Vec<String> = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    Json(json!({ "success": true, "tables": tables })).into_response()
}

#[derive(Deserialize)]
struct MariaDbExecReq {
    db: String,
    sql: String,
}

async fn handle_mariadb_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MariaDbExecReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let safe = sanitize_ident(Some(&req.db), 32);
    if safe.is_empty() || req.sql.trim().is_empty() || !cfg!(unix) {
        return Json(json!({ "success": false, "error": "DB 또는 SQL이 비어 있습니다." })).into_response();
    }
    let out = Command::new("mysql").args(["-D", &safe, "-t", "-e", req.sql.trim()]).output();
    state.db.log_audit("admin", "MARIADB_QUERY", &safe, req.sql.trim());
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            Json(json!({
                "success": o.status.success(),
                "output": if stdout.is_empty() { stderr } else { format!("{}{}", stdout, stderr) }
            }))
            .into_response()
        }
        Err(e) => Json(json!({ "success": false, "error": e.to_string() })).into_response(),
    }
}

async fn handle_mariadb_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<MariaDbQueryParam>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let safe = sanitize_ident(Some(&q.db), 32);
    if safe.is_empty() || !cfg!(unix) {
        return (StatusCode::BAD_REQUEST, "Invalid database name").into_response();
    }
    let out = Command::new("mysqldump").arg(&safe).output();
    match out {
        Ok(o) if o.status.success() => {
            state.db.log_audit("admin", "MARIADB_BACKUP", &safe, "SQL dump downloaded");
            let disp = format!("attachment; filename=\"{}.sql\"", safe);
            (
                [
                    (header::CONTENT_TYPE, "application/sql; charset=utf-8".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                o.stdout,
            )
                .into_response()
        }
        Ok(o) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from_utf8_lossy(&o.stderr).to_string(),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_file_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<QueryPath>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let raw = q.path.unwrap_or_else(|| "/www/wwwroot".to_string());
    let dir = if raw.trim().is_empty() { "/www/wwwroot" } else { raw.trim() };
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => return Json(json!({ "success": false, "error": e.to_string() })).into_response(),
    };
    let mut items: Vec<(bool, String, u64)> = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        items.push((is_dir, name, size));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase())));
    let json_items: Vec<Value> = items
        .into_iter()
        .take(200)
        .map(|(is_dir, name, size)| json!({ "name": name, "is_dir": is_dir, "size": size }))
        .collect();
    Json(json!({ "success": true, "path": dir, "items": json_items })).into_response()
}

#[derive(Deserialize)]
struct DeleteSiteCredReq {
    target: String,
}

async fn handle_delete_site_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<DeleteSiteCredReq>,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let site = match state.db.get_site(id) {
        Ok(Some(s)) => s,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "error": "Site not found" })),
            )
                .into_response()
        }
    };

    match req.target.as_str() {
        "ftp" => {
            let safe_fu = sanitize_ident(Some(&site.ftp_user), 24);
            if !safe_fu.is_empty() && cfg!(unix) {
                let _ = Command::new("userdel").arg(&safe_fu).output();
            }
            let _ = state.db.update_site_credentials(
                id,
                "",
                "",
                &site.db_name,
                &site.db_user,
                &site.db_pass,
            );
            state
                .db
                .log_audit("admin", "DELETE_SITE_FTP", &site.domain, &format!("user={}", safe_fu));
        }
        "db" => {
            let safe_dn = sanitize_ident(Some(&site.db_name), 32);
            let safe_du = sanitize_ident(Some(&site.db_user), 24);
            if cfg!(unix) && (!safe_dn.is_empty() || !safe_du.is_empty()) {
                let mut sql = String::new();
                if !safe_dn.is_empty() {
                    sql.push_str(&format!("DROP DATABASE IF EXISTS `{}`; ", safe_dn));
                }
                if !safe_du.is_empty() {
                    sql.push_str(&format!("DROP USER IF EXISTS '{}'@'localhost'; ", safe_du));
                }
                sql.push_str("FLUSH PRIVILEGES;");
                let out = Command::new("mysql").args(["-e", &sql]).output();
                if !out.map(|o| o.status.success()).unwrap_or(false) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": "MariaDB 삭제 실패" })),
                    )
                        .into_response();
                }
            }
            let _ = state.db.update_site_credentials(
                id,
                &site.ftp_user,
                &site.ftp_pass,
                "",
                "",
                "",
            );
            state
                .db
                .log_audit("admin", "DELETE_SITE_DB", &site.domain, &format!("db={}", safe_dn));
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": "Invalid target (expected ftp or db)" })),
            )
                .into_response();
        }
    }

    let updated = state.db.get_site(id).ok().flatten();
    Json(json!({ "success": true, "site": updated })).into_response()
}

#[derive(Deserialize)]
struct PanelResetReq {
    mode: String,
}

async fn handle_panel_reset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PanelResetReq>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let full = req.mode == "full";
    let sites = state.db.list_sites().unwrap_or_default();
    if full && cfg!(unix) {
        for s in &sites {
            let _ = fs::remove_file(format!("/etc/nginx/sites-enabled/{}.conf", s.domain));
            let _ = fs::remove_file(format!("/etc/nginx/sites-available/{}.conf", s.domain));
            let _ = Command::new("a2dissite").arg(format!("{}.conf", s.domain)).output();
            let _ = Command::new("a2dissite").arg(format!("{}-le-ssl.conf", s.domain)).output();
            let _ = fs::remove_file(format!("/etc/apache2/sites-available/{}.conf", s.domain));
            let _ = fs::remove_file(format!("/etc/apache2/sites-available/{}-le-ssl.conf", s.domain));
            let safe_fu = sanitize_ident(Some(&s.ftp_user), 24);
            if !safe_fu.is_empty() {
                let _ = Command::new("userdel").arg(&safe_fu).output();
            }
            let safe_dn = sanitize_ident(Some(&s.db_name), 32);
            let safe_du = sanitize_ident(Some(&s.db_user), 24);
            if !safe_dn.is_empty() || !safe_du.is_empty() {
                let mut sql = String::new();
                if !safe_dn.is_empty() {
                    sql.push_str(&format!("DROP DATABASE IF EXISTS `{}`; ", safe_dn));
                }
                if !safe_du.is_empty() {
                    sql.push_str(&format!("DROP USER IF EXISTS '{}'@'localhost'; ", safe_du));
                }
                sql.push_str("FLUSH PRIVILEGES;");
                let _ = Command::new("mysql").args(["-e", &sql]).output();
            }
            if s.root_path.starts_with("/www/wwwroot/") && s.root_path.len() > 14 {
                let _ = fs::remove_dir_all(&s.root_path);
            }
            let _ = fs::remove_file(format!("/www/wwwlogs/{}.access.log", s.domain));
            let _ = fs::remove_file(format!("/www/wwwlogs/{}.error.log", s.domain));
        }
        let _ = reload_active_webserver(detect_active_webserver());
    }
    for s in &sites {
        let _ = state.db.delete_site(s.id);
    }
    if let Ok(apps) = state.db.list_apps() {
        for a in apps {
            let _ = state.db.delete_app(a.id);
        }
    }
    let _ = state.db.set_setting("setup_completed", "0");
    state.db.log_audit("admin", "PANEL_RESET", "panel", &format!("mode={}", req.mode));
    Json(json!({ "success": true, "mode": req.mode })).into_response()
}

fn parse_ver_tuple(v: &str) -> (u32, u32, u32) {
    let clean = v.trim().trim_start_matches('v');
    let mut parts = clean.split('.').map(|s| s.parse::<u32>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

async fn handle_panel_version(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let current = env!("CARGO_PKG_VERSION").to_string();
    let mut latest = current.clone();
    let mut release_url = "https://github.com/1clickmake/CHost/releases".to_string();
    if let Ok(o) = Command::new("curl")
        .args([
            "-sSL",
            "--max-time",
            "5",
            "-H",
            "User-Agent: CHost-Panel",
            "https://api.github.com/repos/1clickmake/CHost/releases/latest",
        ])
        .output()
    {
        if o.status.success() {
            if let Ok(v) = serde_json::from_slice::<Value>(&o.stdout) {
                if let Some(tag) = v.get("tag_name").and_then(|x| x.as_str()) {
                    latest = tag.trim_start_matches('v').to_string();
                }
                if let Some(u) = v.get("html_url").and_then(|x| x.as_str()) {
                    release_url = u.to_string();
                }
            }
        }
    }
    let update_available = parse_ver_tuple(&latest) > parse_ver_tuple(&current);
    Json(json!({
        "success": true,
        "current": current,
        "latest": latest,
        "update_available": update_available,
        "release_url": release_url
    }))
    .into_response()
}

async fn handle_panel_update(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    if !cfg!(unix) {
        return Json(json!({ "success": false, "error": "Linux server only" })).into_response();
    }
    state.db.log_audit("admin", "PANEL_UPDATE", "panel", "Triggered self-update from GitHub Releases");
    let script = r#"
exec > /tmp/chost_update.log 2>&1
sleep 1
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  TAG="linux-x64" ;;
  aarch64) TAG="linux-arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
URL=$(python3 -c '
import urllib.request, json, sys
tag = sys.argv[1]
req = urllib.request.Request("https://api.github.com/repos/1clickmake/CHost/releases/latest", headers={"User-Agent": "CHost-Updater"})
with urllib.request.urlopen(req, timeout=15) as r:
    data = json.loads(r.read().decode("utf-8"))
for a in data.get("assets", []):
    if tag in a.get("name", ""):
        print(a.get("browser_download_url", ""))
        break
' "$TAG")
echo "Download URL: $URL"
[ -z "$URL" ] && exit 1
rm -rf /tmp/chost_upd && mkdir -p /tmp/chost_upd
curl -fsSL "$URL" -o /tmp/chost_upd/chost.tar.gz || exit 1
tar -xzf /tmp/chost_upd/chost.tar.gz -C /tmp/chost_upd || exit 1
[ -f /tmp/chost_upd/chost ] || exit 1
[ -f /opt/chost/chost ] && cp -f /opt/chost/chost /opt/chost/chost.bak
systemctl stop chost
cp -rf /tmp/chost_upd/chost /opt/chost/chost
[ -d /tmp/chost_upd/panel ] && cp -rf /tmp/chost_upd/panel /opt/chost/
[ -d /tmp/chost_upd/locales ] && cp -rf /tmp/chost_upd/locales /opt/chost/
chmod +x /opt/chost/chost
chown -R chost_ftp:chost_ftp /opt/chost 2>/dev/null || true
systemctl start chost
echo "Update completed!"
"#;
    let unit = format!("chost-upd-{}", chrono::Utc::now().timestamp());
    let _ = Command::new("systemd-run")
        .args(["--unit", &unit, "--collect", "sh", "-c", script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    Json(json!({ "success": true })).into_response()
}

#[tokio::main]
async fn main() {
    let data_dir = PathBuf::from(
        std::env::var("CHOST_DATA_DIR").unwrap_or_else(|_| "data".to_string()),
    );
    let _ = fs::create_dir_all(&data_dir);
    let db_path = data_dir.join("chost.db");
    let db = Database::open(&db_path.to_string_lossy()).expect("Failed to open CHost DB");

    if db.get_setting("admin_pw_hash", "").is_empty() {
        let init_pw: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(14)
            .map(char::from)
            .collect();
        let _ = db.set_setting("admin_pw_hash", &hash_password(&init_pw));
        let pw_file = data_dir.join("init_password.txt");
        let _ = fs::write(&pw_file, format!("{}\n", init_pw));
        println!("Initial CHost password saved to {}", pw_file.display());
    }

    let jwt_secret = {
        let s = db.get_setting("jwt_secret", "");
        if s.is_empty() {
            let gen: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            let _ = db.set_setting("jwt_secret", &gen);
            gen
        } else {
            s
        }
    };

    let state = Arc::new(AppState {
        db,
        jwt_secret,
        data_dir,
        install_running: AtomicBool::new(false),
        login_guard: Default::default(),
    });

    spawn_alert_monitor(state.clone());

    let app = Router::new()
        .route("/", get(serve_panel))
        .route("/api/auth/me", get(handle_auth_me))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/change-password", post(handle_change_password))
        .route("/api/auth/logout", post(handle_logout))
        .route("/api/locales/{lang}", get(handle_locale))
        .route("/api/system/stats", get(handle_system_stats))
        .route("/api/runtimes/status", get(handle_runtimes_status))
        .route("/api/runtimes/install", post(handle_runtimes_install))
        .route("/api/runtimes/log", get(handle_runtimes_log))
        .route("/api/runtimes/skip-setup", post(handle_runtimes_skip_setup))
        .route("/api/sites", get(handle_list_sites).post(handle_create_site))
        .route("/api/sites/subdomain", post(handle_create_subdomain))
        .route("/api/sites/{id}", delete(handle_delete_site))
        .route("/api/sites/{id}/credentials", post(handle_update_site_credentials))
        .route("/api/sites/{id}/credentials/delete", post(handle_delete_site_credential))
        .route("/api/sites/{id}/conf", get(handle_get_site_conf).post(handle_save_site_conf))
        .route("/api/sites/{id}/domains", post(handle_save_site_domains))
        .route("/api/sites/{id}/logs", get(handle_get_site_logs))
        .route("/api/sites/{id}/logs/clear", post(handle_clear_site_logs))
        .route("/api/sites/{id}/php", post(handle_switch_site_php))
    .route("/api/sites/{id}/health", get(handle_site_health))
    .route("/api/dashboard/sites", get(handle_dashboard_sites))
    .route("/api/alerts/settings", get(handle_alerts_get).post(handle_alerts_save))
    .route("/api/alerts/test", post(handle_alerts_test))
    .route("/api/firewall/status", get(handle_firewall_status))
    .route("/api/firewall/apply", post(handle_firewall_apply))
    .route("/api/php/ini", get(handle_php_ini_get).post(handle_php_ini_save))
    .route("/api/webserver/migrate", post(handle_webserver_migrate))
    .route("/api/sites/{id}/git", get(handle_site_git_info))
    .route("/api/sites/{id}/git/update", post(handle_site_git_update))
    .route("/api/detect", post(handle_detect))
        .route("/api/sites/{id}/ssl", post(handle_issue_ssl))
        .route("/api/php/versions", get(handle_php_versions))
        .route("/api/apps", get(handle_list_apps).post(handle_create_app))
        .route("/api/apps/{id}", delete(handle_delete_app))
        .route("/api/apps/{id}/action", post(handle_app_action))
        .route("/api/db/sqlite/tables", get(handle_sqlite_tables))
        .route("/api/db/sqlite/query", post(handle_sqlite_query))
        .route("/api/db/mariadb/databases", get(handle_mariadb_databases))
        .route("/api/db/mariadb/tables", get(handle_mariadb_tables))
        .route("/api/db/mariadb/query", post(handle_mariadb_query))
        .route("/api/db/mariadb/backup", get(handle_mariadb_backup))
        .route("/api/storage/scan", get(handle_storage_scan))
        .route("/api/storage/clean", post(handle_storage_clean))
        .route("/api/files/list", get(handle_file_list))
        .route("/api/files", get(handle_file_read).post(handle_file_save))
        .route("/api/terminal", post(handle_terminal_exec))
        .route("/api/audits", get(handle_audits))
        .route("/api/panel/reset", post(handle_panel_reset))
        .route("/api/panel/version", get(handle_panel_version))
        .route("/api/panel/update", post(handle_panel_update))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("CHOST_PORT").unwrap_or_else(|_| "8800".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("CHost panel listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .unwrap();
}
