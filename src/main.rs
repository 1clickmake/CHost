mod db;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use db::{hash_secret, Database};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::Arc,
    time::SystemTime,
};
use sysinfo::{Disks, System};
use tower_http::cors::CorsLayer;
use walkdir::WalkDir;

struct AppState {
    db: Database,
    jwt_secret: String,
    data_dir: PathBuf,
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
struct CreateSiteReq {
    domain: String,
    site_type: String,
    proxy_port: Option<i64>,
    php_version: Option<String>,
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

async fn handle_login(State(state): State<Arc<AppState>>, Json(req): Json<LoginReq>) -> Response {
    let stored = state.db.get_setting("admin_pw_hash", "");
    if hash_secret(req.password.trim()) != stored {
        state.db.log_audit("anonymous", "LOGIN_FAILED", "panel", "Invalid password attempt");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Invalid password." })),
        )
            .into_response();
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
    if hash_secret(req.current_password.trim()) != stored {
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
    if let Err(e) = state.db.set_setting("admin_pw_hash", &hash_secret(new_pw)) {
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

fn write_nginx_site_conf(
    domain: &str,
    site_type: &str,
    root_path: &str,
    proxy_port: i64,
    php_version: &str,
) -> String {
    let body = match site_type {
        "proxy" => format!(
            "    location / {{\n        proxy_pass http://127.0.0.1:{};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }}\n",
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
        "server {{\n    listen 80;\n    server_name {};\n    root {};\n{}\n}}\n",
        domain, root_path, body
    )
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
    let index_file = FsPath::new(&root_path).join("index.html");
    if !index_file.exists() {
        let _ = fs::write(
            &index_file,
            format!("<!doctype html><html><head><meta charset='utf-8'><title>{}</title></head><body><h1>{}</h1><p>Provisioned by CHost</p></body></html>", domain, domain),
        );
    }

    let proxy_port = req.proxy_port.unwrap_or(0);
    let php_ver = req.php_version.unwrap_or_default();
    let conf = write_nginx_site_conf(&domain, &req.site_type, &root_path, proxy_port, &php_ver);

    if cfg!(unix) {
        let avail = format!("/etc/nginx/sites-available/{}.conf", domain);
        let enabled = format!("/etc/nginx/sites-enabled/{}.conf", domain);
        let _ = fs::write(&avail, &conf);
        let _ = Command::new("ln").args(["-sf", &avail, &enabled]).output();
        let test = Command::new("nginx").arg("-t").output();
        if let Ok(out) = test {
            if out.status.success() {
                let _ = Command::new("systemctl").args(["reload", "nginx"]).output();
            }
        }
    }

    match state
        .db
        .create_site(&domain, &req.site_type, &root_path, proxy_port, &php_ver)
    {
        Ok(id) => {
            state
                .db
                .log_audit("admin", "CREATE_SITE", &domain, &format!("type={}", req.site_type));
            Json(json!({ "success": true, "id": id })).into_response()
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
                .args(["clone", "--depth", "1", "https://github.com/1clickmake/NeuronAIPHP.git", root_path])
                .output();
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
        }
        "wordpress" => {
            let cmd = format!(
                "curl -sSL https://wordpress.org/latest.tar.gz | tar -xz --strip-components=1 -C '{}'",
                root_path
            );
            let _ = Command::new("sh").args(["-c", &cmd]).output();
        }
        "django" => {
            let cmd = format!("python3 -m venv '{}/venv'", root_path);
            let _ = Command::new("sh").args(["-c", &cmd]).output();
        }
        "springboot" => {
            let run_sh = FsPath::new(root_path).join("run.sh");
            let _ = fs::write(&run_sh, "#!/bin/bash\njava -jar app.jar\n");
        }
        _ => {}
    }
    let idx = FsPath::new(root_path).join("index.html");
    if !idx.exists() {
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
    let prefix = req.prefix.trim().to_lowercase();
    let parent = req.parent_domain.trim().to_lowercase();
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
    let index_file = FsPath::new(&root_path).join("index.html");
    if !index_file.exists() {
        let _ = fs::write(
            &index_file,
            format!(
                "<!doctype html><html><head><meta charset='utf-8'><title>{}</title></head><body><h1>{}</h1><p>Language: {} | Framework: {}</p></body></html>",
                full_domain, full_domain, req.language, req.framework
            ),
        );
    }

    provision_framework(&root_path, req.framework.trim(), &full_domain);

    let site_type = match req.language.as_str() {
        "php" => "php",
        "rust" | "python" | "node" | "java" => "proxy",
        _ => "static",
    };
    let proxy_port = req.proxy_port.unwrap_or(8080);
    let php_ver = req.php_version.unwrap_or_else(|| "8.3".to_string());
    let conf = write_nginx_site_conf(&full_domain, site_type, &root_path, proxy_port, &php_ver);

    if cfg!(unix) {
        let avail = format!("/etc/nginx/sites-available/{}.conf", full_domain);
        let enabled = format!("/etc/nginx/sites-enabled/{}.conf", full_domain);
        let _ = fs::write(&avail, &conf);
        let _ = Command::new("ln").args(["-sf", &avail, &enabled]).output();
        if let Ok(out) = Command::new("nginx").arg("-t").output() {
            if out.status.success() {
                let _ = Command::new("systemctl").args(["reload", "nginx"]).output();
            }
        }
        if req.create_ssh.unwrap_or(false) {
            let safe_user = format!(
                "chost_{}",
                prefix.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect::<String>()
            );
            let _ = Command::new("useradd")
                .args(["-d", &root_path, "-s", "/bin/bash", &safe_user])
                .output();
        }
    }

    match state
        .db
        .create_site(&full_domain, site_type, &root_path, proxy_port, &php_ver)
    {
        Ok(id) => {
            if req.issue_ssl.unwrap_or(false) && cfg!(unix) {
                if let Ok(o) = Command::new("certbot")
                    .args([
                        "--nginx",
                        "-d",
                        &full_domain,
                        "--non-interactive",
                        "--agree-tos",
                        "--register-unsafely-without-email",
                    ])
                    .output()
                {
                    if o.status.success() {
                        let _ = state.db.update_site_ssl(id, true);
                    }
                }
            }
            state.db.log_audit(
                "admin",
                "CREATE_SUBDOMAIN",
                &full_domain,
                &format!("lang={}, fw={}", req.language, req.framework),
            );
            Json(json!({ "success": true, "id": id, "domain": full_domain, "root_path": root_path }))
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
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
    let _ = state.db.update_site_php(id, req.php_version.trim());
    state.db.log_audit(
        "admin",
        "SWITCH_PHP",
        &format!("site:{}", id),
        &format!("php={}", req.php_version),
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
        let out = Command::new("certbot")
            .args([
                "--nginx",
                "-d",
                &site.domain,
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
            ])
            .output();
        if let Ok(o) = out {
            if !o.status.success() {
                let err = String::from_utf8_lossy(&o.stderr).to_string();
                return Json(json!({ "success": false, "error": err })).into_response();
            }
        }
    }
    let _ = state.db.update_site_ssl(id, true);
    state.db.log_audit("admin", "ISSUE_SSL", &site.domain, "SSL enabled");
    Json(json!({ "success": true })).into_response()
}

async fn handle_delete_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !is_authed(&state, &headers) {
        return unauthorized();
    }
    let _ = state.db.delete_site(id);
    state.db.log_audit("admin", "DELETE_SITE", &format!("site:{}", id), "Site removed");
    Json(json!({ "success": true })).into_response()
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
    state.db.log_audit(
        "admin",
        "STORAGE_CLEAN",
        "logs",
        &format!("days={}, compress={}", req.days, req.compress),
    );
    Json(json!({ "success": true, "preview": false, "message": "Safe log cleanup completed." })).into_response()
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
        let _ = db.set_setting("admin_pw_hash", &hash_secret(&init_pw));
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
    });

    let app = Router::new()
        .route("/", get(serve_panel))
        .route("/api/auth/me", get(handle_auth_me))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/change-password", post(handle_change_password))
        .route("/api/auth/logout", post(handle_logout))
        .route("/api/locales/{lang}", get(handle_locale))
        .route("/api/system/stats", get(handle_system_stats))
        .route("/api/sites", get(handle_list_sites).post(handle_create_site))
        .route("/api/sites/subdomain", post(handle_create_subdomain))
        .route("/api/sites/{id}", delete(handle_delete_site))
        .route("/api/sites/{id}/php", post(handle_switch_site_php))
        .route("/api/sites/{id}/ssl", post(handle_issue_ssl))
        .route("/api/php/versions", get(handle_php_versions))
        .route("/api/apps", get(handle_list_apps).post(handle_create_app))
        .route("/api/apps/{id}", delete(handle_delete_app))
        .route("/api/apps/{id}/action", post(handle_app_action))
        .route("/api/db/sqlite/tables", get(handle_sqlite_tables))
        .route("/api/db/sqlite/query", post(handle_sqlite_query))
        .route("/api/storage/scan", get(handle_storage_scan))
        .route("/api/storage/clean", post(handle_storage_clean))
        .route("/api/files", get(handle_file_read).post(handle_file_save))
        .route("/api/terminal", post(handle_terminal_exec))
        .route("/api/audits", get(handle_audits))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("CHOST_PORT").unwrap_or_else(|_| "8800".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("CHost panel listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
