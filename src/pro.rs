use crate::dbtools::BACKUP_ROOT;
use crate::ops::valid_http_url;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ───────────── AI Server Error Doctor ─────────────

pub fn collect_site_diagnostics_logs(domain: &str, site_type: &str, app_svc: &str) -> String {
    let mut out = String::new();
    let err_log = format!("/www/wwwlogs/{}.error.log", domain);
    if let Ok(text) = fs::read_to_string(&err_log) {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(60);
        if !lines[start..].is_empty() {
            out.push_str(&format!("=== {} (last {}) ===\n", err_log, lines.len() - start));
            out.push_str(&lines[start..].join("\n"));
            out.push('\n');
        }
    }
    if site_type == "proxy" && cfg!(unix) {
        if let Ok(o) = Command::new("journalctl")
            .args(["-u", app_svc, "-n", "60", "--no-pager"])
            .output()
        {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.trim().is_empty() {
                out.push_str(&format!("=== journalctl -u {} ===\n{}", app_svc, s));
            }
        }
    }
    out
}

pub fn rule_diagnose(logs: &str, framework: &str, language: &str) -> Value {
    let low = logs.to_lowercase();
    let mut findings: Vec<Value> = Vec::new();
    let mut push = |code: &str, title: &str, cause: &str, fix: &str| {
        findings.push(json!({ "code": code, "title": title, "cause": cause, "fix": fix }));
    };

    if low.contains("eaddrinuse") || low.contains("address already in use") {
        push(
            "PORT_CONFLICT",
            "포트 충돌 (Address already in use)",
            "동일한 포트를 다른 프로세스가 이미 점유하고 있어 앱이 시작되지 못했습니다.",
            "앱 프로세스 탭에서 중복 실행 중인 앱을 중지하거나 사이트 설정에서 프록시 포트를 변경 후 재시작하세요.",
        );
    }
    if low.contains("502 bad gateway") || low.contains("connect() failed") || low.contains("connection refused") && (low.contains("127.0.0.1") || low.contains("upstream")) {
        push(
            "UPSTREAM_DOWN",
            "업스트림 앱 응답 없음 (502 Bad Gateway)",
            "웹서버가 백엔드 앱 포트로 연결하지 못했습니다. 앱이 중지되었거나 시작 중 크래시했습니다.",
            "앱 프로세스 탭에서 서비스 상태(active)와 포트를 확인하고 재시작하세요. 빌드 중이었다면 10~30초 후 다시 확인하세요.",
        );
    }
    if low.contains("sqlstate") || low.contains("access denied for user") || low.contains("password authentication failed") || low.contains("can't connect to local mysql") {
        push(
            "DB_AUTH_OR_CONN",
            "데이터베이스 연결/인증 오류",
            "DB 계정 비밀번호가 틀렸거나, 해당 DB에 권한이 없거나, DB 서버가 중지되었습니다.",
            ".env 또는 설정 파일의 DB_HOST/DB_DATABASE/DB_USERNAME/DB_PASSWORD를 멀티 DB 스튜디오의 계정 정보와 맞춰주세요.",
        );
    }
    if low.contains("permission denied") || low.contains("eacces") || low.contains("failed to open stream: permission denied") {
        push(
            "PERMISSION_DENIED",
            "파일/폴더 권한 부족 (Permission denied)",
            "웹서버(www-data)가 업로드·캐시·세션 폴더에 쓰기/읽기 권한이 없습니다.",
            "파일 관리자 또는 웹 터미널에서 storage / data / uploads 폴더 소유권(chown -R www-data:www-data)과 권한(755/775)을 확인하세요.",
        );
    }
    if low.contains("enoent") || low.contains("no such file or directory") || low.contains("could not open input file") {
        push(
            "MISSING_FILE",
            "필수 파일 또는 빌드 산출물 누락",
            "시작 스크립트, .next/dist 빌드 결과물 또는 루트 index 파일이 존재하지 않습니다.",
            "웹 루트 경로가 맞는지 확인하고, Node/Next/Rust 앱은 빌드(npm run build / cargo build --release)가 정상 완료되었는지 확인하세요.",
        );
    }
    if low.contains("out of memory") || low.contains("killed") || low.contains("memory exhausted") {
        push(
            "OOM_KILLED",
            "메모리 부족 (OOM / Memory Exhausted)",
            "서버 RAM 한도를 초과하여 프로세스가 강제 종료되었거나 PHP 메모리 제한에 걸렸습니다.",
            "대시보드에서 RAM 사용량을 확인하고, Swap 메모리를 추가하거나 PHP memory_limit(예: 256M)을 상향하세요.",
        );
    }
    if low.contains("php fatal error") || low.contains("php parse error") || low.contains("syntax error") {
        push(
            "PHP_SYNTAX_OR_FATAL",
            "PHP 치명적/문법 오류",
            "PHP 코드 문법 오류 또는 설치된 PHP 버전과의 호환성 문제(미지원 함수/확장 모듈 누락)일 가능성이 큽니다.",
            "로그에 표시된 파일·줄 번호를 파일 편집기로 확인하거나 사이트 설정에서 PHP 버전을 프로젝트 요구 버전에 맞게 변경하세요.",
        );
    }
    if low.contains("panicked at") {
        push(
            "RUST_PANIC",
            "Rust 애플리케이션 패닉",
            "실행 중 unwrap()/expect() 실패 또는 초기화 설정 누락으로 프로세스가 비정상 종료되었습니다.",
            "로그의 'panicked at' 바로 위/아래 줄에서 파일명과 사유(.env, DB 경로 등)를 확인하세요.",
        );
    }
    drop(push);

    if findings.is_empty() {
        if logs.trim().is_empty() {
            findings.push(json!({
                "code": "NO_ERRORS",
                "title": "최근 에러 로그가 비어 있습니다",
                "cause": "수집된 에러 로그가 없거나 사이트가 정상 동작 중입니다.",
                "fix": "문제가 계속된다면 접속 로그(Access) 또는 브라우저 개발자 도구(F12) 네트워크 응답 코드를 함께 확인하세요."
            }));
        } else {
            findings.push(json!({
                "code": "GENERAL_CHECK",
                "title": "일반 로그 점검 필요",
                "cause": "대표적인 자동 패턴(포트 충돌·DB·권한·502) 외의 애플리케이션 고유 에러가 기록되어 있습니다.",
                "fix": "아래 로그 마지막 줄의 예외 메시지와 파일 경로를 확인하거나, 보안 설정에서 외부 AI API 키를 연동하면 심층 분석을 받을 수 있습니다."
            }));
        }
    }

    json!({
        "mode": "builtin",
        "framework": framework,
        "language": language,
        "findings": findings,
        "log_excerpt": logs.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
    })
}

pub async fn ai_diagnose(
    provider: &str,
    api_key: &str,
    model: &str,
    domain: &str,
    framework: &str,
    language: &str,
    logs: &str,
) -> Value {
    let mut base = rule_diagnose(logs, framework, language);
    if api_key.trim().is_empty() || provider == "builtin" {
        return base;
    }

    let prompt = format!(
        "You are an expert Linux/Nginx/PHP/Node/Rust server doctor. Analyze the error logs for site '{}' (framework: {}, language: {}).\n\
         Respond concisely in Korean with: 1) 핵심 원인, 2) 즉시 실행할 해결 방법 1~3가지.\n\nLogs:\n{}",
        domain,
        framework,
        language,
        logs.chars().rev().take(3500).collect::<String>().chars().rev().collect::<String>()
    );

    let client = match reqwest::Client::builder().timeout(Duration::from_secs(25)).build() {
        Ok(c) => c,
        Err(e) => {
            base["ai_error"] = json!(e.to_string());
            return base;
        }
    };

    let ai_text: Result<String, String> = if provider == "gemini" {
        let m = if model.trim().is_empty() { "gemini-2.0-flash" } else { model.trim() };
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            m,
            api_key.trim()
        );
        let body = json!({ "contents": [{ "parts": [{ "text": prompt }] }] });
        match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                let v: Value = resp.json().await.unwrap_or_default();
                Ok(v["candidates"][0]["content"]["parts"][0]["text"]
                    .as_str()
                    .unwrap_or("")
                    .to_string())
            }
            Ok(resp) => Err(format!("Gemini HTTP {}", resp.status())),
            Err(e) => Err(e.to_string()),
        }
    } else {
        let m = if model.trim().is_empty() { "gpt-4o-mini" } else { model.trim() };
        let body = json!({
            "model": m,
            "messages": [{ "role": "user", "content": prompt }],
            "max_tokens": 700
        });
        match client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(api_key.trim())
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let v: Value = resp.json().await.unwrap_or_default();
                Ok(v["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string())
            }
            Ok(resp) => Err(format!("OpenAI HTTP {}", resp.status())),
            Err(e) => Err(e.to_string()),
        }
    };

    match ai_text {
        Ok(txt) if !txt.trim().is_empty() => {
            base["mode"] = json!(provider);
            base["ai_analysis"] = json!(txt.trim());
        }
        Ok(_) => base["ai_error"] = json!("Empty AI response"),
        Err(e) => base["ai_error"] = json!(e),
    }
    base
}

// ───────────── Remote Backup (WebDAV & S3 SigV4) ─────────────

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RemoteBackupCfg {
    pub enabled: bool,
    pub protocol: String, // "webdav" | "s3"
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub username: String, // WebDAV user or S3 access key
    pub password: String, // WebDAV pass or S3 secret key
    pub prefix: String,
    pub auto_upload: bool,
}

pub fn validate_remote_cfg(c: &RemoteBackupCfg) -> Result<(), String> {
    if !c.enabled {
        return Ok(());
    }
    if c.protocol != "webdav" && c.protocol != "s3" {
        return Err("Protocol must be 'webdav' or 's3'.".into());
    }
    if !valid_http_url(&c.endpoint) {
        return Err("Endpoint must start with http:// or https://.".into());
    }
    if c.protocol == "s3" && c.bucket.trim().is_empty() {
        return Err("S3 bucket name is required.".into());
    }
    if c.username.trim().is_empty() || c.password.trim().is_empty() {
        return Err("Credentials are required.".into());
    }
    Ok(())
}

pub fn build_s3_put_headers(
    endpoint: &str,
    bucket: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    object_key: &str,
    payload: &[u8],
    amz_date: &str,
) -> Result<(String, String, Vec<(String, String)>), String> {
    let ep = endpoint.trim_end_matches('/');
    let parsed = reqwest::Url::parse(ep).map_err(|e| e.to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "Invalid S3 endpoint host".to_string())?;
    let host_header = match parsed.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };
    let clean_key = object_key.trim_start_matches('/');
    let base_path = parsed.path().trim_end_matches('/');
    let uri_path = format!("{}/{}/{}", base_path, bucket.trim(), clean_key);
    let url = format!("{}://{}{}", parsed.scheme(), host_header, uri_path);

    let date_stamp = &amz_date[..8];
    let reg = if region.trim().is_empty() { "us-east-1" } else { region.trim() };
    let payload_hash = sha256_hex(payload);

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host_header, payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "PUT\n{}\n\n{}\n{}\n{}",
        uri_path, canonical_headers, signed_headers, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, reg);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, reg.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key.trim(),
        scope,
        signed_headers,
        signature
    );
    let headers = vec![
        ("Authorization".to_string(), auth),
        ("x-amz-date".to_string(), amz_date.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash),
    ];
    Ok((url, host_header, headers))
}

async fn upload_one_file(
    client: &reqwest::Client,
    cfg: &RemoteBackupCfg,
    rel_key: &str,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let prefix = cfg.prefix.trim().trim_matches('/');
    let key = if prefix.is_empty() {
        rel_key.to_string()
    } else {
        format!("{}/{}", prefix, rel_key)
    };
    if cfg.protocol == "webdav" {
        let url = format!("{}/{}", cfg.endpoint.trim_end_matches('/'), key);
        let auth = format!("Basic {}", B64.encode(format!("{}:{}", cfg.username.trim(), cfg.password)));
        let resp = client
            .put(&url)
            .header("Authorization", auth)
            .body(bytes)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("WebDAV PUT {} -> HTTP {}", rel_key, resp.status()));
        }
        Ok(())
    } else {
        let now = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let (url, _host, hdrs) = build_s3_put_headers(
            &cfg.endpoint,
            &cfg.bucket,
            &cfg.region,
            &cfg.username,
            &cfg.password,
            &key,
            &bytes,
            &now,
        )?;
        let mut req = client.put(&url).body(bytes);
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let st = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(format!("S3 PUT {} -> HTTP {} {}", rel_key, st, txt.chars().take(160).collect::<String>()));
        }
        Ok(())
    }
}

pub async fn test_remote_backup(cfg: &RemoteBackupCfg) -> Result<String, String> {
    validate_remote_cfg(cfg)?;
    if !cfg.enabled {
        return Err("Remote backup is disabled.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;
    let probe = b"chost-remote-backup-check\n".to_vec();
    upload_one_file(&client, cfg, ".chost-probe.txt", probe).await?;
    Ok("OK (probe uploaded)".into())
}

pub async fn upload_backup_dir(cfg: &RemoteBackupCfg, dir_name: &str) -> Result<Value, String> {
    validate_remote_cfg(cfg)?;
    if !cfg.enabled {
        return Err("Remote backup is disabled.".into());
    }
    let dir = Path::new(BACKUP_ROOT).join(dir_name);
    if !dir.is_dir() {
        return Err("Backup folder not found.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let mut uploaded = Vec::new();
    let mut errors = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().to_string();
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("{}: {}", fname, e));
                continue;
            }
        };
        let key = format!("{}/{}", dir_name, fname);
        match upload_one_file(&client, cfg, &key, bytes).await {
            Ok(()) => uploaded.push(fname),
            Err(e) => errors.push(e),
        }
    }
    Ok(json!({ "ok": errors.is_empty(), "uploaded": uploaded, "errors": errors }))
}

// ───────────── Multi-Server Node Registry ─────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub id: String,
    pub name: String,
    pub url: String,
    pub password: String,
    #[serde(default)]
    pub entry_path: String,
}

pub fn valid_node_url(u: &str) -> bool {
    valid_http_url(u) && u.len() <= 240
}

pub async fn fetch_node_status(node: &NodeEntry) -> Value {
    let base = node.url.trim_end_matches('/');
    let client = match reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "online": false, "error": e.to_string() }),
    };

    if !node.entry_path.trim().is_empty() {
        let ep = node.entry_path.trim();
        let path = if ep.starts_with('/') { ep.to_string() } else { format!("/{}", ep) };
        let _ = client.get(format!("{}{}", base, path)).send().await;
    }

    let login = client
        .post(format!("{}/api/auth/login", base))
        .json(&json!({ "password": node.password }))
        .send()
        .await;
    match login {
        Ok(r) if r.status().is_success() => {
            let v: Value = r.json().await.unwrap_or_default();
            if v["success"] != true {
                return json!({ "online": false, "error": v["error"].as_str().unwrap_or("Auth failed") });
            }
        }
        Ok(r) => return json!({ "online": false, "error": format!("Login HTTP {}", r.status()) }),
        Err(e) => return json!({ "online": false, "error": e.to_string() }),
    }

    let ov: Value = match client.get(format!("{}/api/system/stats", base)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        Ok(r) => return json!({ "online": false, "error": format!("Stats HTTP {}", r.status()) }),
        Err(e) => return json!({ "online": false, "error": e.to_string() }),
    };
    let ver: Value = match client.get(format!("{}/api/panel/version", base)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => json!({}),
    };
    let sites: Value = match client.get(format!("{}/api/sites", base)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => json!({}),
    };
    let site_count = sites["sites"].as_array().map(|a| a.len()).unwrap_or(0);

    json!({
        "online": true,
        "cpu": ov["cpu_percent"],
        "ram_used": ov["mem_used_mb"],
        "ram_total": ov["mem_total_mb"],
        "disk_used": ov["disk_used_gb"],
        "disk_total": ov["disk_total_gb"],
        "disk_percent": ov["disk_percent"],
        "uptime": ov["uptime_secs"],
        "hostname": ov["hostname"],
        "version": ver["current"],
        "sites": site_count
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_diagnose_patterns() {
        let d1 = rule_diagnose("nginx: [error] connect() failed (111: Connection refused) while connecting to upstream, 502 Bad Gateway", "nextjs", "node");
        assert_eq!(d1["findings"][0]["code"], "UPSTREAM_DOWN");

        let d2 = rule_diagnose("Error: listen EADDRINUSE: address already in use :::3001", "express", "node");
        assert_eq!(d2["findings"][0]["code"], "PORT_CONFLICT");

        let d3 = rule_diagnose("SQLSTATE[HY000] [1045] Access denied for user 'app'@'localhost'", "laravel", "php");
        assert_eq!(d3["findings"][0]["code"], "DB_AUTH_OR_CONN");
    }

    #[test]
    fn s3_sigv4_builds_headers() {
        let (url, host, hdrs) = build_s3_put_headers(
            "https://s3.ap-northeast-2.amazonaws.com",
            "my-bucket",
            "ap-northeast-2",
            "AKIAIOSFODNN7",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "backups/test.tar.gz",
            b"hello",
            "20261128T000000Z",
        )
        .unwrap();
        assert_eq!(url, "https://s3.ap-northeast-2.amazonaws.com/my-bucket/backups/test.tar.gz");
        assert_eq!(host, "s3.ap-northeast-2.amazonaws.com");
        assert!(hdrs[0].1.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7/20261128/ap-northeast-2/s3/aws4_request"));
    }

    #[test]
    fn remote_and_node_validators() {
        assert!(valid_node_url("http://49.247.192.40:8800"));
        assert!(!valid_node_url("ftp://example.com"));
        let bad = RemoteBackupCfg { enabled: true, protocol: "ftp".into(), ..Default::default() };
        assert!(validate_remote_cfg(&bad).is_err());
    }
}
