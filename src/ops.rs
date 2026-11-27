//! 운영 편의 기능: 장애·리소스 알림, 방화벽(UFW) 원클릭, php.ini 핵심 옵션 편집

use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

// ───────────── 알림 발송 (Webhook / Telegram) ─────────────

pub fn valid_http_url(u: &str) -> bool {
    let u = u.trim();
    u.len() < 400
        && (u.starts_with("https://") || u.starts_with("http://"))
        && !u.chars().any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '\\' | '<' | '>'))
}

pub fn valid_tg_token(t: &str) -> bool {
    let mut it = t.splitn(2, ':');
    let (a, b) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    a.len() >= 5 && a.chars().all(|c| c.is_ascii_digit()) && b.len() >= 20 && b.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn valid_tg_chat(c: &str) -> bool {
    let c = c.trim();
    (c.len() >= 3 && c.trim_start_matches('-').chars().all(|x| x.is_ascii_digit()) && !c.trim_start_matches('-').is_empty())
        || (c.starts_with('@') && c.len() >= 5 && c[1..].chars().all(|x| x.is_ascii_alphanumeric() || x == '_'))
}

fn curl_post_json(url: &str, body: &str) -> Result<String, String> {
    let mut child = Command::new("curl")
        .args(["-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(body.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// 설정된 모든 채널로 메시지를 보낸다. (채널별 결과 문자열 반환)
pub fn send_alert(webhook: &str, tg_token: &str, tg_chat: &str, text: &str) -> Vec<String> {
    let mut res = Vec::new();
    if valid_http_url(webhook) {
        let body = json!({ "text": text, "content": text, "message": text, "source": "CHost" }).to_string();
        match curl_post_json(webhook.trim(), &body) {
            Ok(code) if code.starts_with('2') => res.push("webhook:ok".to_string()),
            Ok(code) => res.push(format!("webhook:http {}", code)),
            Err(e) => res.push(format!("webhook:{}", e)),
        }
    }
    if valid_tg_token(tg_token) && valid_tg_chat(tg_chat) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", tg_token.trim());
        let out = Command::new("curl")
            .args(["-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", &url, "-d"])
            .arg(format!("chat_id={}", tg_chat.trim()))
            .arg("--data-urlencode")
            .arg(format!("text={}", text))
            .output();
        match out {
            Ok(o) => {
                let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if code == "200" { res.push("telegram:ok".to_string()) } else { res.push(format!("telegram:http {}", code)) }
            }
            Err(e) => res.push(format!("telegram:{}", e)),
        }
    }
    if res.is_empty() {
        res.push("no channel configured".to_string());
    }
    res
}

/// Let's Encrypt 인증서 만료까지 남은 일수
pub fn cert_days_left(domain: &str) -> Option<i64> {
    if domain.contains('/') || domain.contains("..") {
        return None;
    }
    let path = format!("/etc/letsencrypt/live/{}/cert.pem", domain);
    if !Path::new(&path).exists() {
        return None;
    }
    let out = Command::new("openssl").args(["x509", "-enddate", "-noout", "-in", &path]).output().ok()?;
    parse_openssl_enddate(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_openssl_enddate(txt: &str) -> Option<i64> {
    let raw = txt.trim().strip_prefix("notAfter=")?;
    let norm = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let dt = chrono::NaiveDateTime::parse_from_str(&norm, "%b %d %H:%M:%S %Y GMT").ok()?;
    Some((dt - chrono::Utc::now().naive_utc()).num_days())
}

// ───────────── 방화벽 (UFW) ─────────────

fn sh(cmd: &str) -> (bool, String) {
    match Command::new("sh").args(["-c", cmd]).output() {
        Ok(o) => (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
        Err(e) => (false, e.to_string()),
    }
}

/// 실제로 SSH 가 듣고 있는 포트 목록 (못 찾으면 22)
pub fn ssh_ports() -> Vec<u16> {
    let (_, out) = sh("ss -ltnp 2>/dev/null | grep -i sshd");
    let mut v: Vec<u16> = Vec::new();
    for line in out.lines() {
        if let Some(local) = line.split_whitespace().nth(3) {
            if let Some(p) = local.rsplit(':').next().and_then(|x| x.parse::<u16>().ok()) {
                if !v.contains(&p) {
                    v.push(p);
                }
            }
        }
    }
    if v.is_empty() {
        v.push(22);
    }
    v
}

pub fn ufw_status() -> Value {
    let (ok, out) = sh("command -v ufw >/dev/null 2>&1 && ufw status 2>&1");
    if !ok && out.trim().is_empty() {
        return json!({ "installed": false, "active": false, "rules": "" });
    }
    let active = out.lines().any(|l| l.trim().eq_ignore_ascii_case("Status: active"));
    json!({ "installed": true, "active": active, "rules": out.trim(), "ssh_ports": ssh_ports() })
}

/// SSH·웹(80/443)·패널 포트를 먼저 허용한 뒤 UFW 를 켠다. (잠금 사고 방지)
pub fn ufw_enable(panel_port: u16) -> Result<String, String> {
    let (_, _) = sh("command -v ufw >/dev/null 2>&1 || (DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw)");
    let (ok, _) = sh("command -v ufw >/dev/null 2>&1");
    if !ok {
        return Err("ufw is not installed and could not be installed".to_string());
    }
    let mut ports: Vec<u16> = ssh_ports();
    for p in [80u16, 443, panel_port] {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    for p in &ports {
        let (_, _) = sh(&format!("ufw allow {}/tcp", p));
    }
    let (_, _) = sh("ufw default deny incoming; ufw default allow outgoing");
    let (ok, out) = sh("ufw --force enable");
    if ok { Ok(format!("allowed tcp ports: {:?}", ports)) } else { Err(out) }
}

pub fn ufw_disable() -> Result<String, String> {
    let (ok, out) = sh("ufw disable");
    if ok { Ok("disabled".to_string()) } else { Err(out) }
}

// ───────────── php.ini 핵심 옵션 ─────────────

pub const PHP_INI_KEYS: [&str; 4] = ["upload_max_filesize", "post_max_size", "memory_limit", "max_execution_time"];

pub fn valid_php_version(v: &str) -> bool {
    ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"].contains(&v)
}

pub fn valid_ini_value(key: &str, v: &str) -> bool {
    let v = v.trim();
    if v.is_empty() || v.len() > 8 {
        return false;
    }
    if key == "max_execution_time" {
        return v.chars().all(|c| c.is_ascii_digit());
    }
    if key == "memory_limit" && v == "-1" {
        return true;
    }
    let (num, unit) = match v.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&v[..v.len() - 1], Some(c.to_ascii_uppercase())),
        _ => (v, None),
    };
    !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) && matches!(unit, None | Some('K') | Some('M') | Some('G'))
}

fn parse_ini_lines(txt: &str, out: &mut serde_json::Map<String, Value>) {
    for line in txt.lines() {
        let t = line.trim();
        if t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            let k = k.trim();
            if PHP_INI_KEYS.contains(&k) {
                out.insert(k.to_string(), Value::String(v.trim().trim_matches('"').to_string()));
            }
        }
    }
}

pub fn php_ini_get(ver: &str) -> Value {
    let mut vals = serde_json::Map::new();
    parse_ini_lines(&fs::read_to_string(format!("/etc/php/{}/fpm/php.ini", ver)).unwrap_or_default(), &mut vals);
    parse_ini_lines(&fs::read_to_string(format!("/etc/php/{}/fpm/conf.d/99-chost.ini", ver)).unwrap_or_default(), &mut vals);
    json!({ "version": ver, "values": vals, "installed": Path::new(&format!("/etc/php/{}/fpm", ver)).exists() })
}

pub fn php_ini_set(ver: &str, vals: &[(String, String)]) -> Result<(), String> {
    let dir = format!("/etc/php/{}/fpm/conf.d", ver);
    if !Path::new(&dir).exists() {
        return Err(format!("PHP {} (FPM) is not installed.", ver));
    }
    let mut body = String::from("; managed by CHost\n");
    for (k, v) in vals {
        body.push_str(&format!("{} = {}\n", k, v));
    }
    fs::write(format!("{}/99-chost.ini", dir), body).map_err(|e| e.to_string())?;
    let (_, out) = sh(&format!("systemctl reload php{}-fpm 2>&1 || systemctl restart php{}-fpm 2>&1", ver, ver));
    let _ = out;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators() {
        assert!(valid_http_url("https://hooks.slack.com/services/T/B/x"));
        assert!(!valid_http_url("ftp://x"));
        assert!(!valid_http_url("https://a b"));
        assert!(valid_tg_token("123456789:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKK"));
        assert!(!valid_tg_token("abc"));
        assert!(valid_tg_chat("-1001234567890"));
        assert!(valid_tg_chat("@mychannel"));
        assert!(!valid_tg_chat("a;b"));
        assert!(valid_ini_value("upload_max_filesize", "64M"));
        assert!(valid_ini_value("memory_limit", "-1"));
        assert!(valid_ini_value("max_execution_time", "300"));
        assert!(!valid_ini_value("max_execution_time", "30M"));
        assert!(!valid_ini_value("post_max_size", "64MB;rm"));
        assert!(valid_php_version("8.4") && !valid_php_version("9.9"));
    }

    #[test]
    fn enddate_parse() {
        assert!(parse_openssl_enddate("notAfter=Feb 25 08:18:53 2099 GMT\n").unwrap() > 1000);
        assert!(parse_openssl_enddate("notAfter=Feb  5 08:18:53 2099 GMT\n").is_some());
        assert!(parse_openssl_enddate("garbage").is_none());
    }
}
