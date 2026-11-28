//! 패널 접근 보안: 2단계 인증(TOTP), 접속 IP 화이트리스트, 보안 접속 경로

use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use totp_rs::{Algorithm, Secret, TOTP};

// ───────────── TOTP ─────────────

pub fn new_totp_secret() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(_) => String::new(),
    }
}

fn build_totp(secret_b32: &str, account: &str) -> Option<TOTP> {
    let bytes = Secret::Encoded(secret_b32.trim().to_string()).to_bytes().ok()?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some("CHost".to_string()), account.replace(':', "")).ok()
}

pub fn totp_url(secret_b32: &str, host: &str) -> String {
    build_totp(secret_b32, &format!("admin@{}", host)).map(|t| t.get_url()).unwrap_or_default()
}

pub fn totp_check(secret_b32: &str, code: &str) -> bool {
    let c: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if c.len() != 6 || secret_b32.trim().is_empty() {
        return false;
    }
    build_totp(secret_b32, "admin")
        .map(|t| t.check_current(&c).unwrap_or(false))
        .unwrap_or(false)
}

pub fn qr_svg(data: &str) -> String {
    qrcode::QrCode::new(data.as_bytes())
        .map(|q| {
            q.render::<qrcode::render::svg::Color>()
                .min_dimensions(200, 200)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_default()
}

// ───────────── IP 화이트리스트 ─────────────

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn parse_entry(e: &str) -> Option<(IpAddr, u8)> {
    let e = e.trim();
    let (ip_s, pfx) = match e.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (e, None),
    };
    let ip = normalize_ip(ip_s.trim().parse::<IpAddr>().ok()?);
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let p = match pfx {
        Some(p) => p.trim().parse::<u8>().ok().filter(|v| *v <= max)?,
        None => max,
    };
    Some((ip, p))
}

fn in_net(ip: IpAddr, net: IpAddr, pfx: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if pfx == 0 {
                return true;
            }
            let m = u32::MAX << (32 - pfx as u32);
            (u32::from(a) & m) == (u32::from(b) & m)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if pfx == 0 {
                return true;
            }
            let m = u128::MAX << (128 - pfx as u32);
            (u128::from(a) & m) == (u128::from(b) & m)
        }
        _ => false,
    }
}

/// 입력값을 검증하고 정규화된 목록을 돌려준다.
pub fn parse_ip_list(raw: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for e in raw.split(|c: char| c.is_whitespace() || c == ',') {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        if parse_entry(e).is_none() {
            return Err(format!("Invalid IP / CIDR: {}", e));
        }
        if !out.contains(&e.to_string()) {
            out.push(e.to_string());
        }
    }
    if out.len() > 100 {
        return Err("Too many entries (max 100).".to_string());
    }
    Ok(out)
}

/// 목록이 비어 있으면 모두 허용, 루프백(서버 자신)은 항상 허용.
pub fn ip_allowed(list: &str, ip: &str) -> bool {
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return false;
    };
    let addr = normalize_ip(addr);
    if addr.is_loopback() {
        return true;
    }
    let entries: Vec<(IpAddr, u8)> = list
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(parse_entry)
        .collect();
    if entries.is_empty() {
        return true;
    }
    entries.into_iter().any(|(net, p)| in_net(addr, net, p))
}

// ───────────── 보안 접속 경로 ─────────────

pub fn valid_entry(p: &str) -> bool {
    p.starts_with('/')
        && (5..=41).contains(&p.len())
        && p[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !p.to_ascii_lowercase().starts_with("/api")
}

pub fn random_entry() -> String {
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(|c| (c as char).to_ascii_lowercase())
        .collect();
    format!("/{}", s)
}

pub fn entry_token(jwt_secret: &str, path: &str) -> String {
    hex::encode(Sha256::digest(format!("entry:{}:{}", jwt_secret, path).as_bytes()))[..24].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_rules() {
        assert!(parse_ip_list("1.2.3.4, 10.0.0.0/8\n2001:db8::/32").is_ok());
        assert!(parse_ip_list("1.2.3.999").is_err());
        assert!(parse_ip_list("10.0.0.0/33").is_err());
        assert!(ip_allowed("", "8.8.8.8"));
        assert!(ip_allowed("1.2.3.4", "127.0.0.1"));
        assert!(ip_allowed("1.2.3.4", "1.2.3.4"));
        assert!(!ip_allowed("1.2.3.4", "1.2.3.5"));
        assert!(ip_allowed("10.0.0.0/8", "10.20.30.40"));
        assert!(!ip_allowed("10.0.0.0/8", "11.0.0.1"));
        assert!(ip_allowed("1.2.3.4", "::ffff:1.2.3.4"));
        assert!(ip_allowed("2001:db8::/32", "2001:db8::1"));
    }

    #[test]
    fn entry_rules() {
        assert!(valid_entry("/admin-x9k2"));
        assert!(!valid_entry("/api-x"));
        assert!(!valid_entry("admin"));
        assert!(!valid_entry("/a/b"));
        assert!(!valid_entry("/ab"));
        let r = random_entry();
        assert!(valid_entry(&r), "{}", r);
        assert_eq!(entry_token("s", "/x").len(), 24);
    }

    #[test]
    fn totp_roundtrip() {
        let sec = new_totp_secret();
        assert!(sec.len() >= 26);
        let t = build_totp(&sec, "admin").unwrap();
        let code = t.generate_current().unwrap();
        assert!(totp_check(&sec, &code));
        assert!(!totp_check(&sec, "000000") || code == "000000");
        assert!(totp_url(&sec, "host").starts_with("otpauth://totp/"));
        assert!(qr_svg("otpauth://totp/x").contains("<svg"));
    }
}
