//! DB 도구: MariaDB/PostgreSQL 계정·CSV 내보내기, 예약 자동 백업

use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
};

pub const BACKUP_ROOT: &str = "/www/backup";
pub static BACKUP_RUNNING: AtomicBool = AtomicBool::new(false);

// ───────────── 공통 검증 ─────────────

pub fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn valid_db_password(p: &str) -> bool {
    (8..=64).contains(&p.len()) && p.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '\'' | '"' | '\\' | '`'))
}

pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 64 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '%' | '_' | '-' | ':'))
}

// ───────────── CSV ─────────────

fn csv_field(f: &str) -> String {
    if f.contains(',') || f.contains('"') || f.contains('\n') || f.contains('\r') {
        format!("\"{}\"", f.replace('"', "\"\""))
    } else {
        f.to_string()
    }
}

pub fn csv_line(fields: &[String]) -> String {
    fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",") + "\r\n"
}

fn unescape_mysql(f: &str) -> String {
    if f == "NULL" {
        return String::new();
    }
    let mut out = String::with_capacity(f.len());
    let mut it = f.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o)
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `mysql -B` (탭 구분, 이스케이프) 출력을 CSV 로 변환 (엑셀 한글용 BOM 포함)
pub fn mysql_tsv_to_csv(tsv: &str) -> String {
    let mut out = String::from("\u{FEFF}");
    for line in tsv.lines() {
        let fields: Vec<String> = line.split('\t').map(unescape_mysql).collect();
        out.push_str(&csv_line(&fields));
    }
    out
}

// ───────────── MariaDB ─────────────

pub fn mysql(args: &[&str]) -> Result<String, String> {
    let o = Command::new("mysql").args(args).output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

pub fn maria_databases() -> Vec<String> {
    mysql(&["-N", "-B", "-e", "SHOW DATABASES;"])
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !matches!(s.as_str(), "information_schema" | "performance_schema" | "mysql" | "sys"))
        .collect()
}

pub fn maria_users() -> Result<Vec<Value>, String> {
    let users = mysql(&["-N", "-B", "-e", "SELECT User, Host FROM mysql.user WHERE User NOT IN ('root','mysql','mariadb.sys','debian-sys-maint','') ORDER BY User;"])?;
    let grants = mysql(&["-N", "-B", "-e", "SELECT DISTINCT User, Host, Db FROM mysql.db;"]).unwrap_or_default();
    let mut out = Vec::new();
    for l in users.lines() {
        let mut p = l.split('\t');
        let (u, h) = (p.next().unwrap_or(""), p.next().unwrap_or(""));
        if u.is_empty() {
            continue;
        }
        let dbs: Vec<String> = grants
            .lines()
            .filter_map(|g| {
                let mut q = g.split('\t');
                let (gu, gh, gd) = (q.next()?, q.next()?, q.next()?);
                if gu == u && gh == h { Some(gd.replace("\\_", "_")) } else { None }
            })
            .collect();
        out.push(json!({ "user": u, "host": h, "databases": dbs }));
    }
    Ok(out)
}

// ───────────── PostgreSQL ─────────────

pub fn pg_available() -> bool {
    Path::new("/usr/lib/postgresql").exists()
        && Command::new("sh").args(["-c", "command -v psql >/dev/null 2>&1"]).status().map(|s| s.success()).unwrap_or(false)
}

pub fn psql(db: Option<&str>, sql: &str, extra: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("runuser");
    cmd.current_dir("/tmp").args(["-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1"]);
    if let Some(d) = db {
        cmd.args(["-d", d]);
    }
    cmd.args(extra).args(["-c", sql]);
    let o = cmd.output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

pub fn pg_databases() -> Vec<String> {
    psql(None, "SELECT datname FROM pg_database WHERE datistemplate = false AND datname <> 'postgres' ORDER BY datname;", &["-At"])
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn pg_tables(db: &str) -> Vec<String> {
    psql(Some(db), "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;", &["-At"])
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn pg_dump(db: &str) -> Result<Vec<u8>, String> {
    let o = Command::new("runuser")
        .current_dir("/tmp")
        .args(["-u", "postgres", "--", "pg_dump", db])
        .output()
        .map_err(|e| e.to_string())?;
    if o.status.success() { Ok(o.stdout) } else { Err(String::from_utf8_lossy(&o.stderr).trim().to_string()) }
}

// ───────────── 예약 자동 백업 ─────────────

fn sh(cmd: &str) -> Result<(), String> {
    let o = Command::new("sh").args(["-c", cmd]).output().map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&o.stderr).trim().to_string()) }
}

pub fn valid_backup_name(n: &str) -> bool {
    n.len() == 15 && n.as_bytes()[8] == b'-' && n.chars().enumerate().all(|(i, c)| if i == 8 { c == '-' } else { c.is_ascii_digit() })
}

pub fn valid_backup_file(f: &str) -> bool {
    !f.is_empty() && f.len() < 200 && !f.contains('/') && !f.contains("..") && !f.starts_with('.')
}

fn safe_domain(d: &str) -> bool {
    !d.is_empty() && !d.contains('/') && !d.contains("..") && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// 모든 MariaDB / PostgreSQL DB 와 사이트 파일, CHost 설정 DB 를 /www/backup/YYYYMMDD-HHMMSS 에 저장한다.
pub fn run_backup(domains: &[String], panel_db_copy: &dyn Fn(&str) -> Result<(), String>, keep: usize) -> Value {
    let name = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = PathBuf::from(BACKUP_ROOT).join(&name);
    if let Err(e) = fs::create_dir_all(&dir) {
        return json!({ "ok": false, "error": e.to_string() });
    }
    let d = dir.to_string_lossy().to_string();
    let mut done: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for db in maria_databases() {
        if !valid_ident(&db) {
            continue;
        }
        match sh(&format!("set -o pipefail 2>/dev/null; mysqldump --single-transaction --routines --events '{db}' | gzip > '{d}/mysql-{db}.sql.gz'", db = db, d = d)) {
            Ok(()) => done.push(format!("mysql-{}.sql.gz", db)),
            Err(e) => errors.push(format!("mysql {}: {}", db, e)),
        }
    }
    if pg_available() {
        for db in pg_databases() {
            if !valid_ident(&db) {
                continue;
            }
            match sh(&format!("cd /tmp && runuser -u postgres -- pg_dump '{db}' | gzip > '{d}/pg-{db}.sql.gz'", db = db, d = d)) {
                Ok(()) => done.push(format!("pg-{}.sql.gz", db)),
                Err(e) => errors.push(format!("pg {}: {}", db, e)),
            }
        }
    }
    for dom in domains {
        if !safe_domain(dom) || !Path::new(&format!("/www/wwwroot/{}", dom)).exists() {
            continue;
        }
        match sh(&format!(
            "tar czf '{d}/site-{dom}.tar.gz' --exclude=node_modules --exclude=target --exclude=venv --exclude=.git -C /www/wwwroot '{dom}'",
            d = d,
            dom = dom
        )) {
            Ok(()) => done.push(format!("site-{}.tar.gz", dom)),
            Err(e) => errors.push(format!("site {}: {}", dom, e)),
        }
    }
    match panel_db_copy(&format!("{}/chost-panel.db", d)) {
        Ok(()) => done.push("chost-panel.db".to_string()),
        Err(e) => errors.push(format!("panel db: {}", e)),
    }
    let removed = prune_backups(keep);
    json!({ "ok": errors.is_empty(), "name": name, "files": done, "errors": errors, "pruned": removed })
}

pub fn prune_backups(keep: usize) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(BACKUP_ROOT)
        .map(|it| it.flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| valid_backup_name(n)).collect())
        .unwrap_or_default();
    names.sort();
    let keep = keep.max(1);
    let mut removed = Vec::new();
    while names.len() > keep {
        let n = names.remove(0);
        if fs::remove_dir_all(Path::new(BACKUP_ROOT).join(&n)).is_ok() {
            removed.push(n);
        }
    }
    removed
}

pub fn list_backups() -> Vec<Value> {
    let mut names: Vec<String> = fs::read_dir(BACKUP_ROOT)
        .map(|it| it.flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| valid_backup_name(n)).collect())
        .unwrap_or_default();
    names.sort();
    names.reverse();
    names
        .into_iter()
        .map(|n| {
            let mut files: Vec<Value> = Vec::new();
            let mut total: u64 = 0;
            if let Ok(it) = fs::read_dir(Path::new(BACKUP_ROOT).join(&n)) {
                let mut v: Vec<(String, u64)> = it
                    .flatten()
                    .filter_map(|e| Some((e.file_name().to_string_lossy().to_string(), e.metadata().ok()?.len())))
                    .collect();
                v.sort();
                for (f, sz) in v {
                    total += sz;
                    files.push(json!({ "file": f, "size": sz }));
                }
            }
            json!({ "name": n, "files": files, "total": total })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_conv() {
        let tsv = "id\tname\tnote\n1\tKim, J\tline1\\nline2\n2\tPark\tNULL\n3\tsay \"hi\"\ta\\tb";
        let csv = mysql_tsv_to_csv(tsv);
        assert!(csv.starts_with('\u{FEFF}'));
        assert!(csv.contains("1,\"Kim, J\",\"line1\nline2\"\r\n"));
        assert!(csv.contains("2,Park,\r\n"));
        assert!(csv.contains("3,\"say \"\"hi\"\"\",a\tb\r\n"));
    }

    #[test]
    fn validators() {
        assert!(valid_ident("site_db1") && !valid_ident("a;b") && !valid_ident(""));
        assert!(valid_db_password("Abc!2345xyz") && !valid_db_password("short") && !valid_db_password("has'quote1"));
        assert!(valid_host("localhost") && valid_host("%") && !valid_host("a b"));
        assert!(valid_backup_name("20261128-091500") && !valid_backup_name("../etc") && !valid_backup_name("20261128_091500"));
        assert!(valid_backup_file("mysql-a.sql.gz") && !valid_backup_file("../x") && !valid_backup_file("a/b"));
    }
}
