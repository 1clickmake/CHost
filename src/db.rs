#![allow(dead_code)]

use chrono::Utc;
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SiteRecord {
    pub id: i64,
    pub domain: String,
    pub site_type: String,
    pub root_path: String,
    pub proxy_port: i64,
    pub php_version: String,
    pub ssl_enabled: bool,
    pub status: String,
    pub created_at: String,
    pub ftp_user: String,
    pub ftp_pass: String,
    pub db_name: String,
    pub db_user: String,
    pub db_pass: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppRecord {
    pub id: i64,
    pub name: String,
    pub language: String,
    pub work_dir: String,
    pub exec_cmd: String,
    pub port: i64,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditRecord {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForumPost {
    pub id: i64,
    pub category: String,
    pub title: String,
    pub author: String,
    pub content: String,
    pub views: i64,
    pub likes: i64,
    pub is_pinned: bool,
    pub comment_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForumComment {
    pub id: i64,
    pub post_id: i64,
    pub author: String,
    pub content: String,
    pub created_at: String,
}

pub fn hash_secret(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// 관리자 비밀번호를 Argon2id(솔트 포함) 해시로 만든다.
pub fn hash_password(raw: &str) -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(raw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| hash_secret(raw))
}

/// Argon2 해시 또는 (구버전) SHA-256 해시를 모두 검증한다.
pub fn verify_password(stored: &str, raw: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    if stored.starts_with("$argon2") {
        PasswordHash::new(stored)
            .map(|p| Argon2::default().verify_password(raw.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    } else {
        hash_secret(raw) == stored
    }
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                site_type TEXT NOT NULL,
                root_path TEXT NOT NULL,
                proxy_port INTEGER NOT NULL DEFAULT 0,
                php_version TEXT NOT NULL DEFAULT '',
                ssl_enabled INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                ftp_user TEXT NOT NULL DEFAULT '',
                ftp_pass TEXT NOT NULL DEFAULT '',
                db_name TEXT NOT NULL DEFAULT '',
                db_user TEXT NOT NULL DEFAULT '',
                db_pass TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                language TEXT NOT NULL,
                work_dir TEXT NOT NULL,
                exec_cmd TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'stopped',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS forum_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                content TEXT NOT NULL,
                views INTEGER NOT NULL DEFAULT 0,
                likes INTEGER NOT NULL DEFAULT 0,
                is_pinned INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS forum_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(post_id) REFERENCES forum_posts(id) ON DELETE CASCADE
            );
            ",
        )?;
        for col in ["ftp_user", "ftp_pass", "db_name", "db_user", "db_pass"] {
            let _ = conn.execute(
                &format!("ALTER TABLE sites ADD COLUMN {} TEXT NOT NULL DEFAULT ''", col),
                [],
            );
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_setting(&self, key: &str, default: &str) -> String {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| default.to_string())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn log_audit(&self, actor: &str, action: &str, target: &str, detail: &str) {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT INTO audit_logs (actor, action, target, detail, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![actor, action, target, detail, now],
        );
    }

    pub fn list_audits(&self, limit: i64) -> Result<Vec<AuditRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, actor, action, target, detail, created_at FROM audit_logs ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(AuditRecord {
                id: r.get(0)?,
                actor: r.get(1)?,
                action: r.get(2)?,
                target: r.get(3)?,
                detail: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_sites(&self) -> Result<Vec<SiteRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, domain, site_type, root_path, proxy_port, php_version, ssl_enabled, status, created_at,
                    ftp_user, ftp_pass, db_name, db_user, db_pass
             FROM sites ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SiteRecord {
                id: r.get(0)?,
                domain: r.get(1)?,
                site_type: r.get(2)?,
                root_path: r.get(3)?,
                proxy_port: r.get(4)?,
                php_version: r.get(5)?,
                ssl_enabled: r.get::<_, i64>(6)? != 0,
                status: r.get(7)?,
                created_at: r.get(8)?,
                ftp_user: r.get(9)?,
                ftp_pass: r.get(10)?,
                db_name: r.get(11)?,
                db_user: r.get(12)?,
                db_pass: r.get(13)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_site(&self, id: i64) -> Result<Option<SiteRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, domain, site_type, root_path, proxy_port, php_version, ssl_enabled, status, created_at,
                    ftp_user, ftp_pass, db_name, db_user, db_pass
             FROM sites WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok(SiteRecord {
                id: r.get(0)?,
                domain: r.get(1)?,
                site_type: r.get(2)?,
                root_path: r.get(3)?,
                proxy_port: r.get(4)?,
                php_version: r.get(5)?,
                ssl_enabled: r.get::<_, i64>(6)? != 0,
                status: r.get(7)?,
                created_at: r.get(8)?,
                ftp_user: r.get(9)?,
                ftp_pass: r.get(10)?,
                db_name: r.get(11)?,
                db_user: r.get(12)?,
                db_pass: r.get(13)?,
            })
        })?;
        match rows.next() {
            Some(Ok(site)) => Ok(Some(site)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn update_site_credentials(
        &self,
        id: i64,
        ftp_user: &str,
        ftp_pass: &str,
        db_name: &str,
        db_user: &str,
        db_pass: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sites SET ftp_user = ?1, ftp_pass = ?2, db_name = ?3, db_user = ?4, db_pass = ?5 WHERE id = ?6",
            params![ftp_user, ftp_pass, db_name, db_user, db_pass, id],
        )
    }

    pub fn create_site(
        &self,
        domain: &str,
        site_type: &str,
        root_path: &str,
        proxy_port: i64,
        php_version: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sites (domain, site_type, root_path, proxy_port, php_version, ssl_enabled, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 'active', ?6)",
            params![domain, site_type, root_path, proxy_port, php_version, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_site_php(&self, id: i64, php_version: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sites SET php_version = ?1 WHERE id = ?2",
            params![php_version, id],
        )
    }

    pub fn update_site_ssl(&self, id: i64, enabled: bool) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sites SET ssl_enabled = ?1 WHERE id = ?2",
            params![if enabled { 1 } else { 0 }, id],
        )
    }

    pub fn delete_site(&self, id: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sites WHERE id = ?1", params![id])
    }

    pub fn list_apps(&self) -> Result<Vec<AppRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, language, work_dir, exec_cmd, port, status, created_at FROM apps ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AppRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                language: r.get(2)?,
                work_dir: r.get(3)?,
                exec_cmd: r.get(4)?,
                port: r.get(5)?,
                status: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn create_app(
        &self,
        name: &str,
        language: &str,
        work_dir: &str,
        exec_cmd: &str,
        port: i64,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO apps (name, language, work_dir, exec_cmd, port, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'stopped', ?6)",
            params![name, language, work_dir, exec_cmd, port, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_app_status(&self, id: i64, status: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE apps SET status = ?1 WHERE id = ?2",
            params![status, id],
        )
    }

    pub fn delete_app(&self, id: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM apps WHERE id = ?1", params![id])
    }

    pub fn seed_forum_if_empty(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM forum_posts", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let admin_hash = hash_secret("cmake2026!");
        conn.execute(
            "INSERT INTO forum_posts (category, title, author, password_hash, content, views, likes, is_pinned, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 42, 7, 1, ?6, ?6)",
            params![
                "notice",
                "CHost v0.1.0 공개 및 공식 포럼 오픈 안내",
                "CHost Team",
                admin_hash,
                "CHost는 Rust 단일 바이너리로 동작하는 초경량 한국형 서버 관리 패널입니다.\n\n주요 기능:\n1. 실시간 CPU/RAM/디스크 모니터링 및 80% 초과 경고\n2. /www/wwwroot 기반 도메인 추가 및 Nginx/SSL 자동화\n3. PHP 다중 버전(7.4~8.4) 원클릭 설치 및 사이트별 스위칭\n4. Rust/Python/Node.js/PHP 언어 프리셋 앱 프로세스 관리\n5. phpMyAdmin 없는 내장 멀티 DB 스튜디오 (SQLite / MariaDB)\n6. 안전한 로그 로테이션(copytruncate) 및 저장 공간 정리\n\n버그 제보나 기능 제안은 아래 포럼에 자유롭게 남겨주세요.",
                now
            ],
        )?;
        conn.execute(
            "INSERT INTO forum_posts (category, title, author, password_hash, content, views, likes, is_pinned, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 19, 3, 0, ?6, ?6)",
            params![
                "tip",
                "Ubuntu 22.04 / 24.04 환경에서 1줄 설치 후 초기 비밀번호 확인 방법",
                "1clickmake",
                admin_hash,
                "install.sh 스크립트 실행이 완료되면 /var/lib/chost/init_password.txt 파일에 초기 비밀번호가 자동 생성됩니다.\n\n로그인 후 보안 탭에서 2FA 및 접속 IP 제한을 설정하시는 것을 권장합니다.",
                now
            ],
        )?;
        Ok(())
    }

    pub fn list_forum_posts(&self, category: &str, query: &str) -> Result<Vec<ForumPost>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT p.id, p.category, p.title, p.author, p.content, p.views, p.likes, p.is_pinned,
                    (SELECT COUNT(*) FROM forum_comments c WHERE c.post_id = p.id) as comment_count,
                    p.created_at, p.updated_at
             FROM forum_posts p WHERE 1=1",
        );
        if !category.is_empty() && category != "all" {
            sql.push_str(" AND p.category = ?1");
        }
        if !query.is_empty() {
            if !category.is_empty() && category != "all" {
                sql.push_str(" AND (p.title LIKE ?2 OR p.content LIKE ?2)");
            } else {
                sql.push_str(" AND (p.title LIKE ?1 OR p.content LIKE ?1)");
            }
        }
        sql.push_str(" ORDER BY p.is_pinned DESC, p.id DESC");

        let mut stmt = conn.prepare(&sql)?;
        let like_q = format!("%{}%", query);
        let mapper = |r: &rusqlite::Row| {
            Ok(ForumPost {
                id: r.get(0)?,
                category: r.get(1)?,
                title: r.get(2)?,
                author: r.get(3)?,
                content: r.get(4)?,
                views: r.get(5)?,
                likes: r.get(6)?,
                is_pinned: r.get::<_, i64>(7)? != 0,
                comment_count: r.get(8)?,
                created_at: r.get(9)?,
                updated_at: r.get(10)?,
            })
        };

        if !category.is_empty() && category != "all" && !query.is_empty() {
            stmt.query_map(params![category, like_q], mapper)?.collect()
        } else if !category.is_empty() && category != "all" {
            stmt.query_map(params![category], mapper)?.collect()
        } else if !query.is_empty() {
            stmt.query_map(params![like_q], mapper)?.collect()
        } else {
            stmt.query_map([], mapper)?.collect()
        }
    }

    pub fn get_forum_post(&self, id: i64) -> Result<Option<(ForumPost, Vec<ForumComment>)>> {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute("UPDATE forum_posts SET views = views + 1 WHERE id = ?1", params![id]);
        let post_res = conn.query_row(
            "SELECT p.id, p.category, p.title, p.author, p.content, p.views, p.likes, p.is_pinned,
                    (SELECT COUNT(*) FROM forum_comments c WHERE c.post_id = p.id) as comment_count,
                    p.created_at, p.updated_at
             FROM forum_posts p WHERE p.id = ?1",
            params![id],
            |r| {
                Ok(ForumPost {
                    id: r.get(0)?,
                    category: r.get(1)?,
                    title: r.get(2)?,
                    author: r.get(3)?,
                    content: r.get(4)?,
                    views: r.get(5)?,
                    likes: r.get(6)?,
                    is_pinned: r.get::<_, i64>(7)? != 0,
                    comment_count: r.get(8)?,
                    created_at: r.get(9)?,
                    updated_at: r.get(10)?,
                })
            },
        );
        let post = match post_res {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let mut cstmt = conn.prepare(
            "SELECT id, post_id, author, content, created_at FROM forum_comments WHERE post_id = ?1 ORDER BY id ASC",
        )?;
        let comments = cstmt
            .query_map(params![id], |r| {
                Ok(ForumComment {
                    id: r.get(0)?,
                    post_id: r.get(1)?,
                    author: r.get(2)?,
                    content: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>>>()?;
        Ok(Some((post, comments)))
    }

    pub fn create_forum_post(
        &self,
        category: &str,
        title: &str,
        author: &str,
        password: &str,
        content: &str,
        is_pinned: bool,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let pw_hash = hash_secret(password);
        conn.execute(
            "INSERT INTO forum_posts (category, title, author, password_hash, content, views, likes, is_pinned, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, ?7)",
            params![category, title, author, pw_hash, content, if is_pinned { 1 } else { 0 }, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn like_forum_post(&self, id: i64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE forum_posts SET likes = likes + 1 WHERE id = ?1", params![id])?;
        conn.query_row("SELECT likes FROM forum_posts WHERE id = ?1", params![id], |r| r.get(0))
    }

    pub fn delete_forum_post(&self, id: i64, password: &str, admin_pw: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let stored: String = conn.query_row(
            "SELECT password_hash FROM forum_posts WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        if password == admin_pw || hash_secret(password) == stored {
            conn.execute("DELETE FROM forum_comments WHERE post_id = ?1", params![id])?;
            conn.execute("DELETE FROM forum_posts WHERE id = ?1", params![id])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn create_forum_comment(
        &self,
        post_id: i64,
        author: &str,
        password: &str,
        content: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let pw_hash = hash_secret(password);
        conn.execute(
            "INSERT INTO forum_comments (post_id, author, password_hash, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![post_id, author, pw_hash, content, now],
        )?;
        Ok(conn.last_insert_rowid())
    }
}
