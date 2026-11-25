mod db;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use db::Database;
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::PathBuf, sync::Arc};
use tower_http::cors::CorsLayer;

struct PortalState {
    db: Database,
    admin_pw: String,
}

#[derive(Debug, Deserialize)]
struct ForumQuery {
    category: Option<String>,
    q: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreatePostReq {
    category: String,
    title: String,
    author: String,
    password: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct DeletePostReq {
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateCommentReq {
    author: String,
    password: String,
    content: String,
}

async fn serve_page(file: &str) -> Response {
    match fs::read_to_string(file) {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Page not found").into_response(),
    }
}

async fn serve_home() -> Response {
    serve_page("portal/index.html").await
}

async fn serve_docs() -> Response {
    serve_page("portal/docs.html").await
}

async fn serve_forum() -> Response {
    serve_page("portal/forum.html").await
}

async fn handle_health() -> Response {
    Json(json!({ "ok": true, "service": "chost-portal" })).into_response()
}

async fn handle_list_posts(
    State(state): State<Arc<PortalState>>,
    Query(q): Query<ForumQuery>,
) -> Response {
    let cat = q.category.unwrap_or_else(|| "all".to_string());
    let query = q.q.unwrap_or_default();
    let posts = state.db.list_forum_posts(&cat, &query).unwrap_or_default();
    Json(json!({ "success": true, "posts": posts })).into_response()
}

async fn handle_get_post(
    State(state): State<Arc<PortalState>>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.get_forum_post(id) {
        Ok(Some((post, comments))) => {
            Json(json!({ "success": true, "post": post, "comments": comments })).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response(),
    }
}

async fn handle_create_post(
    State(state): State<Arc<PortalState>>,
    Json(req): Json<CreatePostReq>,
) -> Response {
    let title = req.title.trim();
    let author = req.author.trim();
    let content = req.content.trim();
    if title.is_empty() || author.is_empty() || content.is_empty() || req.password.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "모든 필수 항목을 입력해 주세요." })),
        )
            .into_response();
    }
    let cat = match req.category.as_str() {
        "notice" | "qna" | "feature" | "bug" | "tip" => req.category.as_str(),
        _ => "qna",
    };
    let is_pinned = cat == "notice" && req.password.trim() == state.admin_pw;
    match state
        .db
        .create_forum_post(cat, title, author, req.password.trim(), content, is_pinned)
    {
        Ok(id) => Json(json!({ "success": true, "id": id })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn handle_like_post(
    State(state): State<Arc<PortalState>>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.like_forum_post(id) {
        Ok(likes) => Json(json!({ "success": true, "likes": likes })).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response(),
    }
}

async fn handle_delete_post(
    State(state): State<Arc<PortalState>>,
    Path(id): Path<i64>,
    Json(req): Json<DeletePostReq>,
) -> Response {
    match state
        .db
        .delete_forum_post(id, req.password.trim(), &state.admin_pw)
    {
        Ok(true) => Json(json!({ "success": true })).into_response(),
        Ok(false) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "비밀번호가 일치하지 않습니다." })),
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "success": false }))).into_response(),
    }
}

async fn handle_create_comment(
    State(state): State<Arc<PortalState>>,
    Path(id): Path<i64>,
    Json(req): Json<CreateCommentReq>,
) -> Response {
    let author = req.author.trim();
    let content = req.content.trim();
    if author.is_empty() || content.is_empty() || req.password.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "작성자, 비밀번호, 댓글 내용을 입력해 주세요." })),
        )
            .into_response();
    }
    match state
        .db
        .create_forum_comment(id, author, req.password.trim(), content)
    {
        Ok(cid) => Json(json!({ "success": true, "id": cid })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    let data_dir = PathBuf::from(
        std::env::var("CHOST_PORTAL_DATA").unwrap_or_else(|_| "data".to_string()),
    );
    let _ = fs::create_dir_all(&data_dir);
    let db_path = data_dir.join("portal.db");
    let db = Database::open(&db_path.to_string_lossy()).expect("Failed to open portal DB");
    let _ = db.seed_forum_if_empty();

    let admin_pw = std::env::var("CHOST_ADMIN_PW").unwrap_or_else(|_| "cmake2026!".to_string());
    let state = Arc::new(PortalState { db, admin_pw });

    let app = Router::new()
        .route("/", get(serve_home))
        .route("/docs", get(serve_docs))
        .route("/forum", get(serve_forum))
        .route("/health", get(handle_health))
        .route("/api/forum/posts", get(handle_list_posts).post(handle_create_post))
        .route(
            "/api/forum/posts/{id}",
            get(handle_get_post).delete(handle_delete_post),
        )
        .route("/api/forum/posts/{id}/like", post(handle_like_post))
        .route("/api/forum/posts/{id}/comments", post(handle_create_comment))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("CHOST_PORTAL_PORT").unwrap_or_else(|_| "8098".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("CHost portal listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
