mod config;
mod db;
mod ebpf;
mod status;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Duration, Utc};
use db::{
    cleanup_expired_sessions, create_app, create_audit_log, create_session, create_user,
    delete_app, delete_session, find_session, find_user_by_username, get_all_apps,
    get_app_by_id, get_audit_logs, get_user_apps, get_all_users,
    init_database, seed_default_apps, set_user_permissions, user_has_app_permission,
};
use log::{error, info, warn};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::http_proxy_service;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};
use status::StatusCollector;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

struct AppState {
    status: StatusCollector,
    ebpf: ebpf::EbpfMonitor,
    db: sea_orm::DatabaseConnection,
}

struct App {
    state: Arc<Mutex<AppState>>,
    static_files: HashMap<String, Vec<u8>>,
    dashboard_index: String,
    session_hours: i64,
    demo: bool,
}

#[derive(Deserialize)]
struct LoginRequest { username: String, password: String }

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Self { Self { success: true, data: Some(data), error: None } }
    fn err(msg: &str) -> Self { Self { success: false, data: None, error: Some(msg.to_string()) } }
}

#[derive(Serialize)]
struct LoginResponse {
    session_id: String,
    username: String,
    role: String,
    apps: Vec<db::App>,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    username: Option<String>,
    role: Option<String>,
}

#[derive(Deserialize)]
struct CreateAppRequest { name: String, description: String, url: String, icon_url: Option<String> }

#[derive(Deserialize)]
struct CreateUserRequest { username: String, password: String, role: String }

#[derive(Deserialize)]
struct UpdatePermissionsRequest { app_ids: Vec<i64> }

fn load_static_files(dist_dir: &Path) -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(dist_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(data) = std::fs::read(&path) {
                    map.insert(format!("/{}", name), data);
                }
            }
        }
    }
    map
}

fn get_mime(path: &str) -> &str {
    if path.ends_with(".html") { "text/html; charset=utf-8" }
    else if path.ends_with(".js") { "application/javascript" }
    else if path.ends_with(".wasm") { "application/wasm" }
    else { "application/octet-stream" }
}

async fn respond_static(session: &mut Session, data: &[u8], mime: &str) {
    let mut resp = match pingora_http::ResponseHeader::build(http::StatusCode::OK, Some(4)) {
        Ok(r) => r,
        Err(_) => return,
    };
    resp.insert_header("Content-Type", mime).ok();
    resp.insert_header("Content-Length", data.len().to_string()).ok();
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(Bytes::from(data.to_vec())), true).await;
}

fn json_body<T: Serialize>(body: &T) -> Bytes {
    Bytes::from(serde_json::to_string(body).unwrap_or_default())
}

fn json_error(msg: &str) -> Bytes {
    Bytes::from(serde_json::to_string(&ApiResponse::<()>::err(msg)).unwrap_or_default())
}

fn extract_session_id(session: &Session) -> Option<String> {
    session.req_header().headers.get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                if c.starts_with("session=") { Some(c[8..].to_string()) } else { None }
            })
        })
}

fn get_source_ip(session: &Session) -> String {
    session.client_addr().map(|a| a.to_string()).unwrap_or_default()
}

async fn read_full_request_body(session: &mut Session) -> String {
    let mut full_body = Vec::new();
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => full_body.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                break;
            }
        }
    }
    if full_body.is_empty() {
        String::new()
    } else {
        String::from_utf8_lossy(&full_body).to_string()
    }
}

async fn verify_auth(state: &AppState, session: &Session) -> Option<db::User> {
    let session_id = extract_session_id(session)?;
    let s = find_session(&state.db, &session_id).await.ok()??;
    let expires = chrono::NaiveDateTime::parse_from_str(&s.expires_at, "%Y-%m-%d %H:%M:%S")
        .ok().map(|t| t.and_utc())?;
    if Utc::now() < expires {
        db::find_user_by_id(&state.db, s.user_id).await.ok().flatten()
    } else { None }
}

async fn verify_admin(state: &AppState, session: &Session) -> bool {
    verify_auth(state, session).await.map(|u| u.role == "admin").unwrap_or(false)
}

async fn respond(session: &mut Session, body: Bytes) {
    session.set_keepalive(None);
    if let Err(e) = session.respond_error_with_body(200, body).await {
        error!("Failed to send response: {}", e);
    }
}

async fn respond_with_cookie(session: &mut Session, body: Bytes, cookie: &str) {
    session.set_keepalive(None);
    let len = body.len();
    let mut resp = match pingora_http::ResponseHeader::build(http::StatusCode::OK, Some(4)) {
        Ok(r) => r,
        Err(_) => return,
    };
    resp.insert_header("Content-Type", "application/json").ok();
    resp.insert_header("Content-Length", len.to_string()).ok();
    resp.insert_header("Set-Cookie", cookie).ok();
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(body), true).await;
}

async fn respond_html(session: &mut Session, html: String) {
    let body = Bytes::from(html);
    if let Err(e) = session.respond_error_with_body(200, body).await {
        error!("Failed to send HTML response: {}", e);
    }
}

//// HTML Templates

const LOGIN_HTML: &str = include_str!("../html/login.html");

fn inject_demo_flag(html: &str) -> String {
    html.replace("</head>", "<script>window.__VPN_DEMO__=true;</script></head>")
}

//// ProxyHttp

#[async_trait]
impl ProxyHttp for App {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, error: &pingora_core::Error) -> bool {
        match error.etype() {
            pingora_core::ErrorType::Custom("api_handled" | "page_served") => true,
            _ => false,
        }
    }

    async fn fail_to_proxy(
        &self,
        _session: &mut Session,
        error: &pingora_core::Error,
        _ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy {
        match error.etype() {
            pingora_core::ErrorType::Custom("api_handled" | "page_served") => {
                pingora_proxy::FailToProxy {
                    error_code: 0,
                    can_reuse_downstream: false,
                }
            }
            _ => pingora_proxy::FailToProxy {
                error_code: 500,
                can_reuse_downstream: false,
            },
        }
    }

    async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()>
    where Self::CTX: Send + Sync
    {
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let method = req.method.as_str().to_string();

        let request_len: u64 = req.headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut state = self.state.lock().await;
        state.status.record_request("global", 0, request_len);

        if path.starts_with("/api/") {
            drop(state);
            self.handle_api(session, &method, &path).await;
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::Custom("api_handled"), "API",
            ));
        }

        if path == "/" || path == "/index.html" {
            let auth_user = if self.demo { None } else { verify_auth(&state, session).await };
            drop(state);
            if auth_user.is_some() || self.demo {
                let html = if self.demo {
                    inject_demo_flag(&self.dashboard_index)
                } else {
                    self.dashboard_index.clone()
                };
                respond_html(session, html).await;
            } else {
                respond_html(session, LOGIN_HTML.to_string()).await;
            }
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::Custom("page_served"), "Page",
            ));
        }

        if let Some(data) = self.static_files.get(&path) {
            let mime = get_mime(&path);
            respond_static(session, data, mime).await;
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::Custom("page_served"), "Static",
            ));
        }

        Ok(())
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let source_ip = get_source_ip(session);

        let state = self.state.lock().await;

        if self.demo {
            drop(state);
            return Ok(Box::new(HttpPeer::new("127.0.0.1:80".to_string(), false, "".to_string())));
        }

        let user = match verify_auth(&state, session).await {
            Some(u) => u,
            None => {
                drop(state);
                if let Err(e) = session.respond_error_with_body(401, json_error("Authentication required")).await {
                    error!("Failed to send 401: {}", e);
                }
                return Err(pingora_core::Error::explain(pingora_core::ErrorType::Custom("unauthorized"), "Auth required"));
            }
        };

        if path.starts_with("/proxy/") {
            let remainder = &path[7..];
            let parts: Vec<&str> = remainder.splitn(2, '/').collect();
            let app_id = parts[0].parse::<i64>().unwrap_or(0);
            let is_admin_user = user.role == "admin";

            if !is_admin_user {
                let has_perm = user_has_app_permission(&state.db, user.id, app_id).await.unwrap_or(false);
                if !has_perm {
                    let db = &state.db;
                    let _ = create_audit_log(db, Some(user.id), "access_denied", &source_ip, &path, "denied").await;
                    drop(state);
                    if let Err(e) = session.respond_error_with_body(403, json_error("Access denied")).await {
                        error!("Failed to send 403: {}", e);
                    }
                    return Err(pingora_core::Error::explain(pingora_core::ErrorType::Custom("forbidden"), "Access denied"));
                }
            }

            match get_app_by_id(&state.db, app_id).await {
                Ok(Some(app)) => {
                    let _ = create_audit_log(&state.db, Some(user.id), "proxy_access", &source_ip, &format!("{} -> {}", path, app.url), "success").await;
                    let target = app.url.trim_end_matches('/').to_string();
                    drop(state);
                    Ok(Box::new(HttpPeer::new(target, false, "".to_string())))
                }
                Ok(None) => {
                    drop(state);
                    if let Err(e) = session.respond_error_with_body(404, json_error("Application not found")).await {
                        error!("Failed to send 404: {}", e);
                    }
                    Err(pingora_core::Error::explain(pingora_core::ErrorType::Custom("not_found"), "App not found"))
                }
                Err(_) => {
                    drop(state);
                    if let Err(e) = session.respond_error_with_body(500, json_error("Internal error")).await {
                        error!("Failed to send 500: {}", e);
                    }
                    Err(pingora_core::Error::explain(pingora_core::ErrorType::Custom("internal_error"), "DB error"))
                }
            }
        } else {
            drop(state);
            Ok(Box::new(HttpPeer::new("127.0.0.1:80".to_string(), false, "".to_string())))
        }
    }
}

//// API handlers

impl App {
    async fn handle_api(&self, session: &mut Session, method: &str, path: &str) {
        let mut state = self.state.lock().await;
        let source_ip = get_source_ip(session);
        let session_hours = self.session_hours;

        let (response_body, cookie) = match (method, path) {
            ("POST", "/api/auth/login") => {
                drop(state);
                let body = read_full_request_body(session).await;
                let mut state = self.state.lock().await;
                handle_login(&mut *state, &source_ip, &body, session_hours, self.demo).await
            }
            ("POST", "/api/auth/logout") => {
                (handle_logout(&mut *state, session, &source_ip).await, String::new())
            }
            ("GET", "/api/auth/session") => {
                (handle_session_check(&state, session, self.demo).await, String::new())
            }
            ("GET", "/api/status") => {
                let mut stats = state.status.get_stats();
                let ebpf_stats = state.ebpf.read_stats();
                if ebpf_stats.bytes_sent > 0 || ebpf_stats.bytes_recv > 0 {
                    stats.bytes_sent = ebpf_stats.bytes_sent;
                    stats.bytes_recv = ebpf_stats.bytes_recv;
                    stats.connections = ebpf_stats.active_conns;
                }
                (json_body(&stats), String::new())
            }
            ("GET", "/api/apps") => {
                (handle_get_apps(&state, session, self.demo).await, String::new())
            }
            ("POST", "/api/apps") => {
                drop(state);
                let body = read_full_request_body(session).await;
                let state = self.state.lock().await;
                (handle_create_app(&state, session, &body).await, String::new())
            }
            ("DELETE", _) if path.starts_with("/api/apps/") => {
                let app_id = path[10..].parse::<i64>().unwrap_or(0);
                (handle_delete_app(&state, session, app_id).await, String::new())
            }
            ("GET", "/api/users") => {
                (handle_get_users(&state, session).await, String::new())
            }
            ("POST", "/api/users") => {
                drop(state);
                let body = read_full_request_body(session).await;
                let state = self.state.lock().await;
                (handle_create_user_api(&state, session, &body).await, String::new())
            }
            ("PUT", _) if path.starts_with("/api/users/") && path.ends_with("/permissions") => {
                let user_id = path[10..path.len()-12].parse::<i64>().unwrap_or(0);
                drop(state);
                let body = read_full_request_body(session).await;
                let state = self.state.lock().await;
                (handle_update_permissions(&state, session, user_id, &body).await, String::new())
            }
            ("GET", "/api/audit") => {
                (handle_get_audit_logs(&state, session, self.demo).await, String::new())
            }
            _ => (json_error("API endpoint not found"), String::new()),
        };

        if cookie.is_empty() {
            respond(session, response_body).await;
        } else {
            respond_with_cookie(session, response_body, &cookie).await;
        }
    }
}

async fn handle_demo_login(state: &mut AppState, source_ip: &str, session_hours: i64) -> (Bytes, String) {
    let demo_user = match find_user_by_username(&state.db, "admin").await {
        Ok(Some(u)) => u,
        _ => {
            let hash = argon2::hash_encoded(b"admin123", b"web-ssl-vpn-salt-2024", &argon2::Config::default()).unwrap_or_default();
            match create_user(&state.db, "admin", &hash, "admin").await {
                Ok(u) => u,
                Err(_) => return (json_error("Failed to create demo user"), String::new()),
            }
        }
    };

    let session_id = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::hours(session_hours)).format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = create_session(&state.db, demo_user.id, &session_id, &expires_at).await {
        error!("Failed to create demo session: {}", e);
        return (json_error("Internal error"), String::new());
    }
    state.status.add_session(session_id.clone());

    let _ = create_audit_log(&state.db, Some(demo_user.id), "login", source_ip, "/api/auth/login", "success").await;
    let apps = get_user_apps(&state.db, demo_user.id).await.unwrap_or_default();
    info!("Demo login from {}", source_ip);

    let max_age = session_hours * 3600;
    let cookie = format!("session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}", session_id, max_age);
    (json_body(&ApiResponse::ok(&LoginResponse {
        session_id, username: demo_user.username, role: demo_user.role, apps,
    })), cookie)
}

async fn handle_login(state: &mut AppState, source_ip: &str, body: &str, session_hours: i64, demo: bool) -> (Bytes, String) {
    if demo {
        return handle_demo_login(state, source_ip, session_hours).await;
    }

    let login: LoginRequest = match serde_json::from_str(body) {
        Ok(l) => l,
        Err(_) => return (json_error("Invalid request body"), String::new()),
    };

    match find_user_by_username(&state.db, &login.username).await {
        Ok(Some(user)) => {
            let valid = argon2::verify_encoded(&user.password_hash, login.password.as_bytes()).unwrap_or(false);
            if valid {
                let session_id = Uuid::new_v4().to_string();
                let expires_at = (Utc::now() + Duration::hours(session_hours)).format("%Y-%m-%d %H:%M:%S").to_string();
                if let Err(e) = create_session(&state.db, user.id, &session_id, &expires_at).await {
                    error!("Failed to create session: {}", e);
                    return (json_error("Internal error"), String::new());
                }
                state.status.add_session(session_id.clone());
                let _ = create_audit_log(&state.db, Some(user.id), "login", source_ip, "/api/auth/login", "success").await;
                let apps = get_user_apps(&state.db, user.id).await.unwrap_or_default();
                info!("User '{}' logged in from {}", login.username, source_ip);
                let max_age = session_hours * 3600;
                let cookie = format!("session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}", session_id, max_age);
                (json_body(&ApiResponse::ok(&LoginResponse {
                    session_id, username: user.username, role: user.role, apps,
                })), cookie)
            } else {
                let _ = create_audit_log(&state.db, None, "login_failed", source_ip, &format!("user: {}", login.username), "invalid_password").await;
                (json_error("Invalid username or password"), String::new())
            }
        }
        Ok(None) => {
            let _ = create_audit_log(&state.db, None, "login_failed", source_ip, &format!("user: {}", login.username), "user_not_found").await;
            (json_error("Invalid username or password"), String::new())
        }
        Err(e) => { error!("DB error during login: {}", e); (json_error("Internal error"), String::new()) }
    }
}

async fn handle_logout(state: &mut AppState, session: &Session, source_ip: &str) -> Bytes {
    let session_id = extract_session_id(session);
    if let Some(sid) = &session_id {
        if let Ok(Some(s)) = find_session(&state.db, sid).await {
            let _ = create_audit_log(&state.db, Some(s.user_id), "logout", source_ip, "/api/auth/logout", "success").await;
        }
        state.status.remove_session(sid);
        let _ = delete_session(&state.db, sid).await;
    }
    json_body(&ApiResponse::ok(&"Logged out successfully"))
}

async fn handle_session_check(state: &AppState, session: &Session, demo: bool) -> Bytes {
    if demo {
        return json_body(&ApiResponse::ok(&SessionResponse {
            authenticated: true,
            username: Some("admin".to_string()),
            role: Some("admin".to_string()),
        }));
    }
    match verify_auth(state, session).await {
        Some(user) => json_body(&ApiResponse::ok(&SessionResponse { authenticated: true, username: Some(user.username), role: Some(user.role) })),
        None => json_body(&ApiResponse::ok(&SessionResponse { authenticated: false, username: None, role: None })),
    }
}

async fn handle_get_apps(state: &AppState, session: &Session, demo: bool) -> Bytes {
    if demo {
        let apps = get_all_apps(&state.db).await.unwrap_or_default();
        return json_body(&ApiResponse::ok(&apps));
    }
    match verify_auth(state, session).await {
        Some(user) => {
            let apps = if user.role == "admin" { get_all_apps(&state.db).await.unwrap_or_default() }
                       else { get_user_apps(&state.db, user.id).await.unwrap_or_default() };
            json_body(&ApiResponse::ok(&apps))
        }
        None => json_error("Authentication required"),
    }
}

async fn handle_create_app(state: &AppState, session: &Session, body: &str) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let req: CreateAppRequest = match serde_json::from_str(body) { Ok(r) => r, Err(_) => return json_error("Invalid request body") };
    match create_app(&state.db, &req.name, &req.description, &req.url, &req.icon_url.unwrap_or_default()).await {
        Ok(app) => json_body(&ApiResponse::ok(&app)),
        Err(e) => { error!("Failed to create app: {}", e); json_error("Failed to create application") }
    }
}

async fn handle_delete_app(state: &AppState, session: &Session, app_id: i64) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    match delete_app(&state.db, app_id).await {
        Ok(_) => json_body(&ApiResponse::ok(&"Application deleted")),
        Err(e) => { error!("Failed to delete app: {}", e); json_error("Failed to delete application") }
    }
}

async fn handle_get_users(state: &AppState, session: &Session) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let users = get_all_users(&state.db).await.unwrap_or_default();
    let safe_users: Vec<serde_json::Value> = users.into_iter().map(|u| serde_json::json!({"id": u.id, "username": u.username, "role": u.role, "created_at": u.created_at})).collect();
    json_body(&ApiResponse::ok(&safe_users))
}

async fn handle_create_user_api(state: &AppState, session: &Session, body: &str) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let req: CreateUserRequest = match serde_json::from_str(body) { Ok(r) => r, Err(_) => return json_error("Invalid request body") };
    let hash = match argon2::hash_encoded(req.password.as_bytes(), b"web-ssl-vpn-salt-2024", &argon2::Config::default()) {
        Ok(h) => h,
        Err(_) => return json_error("Failed to hash password"),
    };
    match create_user(&state.db, &req.username, &hash, &req.role).await {
        Ok(user) => json_body(&ApiResponse::ok(&serde_json::json!({"id": user.id, "username": user.username, "role": user.role, "created_at": user.created_at}))),
        Err(e) => { error!("Failed to create user: {}", e); json_error("Failed to create user") }
    }
}

async fn handle_update_permissions(state: &AppState, session: &Session, user_id: i64, body: &str) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let req: UpdatePermissionsRequest = match serde_json::from_str(body) { Ok(r) => r, Err(_) => return json_error("Invalid request body") };
    match set_user_permissions(&state.db, user_id, &req.app_ids).await {
        Ok(_) => json_body(&ApiResponse::ok(&"Permissions updated")),
        Err(e) => { error!("Failed to update permissions: {}", e); json_error("Failed to update permissions") }
    }
}

async fn handle_get_audit_logs(state: &AppState, session: &Session, demo: bool) -> Bytes {
    if demo {
        let logs = get_audit_logs(&state.db, 100).await.unwrap_or_default();
        if logs.is_empty() {
            return json_body(&ApiResponse::ok(&demo_audit_logs()));
        }
        return json_body(&ApiResponse::ok(&logs));
    }
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let logs = get_audit_logs(&state.db, 100).await.unwrap_or_default();
    json_body(&ApiResponse::ok(&logs))
}

fn demo_audit_logs() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"id": 1, "timestamp": "09:30:00", "user_id": 1, "action": "login", "target_url": "/api/auth/login", "source_ip": "192.168.1.100", "result": "success"}),
        serde_json::json!({"id": 2, "timestamp": "09:31:00", "user_id": 2, "action": "proxy_access", "target_url": "wiki.internal:3000", "source_ip": "10.0.0.55", "result": "success"}),
        serde_json::json!({"id": 3, "timestamp": "09:32:00", "user_id": 3, "action": "access_denied", "target_url": "mail.internal:8080", "source_ip": "192.168.1.200", "result": "denied"}),
        serde_json::json!({"id": 4, "timestamp": "09:33:00", "user_id": 1, "action": "proxy_access", "target_url": "files.internal:9000", "source_ip": "192.168.1.100", "result": "success"}),
        serde_json::json!({"id": 5, "timestamp": "09:34:00", "user_id": 2, "action": "logout", "target_url": "/api/auth/logout", "source_ip": "10.0.0.55", "result": "success"}),
    ]
}

//// Main

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = config::ServerConfig::from_env();
    config.print_config();

    info!("Starting Web SSL VPN server");

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => { error!("Failed to create Tokio runtime: {}", e); std::process::exit(1); }
    };

    let db_path = &config.db_path;
    let session_hours = config.session_hours;
    let db = rt.block_on(async {
        match init_database(db_path).await {
            Ok(db) => {
                info!("Database initialized successfully");
                let _ = cleanup_expired_sessions(&db).await;
                if let Err(e) = seed_default_apps(&db).await {
                    error!("Failed to seed default apps: {}", e);
                }
                db
            }
            Err(e) => {
                error!("Database initialization failed: {}", e);
                std::process::exit(1);
            }
        }
    });

    let ebpf_monitor = ebpf::EbpfMonitor::try_new(&config.ebpf_iface);
    let state = Arc::new(Mutex::new(AppState { status: StatusCollector::new(), ebpf: ebpf_monitor, db }));

    let static_files = load_static_files(&config.static_dir);
    let dashboard_index = static_files.get("/index.html")
        .map(|d| String::from_utf8_lossy(d).to_string())
        .unwrap_or_else(|| "<h1>WASM not built: run zig build trunk</h1>".to_string());
    info!("Loaded {} static files from {}", static_files.len(), config.static_dir.display());

    let mut server = match Server::new(None) {
        Ok(s) => s,
        Err(e) => { error!("Failed to create server: {:?}", e); std::process::exit(1); }
    };
    server.bootstrap();

    let app = App { state, static_files, dashboard_index, session_hours, demo: config.demo };
    let mut proxy = http_proxy_service(&server.configuration, app);
    proxy.add_tcp(&config.http_bind);
    info!("HTTP listener on {}", config.http_bind);

    if config.is_tls_configured() {
        let cert = config.tls_cert.to_string_lossy().to_string();
        let key = config.tls_key.to_string_lossy().to_string();
        match TlsSettings::intermediate(&cert, &key) {
            Ok(mut tls_settings) => {
                tls_settings.enable_h2();
                proxy.add_tls_with_settings(&config.https_bind, None, tls_settings);
                info!("HTTPS listener on {}", config.https_bind);
            }
            Err(e) => error!("TLS settings failed (HTTPS unavailable): {:?}", e),
        }
    } else {
        warn!("TLS certificates not found - HTTPS disabled");
    }

    server.add_service(proxy);
    if config.demo {
        warn!("================================================");
        warn!("  DEMO MODE ENABLED");
        warn!("  Authentication is bypassed");
        warn!("  Data may be simulated");
        warn!("  Default admin: admin / admin123");
        warn!("================================================");
    }
    info!("Web SSL VPN running: https://localhost:8443 | admin / admin123");
    server.run_forever();
}
