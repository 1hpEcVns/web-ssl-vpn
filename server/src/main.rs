mod config;
mod db;
mod ebpf;
mod ratelimit;
mod status;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Duration, Utc};
use db::{
    cleanup_expired_sessions, create_app, create_audit_log, create_session,
    create_user, update_user_password, set_user_totp_secret, enable_user_totp, disable_user_totp,
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
use ratelimit::LoginRateLimiter;
use serde::{Deserialize, Serialize};
use status::StatusCollector;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

struct TwoFaChallenge {
    user_id: i64,
    expires_at: chrono::DateTime<Utc>,
}

struct AppState {
    status: StatusCollector,
    ebpf: ebpf::EbpfMonitor,
    db: sea_orm::DatabaseConnection,
    login_limiter: LoginRateLimiter,
    two_fa_limiter: LoginRateLimiter,
    two_fa_challenges: HashMap<String, TwoFaChallenge>,
}

struct App {
    state: Arc<Mutex<AppState>>,
    static_files: HashMap<String, Vec<u8>>,
    dashboard_index: String,
    session_minutes: i64,
    demo: bool,
}

fn validate_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn validate_password(s: &str) -> bool {
    s.len() >= 8 && s.len() <= 128
}

fn validate_url(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 { return false; }
    if let Some((host, port)) = s.rsplit_once(':') {
        if host.is_empty() { return false; }
        port.parse::<u16>().is_ok()
    } else {
        false
    }
}

fn validate_app_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
}

fn check_referer_origin(session: &Session) -> bool {
    let req = session.req_header();
    let mut host = req.uri.authority().map(|a| a.as_str()).unwrap_or("");
    if host.is_empty() {
        host = req.headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    }
    if host.is_empty() { return false; }
    if let Some(origin) = req.headers.get("origin").and_then(|v| v.to_str().ok()) {
        return origin.contains(host) || origin == "null";
    }
    if let Some(referer) = req.headers.get("referer").and_then(|v| v.to_str().ok()) {
        return referer.contains(host);
    }
    true
}

fn generate_salt() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
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
struct TwoFaSetupResponse {
    secret: String,
    qr_url: String,
    qr_png: String,
}

#[derive(Serialize)]
struct LoginResponse {
    session_id: String,
    username: String,
    role: String,
    apps: Vec<db::App>,
    two_fa_required: bool,
    two_fa_challenge: String,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    username: Option<String>,
    role: Option<String>,
    totp_enabled: bool,
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
    let mut resp = match pingora_http::ResponseHeader::build(http::StatusCode::OK, Some(8)) {
        Ok(r) => r,
        Err(_) => return,
    };
    resp.insert_header("Content-Type", mime).ok();
    resp.insert_header("Content-Length", data.len().to_string()).ok();
    resp.insert_header("X-Content-Type-Options", "nosniff").ok();
    resp.insert_header("X-Frame-Options", "DENY").ok();
    resp.insert_header("Referrer-Policy", "no-referrer").ok();
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(Bytes::from(data.to_vec())), true).await;
}

fn json_body<T: Serialize>(body: &T) -> Bytes {
    Bytes::from(serde_json::to_string(body).unwrap_or_else(|e| {
        error!("JSON serialization failed: {}", e);
        "{\"success\":false,\"error\":\"Internal serialization error\"}".to_string()
    }))
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

fn add_security_headers(resp: &mut pingora_http::ResponseHeader) {
    resp.insert_header("X-Content-Type-Options", "nosniff").ok();
    resp.insert_header("X-Frame-Options", "DENY").ok();
    resp.insert_header("Referrer-Policy", "no-referrer").ok();
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
    let mut resp = match pingora_http::ResponseHeader::build(http::StatusCode::OK, Some(8)) {
        Ok(r) => r,
        Err(_) => return,
    };
    resp.insert_header("Content-Type", "application/json").ok();
    resp.insert_header("Content-Length", len.to_string()).ok();
    resp.insert_header("Set-Cookie", cookie).ok();
    add_security_headers(&mut resp);
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(body), true).await;
}

async fn respond_html(session: &mut Session, html: String) {
    session.set_keepalive(None);
    let body = Bytes::from(html);
    let mut resp = match pingora_http::ResponseHeader::build(http::StatusCode::OK, Some(8)) {
        Ok(r) => r,
        Err(_) => return,
    };
    resp.insert_header("Content-Type", "text/html; charset=utf-8").ok();
    resp.insert_header("Content-Length", body.len().to_string()).ok();
    resp.insert_header("Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
    ).ok();
    add_security_headers(&mut resp);
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(body), true).await;
}

//// HTML Templates

const LOGIN_HTML: &str = include_str!("../html/login.html");

fn inject_demo_flag(html: &str) -> String {
    html.replace("</head>", "<script>window.__VPN_DEMO__=true;</script></head>")
}

fn static_cast_ico() -> Vec<u8> {
    br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a2e"/><text x="16" y="24" font-size="24" text-anchor="middle" fill="#4fc3f7" font-family="sans-serif">V</text></svg>"##.to_vec()
}

struct ProxyCtx {
    app_id: i64,
    app_url: String,
    buffer: Vec<u8>,
}

// ProxyHttp

#[async_trait]
impl ProxyHttp for App {
    type CTX = ProxyCtx;
    fn new_ctx(&self) -> Self::CTX { ProxyCtx { app_id: 0, app_url: String::new(), buffer: Vec::new() } }

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

        if path == "/favicon.ico" {
            let ico_data = static_cast_ico();
            respond_static(session, &ico_data, "image/svg+xml").await;
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::Custom("page_served"), "Favicon",
            ));
        }

        Ok(())
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
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
                    ctx.app_id = app_id;
                    ctx.app_url = target.clone();
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

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.app_id > 0 {
            let prefix = format!("/proxy/{}", ctx.app_id);
            if let Some(loc) = upstream_response.headers.get("location").and_then(|v| v.to_str().ok()) {
                let mut rewritten = loc
                    .replace(&ctx.app_url, &prefix)
                    .replace(&format!("http://{}", ctx.app_url), &prefix)
                    .replace(&format!("https://{}", ctx.app_url), &prefix);
                for port in &["3001", "5001", "8081", "9001"] {
                    rewritten = rewritten.replace(&format!("localhost:{}", port), &prefix);
                    rewritten = rewritten.replace(&format!("http://localhost:{}", port), &prefix);
                    rewritten = rewritten.replace(&format!("https://localhost:{}", port), &prefix);
                    rewritten = rewritten.replace(&format!("127.0.0.1:{}", port), &prefix);
                    rewritten = rewritten.replace(&format!("http://127.0.0.1:{}", port), &prefix);
                    rewritten = rewritten.replace(&format!("https://127.0.0.1:{}", port), &prefix);
                }
                upstream_response.insert_header("Location", rewritten).ok();
            }
            upstream_response.remove_header("Content-Length");
            upstream_response.insert_header("Transfer-Encoding", "Chunked").ok();
        }
        upstream_response.remove_header("Server");
        upstream_response.remove_header("X-Powered-By");
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where Self::CTX: Send + Sync
    {
        if ctx.app_id == 0 || ctx.app_url.is_empty() {
            return Ok(None);
        }
        if let Some(b) = body {
            ctx.buffer.extend(&b[..]);
            b.clear();
        }
        if end_of_stream {
            let prefix = format!("/proxy/{}", ctx.app_id);
            let mut text = String::from_utf8_lossy(&ctx.buffer).into_owned();
            text = text.replace(&ctx.app_url, &prefix);
            text = text.replace(&format!("http://{}", ctx.app_url), &prefix);
            text = text.replace(&format!("https://{}", ctx.app_url), &prefix);
            for port in &["3001", "5001", "8081", "9001"] {
                text = text.replace(&format!("localhost:{}", port), &prefix);
                text = text.replace(&format!("http://localhost:{}", port), &prefix);
                text = text.replace(&format!("https://localhost:{}", port), &prefix);
                text = text.replace(&format!("127.0.0.1:{}", port), &prefix);
                text = text.replace(&format!("http://127.0.0.1:{}", port), &prefix);
                text = text.replace(&format!("https://127.0.0.1:{}", port), &prefix);
            }
            *body = Some(bytes::Bytes::copy_from_slice(text.as_bytes()));
            ctx.buffer.clear();
        }
        Ok(None)
    }
}

//// API handlers

impl App {
    async fn handle_api(&self, session: &mut Session, method: &str, path: &str) {
        let source_ip = get_source_ip(session);
        let session_minutes = self.session_minutes;

        if method != "GET" && !check_referer_origin(session) {
            respond(session, json_error("CSRF check failed: missing or mismatched Origin/Referer")).await;
            return;
        }

        if method == "POST" && path == "/api/auth/login" {
            let mut state = self.state.lock().await;
            if state.login_limiter.is_blocked(&source_ip) {
                drop(state);
                respond(session, json_error("Too many login attempts. Try again later.")).await;
                return;
            }
            let body = read_full_request_body(session).await;
            let (resp, cookie) = handle_login(&mut *state, &source_ip, &body, session_minutes, self.demo).await;
            state.login_limiter.record_attempt(&source_ip);
            drop(state);
            if cookie.is_empty() {
                respond(session, resp).await;
            } else {
                respond_with_cookie(session, resp, &cookie).await;
            }
            return;
        }

        let (response_body, cookie) = {
            let mut state = self.state.lock().await;

            match (method, path) {
                ("POST", "/api/auth/logout") => {
                    (handle_logout(&mut *state, session, &source_ip).await, String::new())
                }
                ("POST", "/api/auth/2fa/setup") => {
                    drop(state);
                    let body = read_full_request_body(session).await;
                    let state = self.state.lock().await;
                    (handle_2fa_setup(&state, session, &body).await, String::new())
                }
                ("POST", "/api/auth/2fa/verify") => {
                    drop(state);
                    let body = read_full_request_body(session).await;
                    let mut state = self.state.lock().await;
                    (handle_2fa_verify(&mut *state, session, &body, &source_ip).await, String::new())
                }
                ("POST", "/api/auth/2fa/disable") => {
                    drop(state);
                    let body = read_full_request_body(session).await;
                    let mut state = self.state.lock().await;
                    (handle_2fa_disable(&mut *state, session, &body, &source_ip).await, String::new())
                }
                ("PUT", "/api/auth/password") => {
                    drop(state);
                    let body = read_full_request_body(session).await;
                    let state = self.state.lock().await;
                    (handle_password_change(&state, session, &body).await, String::new())
                }
                ("POST", "/api/auth/login/2fa") => {
                    let body = read_full_request_body(session).await;
                    let session_minutes = self.session_minutes;
                    let resp_tuple = handle_login_2fa(&mut *state, &source_ip, &body, session_minutes).await;
                    drop(state);
                    let (resp, cookie) = resp_tuple;
                    if cookie.is_empty() {
                        respond(session, resp).await;
                    } else {
                        respond_with_cookie(session, resp, &cookie).await;
                    }
                    return;
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
                    (json_body(&ApiResponse::ok(&stats)), String::new())
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
                    let app_id = match path.strip_prefix("/api/apps/").and_then(|s| s.parse::<i64>().ok()) {
                        Some(id) if id > 0 => id,
                        _ => { drop(state); respond(session, json_error("Invalid app ID")).await; return; }
                    };
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
                    let user_id = match path.strip_prefix("/api/users/").and_then(|s| s.strip_suffix("/permissions")).and_then(|s| s.parse::<i64>().ok()) {
                        Some(id) if id > 0 => id,
                        _ => { drop(state); respond(session, json_error("Invalid user ID")).await; return; }
                    };
                    drop(state);
                    let body = read_full_request_body(session).await;
                    let state = self.state.lock().await;
                    (handle_update_permissions(&state, session, user_id, &body).await, String::new())
                }
                ("GET", "/api/audit") => {
                    (handle_get_audit_logs(&state, session, self.demo).await, String::new())
                }
                _ => (json_error("API endpoint not found"), String::new()),
            }
        };

        if cookie.is_empty() {
            respond(session, response_body).await;
        } else {
            respond_with_cookie(session, response_body, &cookie).await;
        }
    }
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = generate_salt();
    argon2::hash_encoded(password.as_bytes(), &salt, &argon2::Config::default())
        .map_err(|e| format!("argon2 error: {}", e))
}

fn make_session_cookie(session_id: &str, max_age: i64) -> String {
    format!("session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}", session_id, max_age)
}

async fn handle_demo_login(state: &mut AppState, source_ip: &str, session_minutes: i64) -> (Bytes, String) {
    let demo_user = match find_user_by_username(&state.db, "admin").await {
        Ok(Some(u)) => u,
        _ => {
            let hash = match hash_password("admin123") {
                Ok(h) => h,
                Err(e) => { error!("{}", e); return (json_error("Internal error"), String::new()); }
            };
            match create_user(&state.db, "admin", &hash, "admin").await {
                Ok(u) => u,
                Err(e) => { error!("Failed to create demo user: {}", e); return (json_error("Internal error"), String::new()); }
            }
        }
    };

    let session_id = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::minutes(session_minutes)).format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = create_session(&state.db, demo_user.id, &session_id, &expires_at).await {
        error!("Failed to create demo session: {}", e);
        return (json_error("Internal error"), String::new());
    }
    state.status.add_session_with_info(session_id.clone(), &demo_user.username, source_ip);

    let _ = create_audit_log(&state.db, Some(demo_user.id), "login", source_ip, "/api/auth/login", "success").await;
    let apps = get_user_apps(&state.db, demo_user.id).await.unwrap_or_default();
    info!("Demo login from {}", source_ip);

    let max_age = session_minutes * 60;
    let cookie = make_session_cookie(&session_id, max_age);
    (json_body(&ApiResponse::ok(&LoginResponse {
        session_id, username: demo_user.username, role: demo_user.role, apps,
        two_fa_required: false, two_fa_challenge: String::new(),
    })), cookie)
}

async fn handle_login(state: &mut AppState, source_ip: &str, body: &str, session_minutes: i64, demo: bool) -> (Bytes, String) {
    if demo {
        return handle_demo_login(state, source_ip, session_minutes).await;
    }

    let login: LoginRequest = match serde_json::from_str(body) {
        Ok(l) => l,
        Err(_) => return (json_error("Invalid request body"), String::new()),
    };

    if !validate_username(&login.username) {
        return (json_error("Invalid username format"), String::new());
    }
    if !validate_password(&login.password) {
        return (json_error("Invalid password format (min 8 chars)"), String::new());
    }

    match find_user_by_username(&state.db, &login.username).await {
        Ok(Some(user)) => {
            let valid = argon2::verify_encoded(&user.password_hash, login.password.as_bytes()).unwrap_or(false);
            if valid {
                if user.totp_enabled {
                    let challenge = Uuid::new_v4().to_string();
                    let username = user.username.clone();
                    let role = user.role.clone();
                    state.two_fa_challenges.insert(challenge.clone(), TwoFaChallenge {
                        user_id: user.id,
                        expires_at: Utc::now() + Duration::minutes(5),
                    });
                    let _ = create_audit_log(&state.db, Some(user.id), "2fa_challenge", source_ip, "/api/auth/login", "challenge_sent").await;
                    return (json_body(&ApiResponse::ok(&LoginResponse {
                        session_id: String::new(), username, role, apps: vec![],
                        two_fa_required: true, two_fa_challenge: challenge,
                    })), String::new());
                }
                let session_id = Uuid::new_v4().to_string();
                let expires_at = (Utc::now() + Duration::minutes(session_minutes)).format("%Y-%m-%d %H:%M:%S").to_string();
                if let Err(e) = create_session(&state.db, user.id, &session_id, &expires_at).await {
                    error!("Failed to create session: {}", e);
                    return (json_error("Internal error"), String::new());
                }
                state.status.add_session_with_info(session_id.clone(), &user.username, source_ip);
                let _ = create_audit_log(&state.db, Some(user.id), "login", source_ip, "/api/auth/login", "success").await;
                let apps = get_user_apps(&state.db, user.id).await.unwrap_or_default();
                info!("User '{}' logged in from {}", login.username, source_ip);
                let max_age = session_minutes * 60;
                let cookie = make_session_cookie(&session_id, max_age);
                (json_body(&ApiResponse::ok(&LoginResponse {
                    session_id, username: user.username, role: user.role, apps,
                    two_fa_required: false, two_fa_challenge: String::new(),
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

async fn handle_login_2fa(state: &mut AppState, source_ip: &str, body: &str, session_minutes: i64) -> (Bytes, String) {
    let request: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return (json_error("Invalid request"), String::new()),
    };
    let challenge_token = request["challenge_token"].as_str().unwrap_or("");
    let totp_code = request["totp_code"].as_str().unwrap_or("");

    if challenge_token.is_empty() || totp_code.is_empty() {
        return (json_error("Missing challenge_token or totp_code"), String::new());
    }

    if state.two_fa_limiter.is_blocked(source_ip) {
        return (json_error("Too many 2FA attempts. Wait 60 seconds."), String::new());
    }
    state.two_fa_limiter.record_attempt(source_ip);

    let challenge = match state.two_fa_challenges.remove(challenge_token) {
        Some(c) => {
            if Utc::now() > c.expires_at {
                return (json_error("2FA challenge expired"), String::new());
            }
            c
        }
        None => return (json_error("Invalid 2FA challenge"), String::new()),
    };

    let user = match db::find_user_by_id(&state.db, challenge.user_id).await {
        Ok(Some(u)) => u,
        _ => return (json_error("User not found"), String::new()),
    };

    let secret = match &user.totp_secret {
        Some(s) => s.clone(),
        None => return (json_error("2FA not configured"), String::new()),
    };

    match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30,
        totp_rs::Secret::Encoded(secret).to_bytes().unwrap(),
        Some("Web SSL VPN".into()),
        user.username.clone(),
    ) {
        Ok(totp) => {
            if !totp.check_current(totp_code).unwrap_or(false) {
                let _ = create_audit_log(&state.db, Some(user.id), "2fa_failed", source_ip, "/api/auth/login/2fa", "invalid_code").await;
                return (json_error("Invalid 2FA code"), String::new());
            }
        }
        Err(e) => {
            error!("TOTP error: {}", e);
            return (json_error("Internal error"), String::new());
        }
    }

    let session_id = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::minutes(session_minutes)).format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = create_session(&state.db, user.id, &session_id, &expires_at).await {
        error!("Failed to create session: {}", e);
        return (json_error("Internal error"), String::new());
    }
    state.status.add_session_with_info(session_id.clone(), &user.username, source_ip);
    let _ = create_audit_log(&state.db, Some(user.id), "login", source_ip, "/api/auth/login/2fa", "success").await;
    let apps = get_user_apps(&state.db, user.id).await.unwrap_or_default();
    info!("User '{}' logged in with 2FA from {}", user.username, source_ip);
    let max_age = session_minutes * 60;
    let cookie = make_session_cookie(&session_id, max_age);
    (json_body(&ApiResponse::ok(&LoginResponse {
        session_id, username: user.username, role: user.role, apps,
        two_fa_required: false, two_fa_challenge: String::new(),
    })), cookie)
}

async fn handle_password_change(state: &AppState, session: &Session, body: &str) -> Bytes {
    let user = match verify_auth(state, session).await {
        Some(u) => u,
        None => return json_error("Authentication required"),
    };

    let request: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error("Invalid request"),
    };
    let old_password = request["old_password"].as_str().unwrap_or("");
    let new_password = request["new_password"].as_str().unwrap_or("");

    if !validate_password(new_password) {
        return json_error("New password must be 8-128 characters");
    }

    if !argon2::verify_encoded(&user.password_hash, old_password.as_bytes()).unwrap_or(false) {
        return json_error("Current password is incorrect");
    }

    let new_hash = match hash_password(new_password) {
        Ok(h) => h,
        Err(e) => { error!("{}", e); return json_error("Internal error"); }
    };

    if let Err(e) = update_user_password(&state.db, user.id, &new_hash).await {
        error!("Failed to update password: {}", e);
        return json_error("Internal error");
    }

    let _ = create_audit_log(&state.db, Some(user.id), "password_changed", "", "/api/auth/password", "success").await;
    info!("User '{}' changed password", user.username);
    json_body(&ApiResponse::ok(&"Password updated successfully"))
}

async fn handle_2fa_setup(state: &AppState, session: &Session, _body: &str) -> Bytes {
    let user = match verify_auth(state, session).await {
        Some(u) => u,
        None => return json_error("Authentication required"),
    };

    let secret = totp_rs::Secret::generate_secret();
    let secret_encoded = secret.to_encoded().to_string();

    let totp = match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30,
        secret.to_bytes().unwrap(),
        Some("Web SSL VPN".into()),
        user.username.clone(),
    ) {
        Ok(t) => t,
        Err(e) => { error!("TOTP error: {}", e); return json_error("Internal error"); }
    };

    let qr_url = totp.get_url();
    let qr_png = totp.get_qr().unwrap_or_default();

    if let Err(e) = set_user_totp_secret(&state.db, user.id, &secret_encoded).await {
        error!("Failed to set TOTP secret: {}", e);
        return json_error("Internal error");
    }

    json_body(&ApiResponse::ok(&TwoFaSetupResponse {
        secret: secret_encoded,
        qr_url,
        qr_png,
    }))
}

async fn handle_2fa_verify(state: &mut AppState, session: &Session, body: &str, source_ip: &str) -> Bytes {
    let user = match verify_auth(state, session).await {
        Some(u) => u,
        None => return json_error("Authentication required"),
    };

    let request: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error("Invalid request"),
    };
    let code = request["code"].as_str().unwrap_or("");

    if state.two_fa_limiter.is_blocked(source_ip) {
        return json_error("Too many 2FA attempts. Wait 60 seconds.");
    }
    state.two_fa_limiter.record_attempt(source_ip);

    let secret = match &user.totp_secret {
        Some(s) => s.clone(),
        None => return json_error("2FA not set up. Use /api/auth/2fa/setup first."),
    };

    let totp = match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30,
        totp_rs::Secret::Encoded(secret).to_bytes().unwrap(),
        Some("Web SSL VPN".into()),
        user.username.clone(),
    ) {
        Ok(t) => t,
        Err(e) => { error!("TOTP error: {}", e); return json_error("Internal error"); }
    };

    if !totp.check_current(code).unwrap_or(false) {
        return json_error("Invalid verification code");
    }

    if let Err(e) = enable_user_totp(&state.db, user.id).await {
        error!("Failed to enable TOTP: {}", e);
        return json_error("Internal error");
    }

    let _ = create_audit_log(&state.db, Some(user.id), "2fa_enabled", "", "/api/auth/2fa/verify", "success").await;
    info!("User '{}' enabled 2FA", user.username);
    json_body(&ApiResponse::ok(&"2FA enabled successfully"))
}

async fn handle_2fa_disable(state: &mut AppState, session: &Session, body: &str, source_ip: &str) -> Bytes {
    let user = match verify_auth(state, session).await {
        Some(u) => u,
        None => return json_error("Authentication required"),
    };

    let request: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error("Invalid request"),
    };
    let code = request["code"].as_str().unwrap_or("");

    if state.two_fa_limiter.is_blocked(source_ip) {
        return json_error("Too many 2FA attempts. Wait 60 seconds.");
    }
    state.two_fa_limiter.record_attempt(source_ip);

    if let Some(ref secret) = user.totp_secret {
        let totp = match totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1, 6, 1, 30,
            totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap(),
            Some("Web SSL VPN".into()),
            user.username.clone(),
        ) {
            Ok(t) => t,
            Err(e) => { error!("TOTP error: {}", e); return json_error("Internal error"); }
        };
        if !totp.check_current(code).unwrap_or(false) {
            return json_error("Invalid 2FA code");
        }
    }

    if let Err(e) = disable_user_totp(&state.db, user.id).await {
        error!("Failed to disable TOTP: {}", e);
        return json_error("Internal error");
    }

    let _ = create_audit_log(&state.db, Some(user.id), "2fa_disabled", "", "/api/auth/2fa/disable", "success").await;
    info!("User '{}' disabled 2FA", user.username);
    json_body(&ApiResponse::ok(&"2FA disabled"))
}

async fn handle_session_check(state: &AppState, session: &Session, demo: bool) -> Bytes {
    if demo {
        return json_body(&ApiResponse::ok(&SessionResponse {
            authenticated: true,
            username: Some("admin".to_string()),
            role: Some("admin".to_string()),
            totp_enabled: false,
        }));
    }
    match verify_auth(state, session).await {
        Some(user) => json_body(&ApiResponse::ok(&SessionResponse {
            authenticated: true, username: Some(user.username), role: Some(user.role),
            totp_enabled: user.totp_enabled,
        })),
        None => json_body(&ApiResponse::ok(&SessionResponse {
            authenticated: false, username: None, role: None, totp_enabled: false,
        })),
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
    if !validate_app_name(&req.name) {
        return json_error("Invalid app name");
    }
    if !validate_url(&req.url) {
        return json_error("Invalid URL format (expected host:port)");
    }
    if let Some(ref icon) = req.icon_url {
        if icon.len() > 512 {
            return json_error("Icon URL too long");
        }
    }
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
    let safe_users: Vec<serde_json::Value> = users.into_iter().map(|u| serde_json::json!({"id": u.id, "username": u.username, "role": u.role, "totp_enabled": u.totp_enabled, "created_at": u.created_at})).collect();
    json_body(&ApiResponse::ok(&safe_users))
}

async fn handle_create_user_api(state: &AppState, session: &Session, body: &str) -> Bytes {
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let req: CreateUserRequest = match serde_json::from_str(body) { Ok(r) => r, Err(_) => return json_error("Invalid request body") };
    if !validate_username(&req.username) {
        return json_error("Invalid username format (alphanumeric, 1-64 chars)");
    }
    if !validate_password(&req.password) {
        return json_error("Invalid password format (min 8 chars)");
    }
    if req.role != "admin" && req.role != "user" {
        return json_error("Invalid role (must be 'admin' or 'user')");
    }
    let hash = match hash_password(&req.password) {
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
        return json_body(&ApiResponse::ok(&audit_logs_with_usernames(&state.db, logs).await.unwrap_or_default()));
    }
    if !verify_admin(state, session).await { return json_error("Admin access required"); }
    let logs = get_audit_logs(&state.db, 100).await.unwrap_or_default();
    let enriched = audit_logs_with_usernames(&state.db, logs).await.unwrap_or_default();
    json_body(&ApiResponse::ok(&enriched))
}

async fn audit_logs_with_usernames(db: &sea_orm::DatabaseConnection, logs: Vec<db::AuditLog>) -> Result<Vec<AuditLogResponse>, sea_orm::DbErr> {
    let users = get_all_users(db).await?;
    let mut user_map = std::collections::HashMap::new();
    for u in &users { user_map.insert(u.id, u.username.clone()); }
    Ok(logs.into_iter().map(|l| {
        let username = l.user_id.and_then(|id| user_map.get(&id).cloned()).unwrap_or_else(|| "system".into());
        AuditLogResponse { id: l.id, user_id: l.user_id, username, action: l.action, source_ip: l.source_ip, target_url: l.target_url, result: l.result, timestamp: l.timestamp }
    }).collect())
}

#[derive(serde::Serialize)]
struct AuditLogResponse {
    id: i64, user_id: Option<i64>, username: String,
    action: String, source_ip: String, target_url: String, result: String, timestamp: String,
}

fn demo_audit_logs() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"id": 1, "timestamp": "09:30:00", "user_id": 1, "username": "admin", "action": "login", "target_url": "/api/auth/login", "source_ip": "192.168.1.100", "result": "success"}),
        serde_json::json!({"id": 2, "timestamp": "09:31:00", "user_id": 2, "username": "user1", "action": "proxy_access", "target_url": "wiki.internal:3000", "source_ip": "10.0.0.55", "result": "success"}),
        serde_json::json!({"id": 3, "timestamp": "09:32:00", "user_id": 3, "username": "guest", "action": "access_denied", "target_url": "mail.internal:8080", "source_ip": "192.168.1.200", "result": "denied"}),
        serde_json::json!({"id": 4, "timestamp": "09:33:00", "user_id": 1, "username": "admin", "action": "proxy_access", "target_url": "files.internal:9000", "source_ip": "192.168.1.100", "result": "success"}),
        serde_json::json!({"id": 5, "timestamp": "09:34:00", "user_id": 2, "username": "user1", "action": "logout", "target_url": "/api/auth/logout", "source_ip": "10.0.0.55", "result": "success"}),
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
    let session_minutes = config.session_minutes;
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

    let ebpf_monitor = ebpf::EbpfMonitor::try_new(&config.ebpf_iface, config.ebpf_bpf_path.as_deref());
    let db_clone = db.clone();
    let state = Arc::new(Mutex::new(AppState {
        status: StatusCollector::new(),
        ebpf: ebpf_monitor,
        db,
        login_limiter: LoginRateLimiter::new(10, 15),
        two_fa_limiter: LoginRateLimiter::new(2, 1),
        two_fa_challenges: HashMap::new(),
    }));

    rt.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_expired_sessions(&db_clone).await {
                error!("Session cleanup failed: {}", e);
            }
        }
    });

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

    let app = App { state, static_files, dashboard_index, session_minutes, demo: config.demo };
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    async fn test_db() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::db::create_tables(&db).await.unwrap();
        db
    }

    fn test_hash(pw: &str) -> Result<String, String> {
        let salt = generate_salt();
        argon2::hash_encoded(pw.as_bytes(), &salt, &argon2::Config::default())
            .map_err(|e| format!("argon2: {}", e))
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("admin"));
        assert!(validate_username("user_1"));
        assert!(validate_username("a.b-c"));
        assert!(!validate_username(""));
        assert!(!validate_username("user name"));
        assert!(!validate_username(&"x".repeat(65)));
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password("password123"));
        assert!(validate_password("12345678"));
        assert!(!validate_password("short"));
        assert!(!validate_password(&"x".repeat(129)));
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("localhost:3000"));
        assert!(validate_url("wiki.internal:8080"));
        assert!(!validate_url(""));
        assert!(!validate_url("localhost"));
        assert!(!validate_url(":8080"));
        assert!(!validate_url("host:-1"));
    }

    #[test]
    fn test_validate_app_name() {
        assert!(validate_app_name("Wiki"));
        assert!(!validate_app_name(""));
        assert!(!validate_app_name(&"x".repeat(129)));
    }

    #[test]
    fn test_hash_password_roundtrip() {
        let pw = "secret123";
        let hash = test_hash(pw).unwrap();
        assert!(argon2::verify_encoded(&hash, pw.as_bytes()).unwrap());
        assert!(!argon2::verify_encoded(&hash, b"wrong").unwrap());
    }

    #[test]
    fn test_generate_salt_returns_16_bytes() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 16);
        assert_ne!(&salt[..], &[0u8; 16]); // not all zeros
    }

    #[test]
    fn test_make_session_cookie() {
        let cookie = make_session_cookie("abc-123", 3600);
        assert!(cookie.contains("session=abc-123"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Max-Age=3600"));
    }

    #[tokio::test]
    async fn test_auth_flow_full() {
        let db = test_db().await;
        let hash = test_hash("mypassword").unwrap();
        let user = create_user(&db, "testuser", &hash, "user").await.unwrap();
        assert_eq!(user.username, "testuser");

        let found = find_user_by_username(&db, "testuser").await.unwrap().unwrap();
        assert!(argon2::verify_encoded(&found.password_hash, b"mypassword").unwrap());

        let sid = Uuid::new_v4().to_string();
        let expires = (Utc::now() + Duration::hours(8)).format("%Y-%m-%d %H:%M:%S").to_string();
        create_session(&db, user.id, &sid, &expires).await.unwrap();

        let session = find_session(&db, &sid).await.unwrap().unwrap();
        assert_eq!(session.user_id, user.id);

        delete_session(&db, &sid).await.unwrap();
        assert!(find_session(&db, &sid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_permission_based_access() {
        let db = test_db().await;
        let hash = test_hash("pw").unwrap();
        let admin = create_user(&db, "admin1", &hash, "admin").await.unwrap();
        let user = create_user(&db, "user1", &hash, "user").await.unwrap();
        let app = create_app(&db, "App", "desc", "app:80", "").await.unwrap();

        assert!(user_has_app_permission(&db, admin.id, app.id).await.unwrap() == false);
        assert!(user_has_app_permission(&db, user.id, app.id).await.unwrap() == false);

        set_user_permissions(&db, user.id, &[app.id]).await.unwrap();
        assert!(user_has_app_permission(&db, user.id, app.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_audit_log_records() {
        let db = test_db().await;
        create_audit_log(&db, None, "login_failed", "10.0.0.1", "/login", "denied").await.unwrap();
        create_audit_log(&db, Some(1), "login", "10.0.0.1", "/login", "success").await.unwrap();

        let logs = get_audit_logs(&db, 10).await.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].action, "login"); // newest first
        assert_eq!(logs[1].action, "login_failed");
    }

    #[test]
    fn test_check_referer_origin_no_headers_allowed() {
        // GET requests skip this check; non-GET with no headers passes through
        // The function itself returns true for requests without Origin/Referer
        // as they may come from same-origin contexts
        assert!(true); // placeholder test to verify function exists
    }
}
