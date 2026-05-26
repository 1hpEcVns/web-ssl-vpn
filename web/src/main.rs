mod styles;

use iced::{
    widget::{button, column, container, row, scrollable, text, text_input, Image, Space},
    alignment, time, Element, Font, Length, Subscription, Task,
};
use styles::{ButtonType, ContainerType, StyleType, TextType};
use gloo_net::http::Request;
use serde::Deserialize;

fn main() -> iced::Result {
    iced::application(WebSslVpn::boot, WebSslVpn::update, WebSslVpn::view)
        .title("Web SSL VPN")
        .theme(WebSslVpn::theme)
        .subscription(WebSslVpn::subscription)
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page { Overview, Network, Sessions, Apps, Audit, Ebpf, Settings }

impl Page {
    const ALL: [Page; 7] = [Page::Overview, Page::Network, Page::Sessions, Page::Apps, Page::Audit, Page::Ebpf, Page::Settings];
    fn label(&self) -> &str {
        match self { Page::Overview => "Overview", Page::Network => "Network", Page::Sessions => "Sessions", Page::Apps => "Apps", Page::Audit => "Audit", Page::Ebpf => "eBPF", Page::Settings => "Settings" }
    }
}

#[derive(Debug, Clone)]
enum Message {
    SwitchPage(Page),
    Tick,
    FetchStatus,
    ToggleSessionTab,
    ToggleSessionColumns,
    ExportLogs,
    SetQuota(u64),
    EditQuota,
    ToggleDemo,
    StatusFetched(Result<ApiStats, String>),
    AppsFetched(Result<Vec<ApiApp>, String>),
    AuditFetched(Result<Vec<ApiAuditEntry>, String>),
    SetOldPassword(String),
    SetNewPassword(String),
    SetConfirmPassword(String),
    ChangePassword,
    PasswordChanged(Result<String, String>),
    Setup2FA,
    TwoFaSetupDone(Result<TwoFaSetupData, String>),
    SetTotpCode(String),
    Verify2FA,
    TwoFaVerified(Result<String, String>),
    Disable2FA,
    TwoFaDisabled(Result<String, String>),
    ClearSettingsMsg,
    Logout,
    OpenApp(i64),
    CheckSession,
    SessionChecked(Result<SessionInfo2, String>),
    SetCreateUser(String), SetCreatePass(String), SetCreateRole(String),
    CreateUser, UserCreated(Result<String, String>),
    GrantAllApps, AppAccessGranted(Result<String, String>),
    CreateAndGrantUser,
    ToggleGrantApp(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionTab { Active, Closed }

struct WebSslVpn {
    page: Page,
    session_tab: SessionTab,
    show_session_cols: bool,
    traffic_quota: u64,
    editing_quota: bool,
    demo_mode: bool,
    ebpf_active: bool,
    uptime: u64,
    requests: u64,
    conns: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    apps: Vec<AppInfo>,
    logs: Vec<LogEntry>,
    active_sessions: Vec<SessionInfo>,
    closed_sessions: Vec<SessionInfo>,
    sent_history: Vec<f32>,
    recv_history: Vec<f32>,
    frame: u64,
    prev_bytes_sent: f32,
    prev_bytes_recv: f32,
    old_password: String,
    new_password: String,
    confirm_password: String,
    totp_code: String,
    two_fa_setup_data: Option<TwoFaSetupData>,
    two_fa_enabled: bool,
    qr_handle: Option<iced::widget::image::Handle>,
    settings_msg: Option<(String, bool)>,
    create_user: String, create_pass: String, create_role: String,
    grant_apps: Vec<i64>,
}

#[derive(Debug, Clone)] struct AppInfo { name: String, url: String, desc: String, id: i64 }
#[derive(Debug, Clone)] struct LogEntry { ts: String, user: String, action: String, target: String, result: String }

#[derive(Debug, Clone)]
struct SessionInfo {
    host: String, dl_speed: u64, ul_speed: u64,
    dl_total: u64, ul_total: u64,
    source: String, target: String, connected: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiStats {
    uptime: u64, connections: u64, requests_total: u64,
    bytes_sent: u64, bytes_recv: u64, active_sessions: u64,
    session_details: Vec<ApiSessionDetail>, timestamp: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiSessionDetail { username: String, source_ip: String, connected_at: String }

#[derive(Debug, Clone, Deserialize)]
struct ApiApp { id: i64, name: String, description: String, url: String, icon_url: String, is_active: bool }

#[derive(Debug, Clone, Deserialize)]
struct ApiAuditEntry {
    id: i64, user_id: Option<i64>, username: String,
    action: String, source_ip: String, target_url: String, result: String, timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse<T> { success: bool, data: Option<T>, error: Option<String> }

#[derive(Debug, Clone, Deserialize)]
struct TwoFaSetupData { secret: String, qr_url: String, qr_png: String }
#[derive(Debug, Clone, Deserialize)]
struct SessionInfo2 { authenticated: bool, username: Option<String>, role: Option<String>, totp_enabled: bool }

async fn fetch_status() -> Result<ApiStats, String> {
    let text = fetch_text("/api/status").await?;
    let body: ApiResponse<ApiStats> = serde_json::from_str(&text).map_err(|e| format!("JSON parse status: {}", e))?;
    body.data.ok_or_else(|| "API returned no data".into())
}

async fn fetch_apps() -> Result<Vec<ApiApp>, String> {
    let text = fetch_text("/api/apps").await?;
    let body: ApiResponse<Vec<ApiApp>> = serde_json::from_str(&text).map_err(|e| format!("JSON parse apps: {}", e))?;
    body.data.ok_or_else(|| "API returned no data".into())
}

async fn fetch_audit() -> Result<Vec<ApiAuditEntry>, String> {
    let text = fetch_text("/api/audit").await?;
    let body: ApiResponse<Vec<ApiAuditEntry>> = serde_json::from_str(&text).map_err(|e| format!("JSON parse audit: {}", e))?;
    body.data.ok_or_else(|| "API returned no data".into())
}

async fn fetch_text(path: &str) -> Result<String, String> {
    let resp = Request::get(path).send().await.map_err(|e| format!("HTTP: {}", e))?;
    resp.text().await.map_err(|e| format!("HTTP: {}", e))
}

async fn api_post_json(path: &str, body: &str) -> Result<serde_json::Value, String> {
    let text = api_request("POST", path, body).await?;
    serde_json::from_str(&text).map_err(|e| format!("JSON: {}", e))
}

async fn api_put_json(path: &str, body: &str) -> Result<serde_json::Value, String> {
    let text = api_request("PUT", path, body).await?;
    serde_json::from_str(&text).map_err(|e| format!("JSON: {}", e))
}

async fn api_request(method: &str, path: &str, body: &str) -> Result<String, String> {
    let req = match method {
        "POST" => Request::post(&format!("/api{}", path)),
        "PUT" => Request::put(&format!("/api{}", path)),
        _ => return Err("unsupported method".into()),
    };
    let resp = req.header("Content-Type", "application/json").body(body)
        .map_err(|e| format!("HTTP: {}", e))?
        .send().await.map_err(|e| format!("HTTP: {}", e))?;
    resp.text().await.map_err(|e| format!("HTTP: {}", e))
}

impl WebSslVpn {
    fn theme(&self) -> StyleType { StyleType::NordDark }
    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            time::every(std::time::Duration::from_millis(16)).map(|_| Message::Tick),
            time::every(std::time::Duration::from_millis(166)).map(|_| Message::FetchStatus),
        ])
    }
    fn boot() -> (Self, Task<Message>) { (Self::default(), Task::none()) }

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::SwitchPage(p) => {
                self.page = p;
                self.settings_msg = None;
                match p {
                    Page::Apps => return Task::perform(fetch_apps(), Message::AppsFetched),
                    Page::Audit => return Task::perform(fetch_audit(), Message::AuditFetched),
                    Page::Settings => return Task::perform(async {
                        fetch_text("/api/auth/session").await.ok().and_then(|t| serde_json::from_str::<ApiResponse<SessionInfo2>>(&t).ok().and_then(|r| r.data)).ok_or("session check failed".into())
                    }, Message::SessionChecked),
                    _ => {}
                }
            }
            Message::ToggleSessionTab => { self.session_tab = match self.session_tab { SessionTab::Active => SessionTab::Closed, SessionTab::Closed => SessionTab::Active }; }
            Message::ToggleSessionColumns => { self.show_session_cols = !self.show_session_cols; }
            Message::ExportLogs => {}
            Message::EditQuota => { self.editing_quota = !self.editing_quota; }
            Message::SetQuota(val) => { self.traffic_quota = val; self.editing_quota = false; }
            Message::ToggleDemo => {
                self.demo_mode = !self.demo_mode;
                if !self.demo_mode { self.uptime = 0; self.requests = 0; self.conns = 0; self.bytes_sent = 0; self.bytes_recv = 0; self.sent_history.clear(); self.recv_history.clear(); self.prev_bytes_sent = 0.0; self.prev_bytes_recv = 0.0; }
            }
            Message::Tick => {
                self.frame += 1;
                if self.demo_mode {
                    if self.frame % 60 == 0 {
                        self.uptime += 1;
                        self.requests = self.requests.saturating_add(4 + (self.uptime % 20));
                        self.bytes_sent = self.bytes_sent.wrapping_add(1024 * (60 + self.uptime % 240));
                        self.bytes_recv = self.bytes_recv.wrapping_add(1024 * (24 + self.uptime % 180));
                        self.conns = 2 + (self.uptime % 12) as u64;
                        self.sent_history.push(self.bytes_sent as f32 / 1048576.0);
                        self.recv_history.push(self.bytes_recv as f32 / 1048576.0);
                        if self.sent_history.len() > 60 { self.sent_history.remove(0); self.recv_history.remove(0); }
                    }
                } else {
                    if self.frame % 60 == 0 {
                        self.sent_history.push(self.bytes_sent as f32 / 1048576.0);
                        self.recv_history.push(self.bytes_recv as f32 / 1048576.0);
                        if self.sent_history.len() > 60 { self.sent_history.remove(0); self.recv_history.remove(0); }
                    }
                }
            }
            Message::FetchStatus => {
                if !self.demo_mode {
                    return Task::perform(fetch_status(), Message::StatusFetched);
                }
            }
            Message::StatusFetched(result) => {
                match result {
                    Ok(stats) => {
                        self.uptime = stats.uptime; self.requests = stats.requests_total; self.conns = stats.connections;
                        let (cs, cr) = (stats.bytes_sent as f32, stats.bytes_recv as f32);
                        let ds = (cs - self.prev_bytes_sent).max(0.0); let dr = (cr - self.prev_bytes_recv).max(0.0);
                        self.prev_bytes_sent = cs; self.prev_bytes_recv = cr;
                        self.bytes_sent = stats.bytes_sent; self.bytes_recv = stats.bytes_recv;
                        self.sent_history.push(ds / 1048576.0); self.recv_history.push(dr / 1048576.0);
                        if self.sent_history.len() > 60 { self.sent_history.remove(0); self.recv_history.remove(0); }
                        self.active_sessions = stats.session_details.into_iter().map(|s| SessionInfo { host: s.username, dl_speed: 0, ul_speed: 0, dl_total: 0, ul_total: 0, source: s.source_ip, target: String::new(), connected: s.connected_at }).collect();
                    }
                    Err(e) => { gloo_console::log!("Status fetch failed:", &e); }
                }
            }
            Message::AppsFetched(result) => { if let Ok(a) = result { self.apps = a.into_iter().map(|a| AppInfo { id: a.id, name: a.name, url: a.url, desc: a.description }).collect(); } }
            Message::AuditFetched(result) => {
                if let Ok(e) = result { self.logs = e.into_iter().map(|l| { let ts = if l.timestamp.len() >= 16 { l.timestamp[11..16].to_string() } else { l.timestamp }; LogEntry { ts, user: l.username, action: l.action, target: l.target_url, result: l.result } }).collect(); }
            }
            // ── Settings ──
            Message::SetOldPassword(v) => { self.old_password = v; self.settings_msg = None; }
            Message::SetNewPassword(v) => { self.new_password = v; self.settings_msg = None; }
            Message::SetConfirmPassword(v) => { self.confirm_password = v; self.settings_msg = None; }
            Message::ChangePassword => {
                if self.new_password != self.confirm_password { self.settings_msg = Some(("Passwords do not match".into(), true)); return Task::none(); }
                if self.new_password.len() < 8 { self.settings_msg = Some(("Min 8 characters".into(), true)); return Task::none(); }
                let body = format!(r#"{{"old_password":"{}","new_password":"{}"}}"#, self.old_password, self.new_password);
                return Task::perform(async move {
                    match api_put_json("/auth/password", &body).await {
                        Ok(v) => v["error"].as_str().map(|s| Err(s.into())).unwrap_or_else(|| Ok("Password updated".into())),
                        Err(e) => Err(e),
                    }
                }, Message::PasswordChanged);
            }
            Message::PasswordChanged(result) => {
                match result {
                    Ok(msg) => { self.settings_msg = Some((msg, false)); self.old_password.clear(); self.new_password.clear(); self.confirm_password.clear(); }
                    Err(e) => { self.settings_msg = Some((e, true)); }
                }
            }
            Message::Setup2FA => {
                return Task::perform(async move {
                    let text = api_request("POST", "/auth/2fa/setup", "{}").await?;
                    let body: ApiResponse<TwoFaSetupData> = serde_json::from_str(&text).map_err(|e| format!("JSON: {}", e))?;
                    body.data.ok_or_else(|| "API returned no data".into())
                }, Message::TwoFaSetupDone);
            }
            Message::TwoFaSetupDone(result) => {
                match result {
                    Ok(data) => {
                        if !data.qr_png.is_empty() {
                            if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data.qr_png) {
                                self.qr_handle = Some(iced::widget::image::Handle::from_bytes(bytes));
                            }
                        }
                        self.two_fa_setup_data = Some(data);
                    }
                    Err(e) => { self.settings_msg = Some((e, true)); }
                }
            }
            Message::SetTotpCode(v) => { self.totp_code = v; self.settings_msg = None; }
            Message::Verify2FA => {
                let code = self.totp_code.clone();
                let body = format!(r#"{{"code":"{}"}}"#, code);
                return Task::perform(async move {
                    match api_post_json("/auth/2fa/verify", &body).await {
                        Ok(v) => v["error"].as_str().map(|s| Err(s.into())).unwrap_or_else(|| Ok("2FA enabled".into())),
                        Err(e) => Err(e),
                    }
                }, Message::TwoFaVerified);
            }
            Message::TwoFaVerified(result) => {
                match result {
                    Ok(msg) => { self.settings_msg = Some((msg, false)); self.two_fa_setup_data = None; self.two_fa_enabled = true; self.totp_code.clear(); }
                    Err(e) => { self.settings_msg = Some((e, true)); }
                }
            }
            Message::Disable2FA => {
                let code = self.totp_code.clone();
                let body = format!(r#"{{"code":"{}"}}"#, code);
                return Task::perform(async move {
                    match api_post_json("/auth/2fa/disable", &body).await {
                        Ok(v) => v["error"].as_str().map(|s| Err(s.into())).unwrap_or_else(|| Ok("2FA disabled".into())),
                        Err(e) => Err(e),
                    }
                }, Message::TwoFaDisabled);
            }
            Message::TwoFaDisabled(result) => {
                match result {
                    Ok(msg) => { self.settings_msg = Some((msg, false)); self.two_fa_enabled = false; self.totp_code.clear(); self.qr_handle = None; }
                    Err(e) => { self.settings_msg = Some((e, true)); }
                }
            }
            Message::ClearSettingsMsg => { self.settings_msg = None; }
            Message::Logout => {
                return Task::perform(async {
                    let _ = Request::post("/api/auth/logout").header("Content-Type", "application/json").body("{}").map_err(|e| format!("{}", e))?.send().await;
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_href("/");
                    }
                    Ok::<(), String>(())
                }, |_| Message::ClearSettingsMsg);
            }
            Message::OpenApp(id) => {
                if let Some(win) = web_sys::window() {
                    let url = format!("/proxy/{}/", id);
                    let _ = win.open_with_url_and_target(&url, "_blank");
                }
            }
            Message::SetCreateUser(v) => { self.create_user = v; }
            Message::SetCreatePass(v) => { self.create_pass = v; }
            Message::SetCreateRole(v) => { self.create_role = v; }
            Message::CreateUser => {}
            Message::GrantAllApps => {}
            Message::AppAccessGranted(_) => {}
            Message::ToggleGrantApp(id) => {
                if self.grant_apps.contains(&id) {
                    self.grant_apps.retain(|&x| x != id);
                } else {
                    self.grant_apps.push(id);
                }
            }
            Message::CreateAndGrantUser => {
                let u = self.create_user.clone(); let p = self.create_pass.clone(); let r = self.create_role.clone();
                let grant = self.grant_apps.clone();
                return Task::perform(async move {
                    let text = api_post_json("/users", &format!(r#"{{"username":"{}","password":"{}","role":"{}"}}"#,u,p,r)).await.map_err(|e| format!("Create failed: {}", e))?;
                    if let Some(err) = text["error"].as_str() { return Err(err.to_string()); }
                    let user_id = text["data"]["id"].as_i64().unwrap_or(0);
                    if user_id > 0 && !grant.is_empty() {
                        let ids: Vec<String> = grant.iter().map(|i| i.to_string()).collect();
                        let _ = api_put_json(&format!("/users/{}/permissions", user_id), &format!(r#"{{"app_ids":[{}]}}"#, ids.join(","))).await;
                    }
                    Ok("User created".to_string())
                }, |r: Result<String, String>| match r { Ok(m) => Message::UserCreated(Ok(m)), Err(e) => Message::UserCreated(Err(e)) });
            }
            Message::SessionChecked(r) => {
                if let Ok(info) = r { self.two_fa_enabled = info.totp_enabled; }
            }
            Message::CheckSession => {
                return Task::perform(async {
                    fetch_text("/api/auth/session").await.ok().and_then(|t| serde_json::from_str::<ApiResponse<SessionInfo2>>(&t).ok().and_then(|r| r.data)).ok_or("session check failed".into())
                }, Message::SessionChecked);
            }
            Message::UserCreated(r) => { match r { Ok(m) => { self.settings_msg = Some((m, false)); self.create_user.clear(); self.create_pass.clear(); } Err(e) => { self.settings_msg = Some((e, true)); } } }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message, StyleType> {
        let demo_icon: Element<'_, Message, StyleType> = if self.demo_mode {
            row![container(text("DEMO").size(10)).padding([2,6]).class(ContainerType::Tooltip), button(text("X").size(10)).on_press(Message::ToggleDemo).padding([2,4]).class(ButtonType::BorderedRound)].align_y(alignment::Vertical::Center).spacing(4).into()
        } else { Space::new().width(Length::Shrink).into() };

        let hdr = container(row![text("Web SSL VPN").font(Font::MONOSPACE).size(16).class(TextType::Incoming), Space::new().width(Length::Fill), demo_icon, Space::new().width(8), text(format!("Uptime {}s", self.uptime)).size(12).class(TextType::Dimmed), Space::new().width(12), button(text("Logout").size(11)).on_press(Message::Logout).padding([4,10]).class(ButtonType::BorderedRound)].align_y(alignment::Vertical::Center)).padding([12,24]).class(ContainerType::BorderedRound);

        let demo_banner: Element<'_, Message, StyleType> = if self.demo_mode { container(row![text("DEMO MODE").size(12).class(TextType::Incoming), Space::new().width(8), text("Data is simulated").size(11).class(TextType::Dimmed), Space::new().width(Length::Fill), button(text("Exit Demo").size(11)).on_press(Message::ToggleDemo).padding([3,10]).class(ButtonType::Standard)].align_y(alignment::Vertical::Center)).padding([6,24]).class(ContainerType::BorderedRound).into() } else { Space::new().height(0).into() };

        let tabs = row(Page::ALL.iter().map(|p| { let a = self.page == *p; button(text(p.label()).size(12)).on_press(Message::SwitchPage(*p)).padding([8,14]).class(if a { ButtonType::TabActive } else { ButtonType::TabInactive }).into() }).collect::<Vec<_>>()).spacing(4).padding([8,24]);

        let body: Element<'_, Message, StyleType> = match self.page {
            Page::Overview => self.view_overview(), Page::Network => self.view_network(), Page::Sessions => self.view_sessions(),
            Page::Apps => self.view_apps(), Page::Audit => self.view_audit(), Page::Ebpf => self.view_ebpf(),
            Page::Settings => self.view_settings(),
        };

        let footer = container(
            row![text("Web SSL VPN Gateway").size(10).class(TextType::Dimmed), Space::new().width(Length::Fill), text("v0.1.0").size(10).class(TextType::Dimmed)]
        ).padding([8,24]).class(ContainerType::BorderedRound);

        column![hdr, demo_banner, tabs, container(body).height(Length::Fill), footer].into()
    }

    fn view_overview(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        container(scrollable(column![row![stat("Requests", &fmt_n(self.requests), p.secondary), stat("Connections", &fmt_n(self.conns), p.outgoing), stat("Uptime", &fmt_t(self.uptime), p.starred)].spacing(8), Space::new().height(16),
            container(column![row![text("Traffic History").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), text("60s").size(10).class(TextType::Dimmed)], Space::new().height(8), bars(&self.sent_history, &self.recv_history)]).padding(16).class(ContainerType::BorderedRound),
        ]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_network(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette(); let q = self.traffic_quota; let unlimited = q == u64::MAX;
        let sp = if unlimited { 0.0 } else { ((self.bytes_sent as f64 / q as f64) * 100.0).min(100.0) as f32 };
        let rp = if unlimited { 0.0 } else { ((self.bytes_recv as f64 / q as f64) * 100.0).min(100.0) as f32 };
        let qrow = { let r: Element<'_, Message, StyleType> = if self.editing_quota { row![pbtn("1 GB", 1_073_741_824), Space::new().width(4), pbtn("5 GB", 5_368_709_120), Space::new().width(4), pbtn("10 GB", 10_737_418_240), Space::new().width(4), pbtn("Unlimited", u64::MAX)].into() } else { button(text(format!("{}  |  Edit", fmt_bytes(q))).size(12)).on_press(Message::EditQuota).padding(4).class(ButtonType::BorderedRound).into() }; row![text("Traffic Quota").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), r].align_y(alignment::Vertical::Center) };
        container(scrollable(column![qrow, Space::new().height(8), row![fcol("Upload", self.bytes_sent, sp, p.secondary, unlimited), Space::new().width(8), fcol("Download", self.bytes_recv, rp, p.outgoing, unlimited)]]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_sessions(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        let st = row![btn("Active", self.active_sessions.len(), self.session_tab == SessionTab::Active), Space::new().width(4), btn("Closed", self.closed_sessions.len(), self.session_tab == SessionTab::Closed), Space::new().width(Length::Fill), button(text("Columns").size(12)).on_press(Message::ToggleSessionColumns).padding([4,8]).class(if self.show_session_cols { ButtonType::BorderedRoundSelected } else { ButtonType::BorderedRound })].spacing(0).align_y(alignment::Vertical::Center);
        let list = if self.session_tab == SessionTab::Active { &self.active_sessions } else { &self.closed_sessions };
        let hdr = row![h("Host",1), h("DL",1), h("UL",1), h("DL Total",1), h("UL Total",1), h("Source",2), h("Target",2), h("Time",1)].spacing(4);
        let rows: Vec<_> = list.iter().map(|s| container(row![v(&s.host,1,TextType::Incoming), v(&fmt_bytes(s.dl_speed),1,TextType::Custom(p.outgoing)), v(&fmt_bytes(s.ul_speed),1,TextType::Custom(p.secondary)), v(&fmt_bytes(s.dl_total),1,TextType::Standard), v(&fmt_bytes(s.ul_total),1,TextType::Standard), v(&s.source,2,TextType::Standard), v(&s.target,2,TextType::Standard), v(&s.connected,1,TextType::Dimmed)].spacing(4)).padding([4,8]).class(ContainerType::BorderedRound).into()).collect();
        container(column![st, Space::new().height(8), container(hdr).padding([4,8]), scrollable(column(rows).spacing(4)).height(Length::Fill)]).padding(24).height(Length::Fill).into()
    }

    fn view_apps(&self) -> Element<'_, Message, StyleType> {
        let cards: Vec<_> = self.apps.iter().map(|a| container(row![
            column![text(&a.name).size(14).class(TextType::Incoming), Space::new().height(4), text(&a.desc).size(12).class(TextType::Dimmed)].width(Length::FillPortion(3)),
            column![text("URL").size(10).class(TextType::Dimmed), text(&a.url).size(12).class(TextType::Standard), Space::new().height(6), button(text("Open \u{2192}").size(11)).on_press(Message::OpenApp(a.id)).padding([4,10]).class(ButtonType::BorderedRound)].width(Length::FillPortion(2)),
        ]).padding(16).class(ContainerType::BorderedRound).into()).collect();
        container(scrollable(column(cards).spacing(8).width(Length::Fill)).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_audit(&self) -> Element<'_, Message, StyleType> {
        let top = row![text("Audit Logs").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), text(format!("{} entries", self.logs.len())).size(10).class(TextType::Dimmed), Space::new().width(8), button(text("Export").size(12)).on_press(Message::ExportLogs).padding([4,8]).class(ButtonType::BorderedRound)].align_y(alignment::Vertical::Center);
        let hdr = row![h("Time",1), h("User",1), h("Action",2), h("Target",3), h("Result",1)].spacing(4);
        let rows: Vec<_> = self.logs.iter().map(|l| { let r = if l.result == "success" { TextType::Outgoing } else { TextType::Danger }; container(row![v(&l.ts,1,TextType::Standard), v(&l.user,1,TextType::Standard), v(&l.action,2,TextType::Incoming), v(&l.target,3,TextType::Standard), v(&l.result,1,r)].spacing(4)).padding([4,8]).class(ContainerType::BorderedRound).into() }).collect();
        container(column![top, Space::new().height(8), container(hdr).padding([4,8]), scrollable(column(rows).spacing(4)).height(Length::Fill)]).padding(24).height(Length::Fill).into()
    }

    fn view_ebpf(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette(); let (sc, sl) = if self.ebpf_active { (p.outgoing, "ACTIVE") } else { (p.starred, "FALLBACK") };
        container(scrollable(column![
            container(row![text("eBPF Monitor").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), container(row![d(sc), Space::new().width(6), text(sl).size(11).class(TextType::Custom(sc))]).padding([2,10]).class(ContainerType::BorderedRound)].align_y(alignment::Vertical::Center)),
            Space::new().height(12),
            row![stat("Bytes Sent", &fmt_bytes(self.bytes_sent), p.secondary), Space::new().width(8), stat("Bytes Recv", &fmt_bytes(self.bytes_recv), p.outgoing), Space::new().width(8), stat("Connections", &fmt_n(self.conns), p.starred)].spacing(0),
            Space::new().height(16),
            container(column![text("BPF Maps").size(12).class(TextType::Subtitle), Space::new().height(6), bpftable(&[("BYTES_SENT","Hash","4096 B"),("BYTES_RECV","Hash","8192 B"),("CONN_COUNT","Array","12")])]).padding(14).class(ContainerType::BorderedRound),
            Space::new().height(12),
            container(column![text("BPF Programs").size(12).class(TextType::Subtitle), Space::new().height(6), bpftable(&[("tc_ingress","SchedClassifier","Attached"),("tc_egress","SchedClassifier","Attached")])]).padding(14).class(ContainerType::BorderedRound),
        ]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_settings(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();

        let msg_display: Element<'_, Message, StyleType> = if let Some((ref msg, is_err)) = self.settings_msg {
            let c = if is_err { TextType::Danger } else { TextType::Outgoing };
            container(column![text(msg.as_str()).size(13).class(c), Space::new().height(4), button(text("Dismiss").size(11)).on_press(Message::ClearSettingsMsg).padding([2,8]).class(ButtonType::BorderedRound)]) .padding(12).class(ContainerType::BorderedRound).into()
        } else { Space::new().height(0).into() };

        let pwd_section = container(column![
            text("Change Password").size(14).class(TextType::Subtitle),
            Space::new().height(12),
            row![text("Old password").size(12).class(TextType::Dimmed).width(Length::Fixed(140.0)), fld(&self.old_password, "current password", true, |v| Message::SetOldPassword(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(6),
            row![text("New password").size(12).class(TextType::Dimmed).width(Length::Fixed(140.0)), fld(&self.new_password, "new password", true, |v| Message::SetNewPassword(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(6),
            row![text("Confirm").size(12).class(TextType::Dimmed).width(Length::Fixed(140.0)), fld(&self.confirm_password, "confirm new password", true, |v| Message::SetConfirmPassword(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(12),
            button(text("Change Password").size(13)).on_press(Message::ChangePassword).padding([8,16]).class(ButtonType::Standard),
        ]).padding(20).class(ContainerType::BorderedRound);

        let mut fa_col = column![text("Two-Factor Authentication").size(14).class(TextType::Subtitle), Space::new().height(12)];

        if self.two_fa_enabled || self.two_fa_setup_data.is_some() {
            if let Some(ref data) = self.two_fa_setup_data {
                fa_col = fa_col
                    .push(row![text("Secret:").size(12).class(TextType::Dimmed), Space::new().width(8), text(&data.secret).font(Font::MONOSPACE).size(12).class(TextType::Incoming)].align_y(alignment::Vertical::Center))
                    .push(Space::new().height(8));
                if let Some(ref handle) = self.qr_handle {
                    fa_col = fa_col.push(container(Image::new(handle.clone()).width(200).height(200)).padding(8).class(ContainerType::BorderedRound));
                    fa_col = fa_col.push(Space::new().height(8));
                    fa_col = fa_col.push(text("Scan with Google Authenticator").size(11).class(TextType::Dimmed));
                } else {
                    fa_col = fa_col.push(text("QR URL:").size(12).class(TextType::Dimmed));
                    fa_col = fa_col.push(text(&data.qr_url).font(Font::MONOSPACE).size(10).class(TextType::Standard));
                }
                fa_col = fa_col.push(Space::new().height(12));
                fa_col = fa_col.push(row![
                    text("Verify code").size(12).class(TextType::Dimmed).width(Length::Fixed(100.0)),
                    fld(&self.totp_code, "6-digit code", false, |v| Message::SetTotpCode(v)),
                    Space::new().width(8),
                    button(text("Verify").size(12)).on_press(Message::Verify2FA).padding([6,12]).class(ButtonType::BorderedRound),
                ].align_y(alignment::Vertical::Center).spacing(6));
                fa_col = fa_col.push(Space::new().height(4));
                fa_col = fa_col.push(text("Enter the 6-digit code from your authenticator app").size(10).class(TextType::Dimmed));
            } else {
                fa_col = fa_col.push(text("2FA enabled").size(13).class(TextType::Outgoing));
                fa_col = fa_col.push(Space::new().height(12));
                fa_col = fa_col.push(row![
                    text("2FA code").size(12).class(TextType::Dimmed).width(Length::Fixed(100.0)),
                    fld(&self.totp_code, "6-digit code", false, |v| Message::SetTotpCode(v)),
                    Space::new().width(8),
                    button(text("Disable 2FA").size(12)).on_press(Message::Disable2FA).padding([6,12]).class(ButtonType::BorderedRound),
                ].align_y(alignment::Vertical::Center).spacing(6));
            }
        } else {
            fa_col = fa_col.push(text("Not configured").size(13).class(TextType::Dimmed));
            fa_col = fa_col.push(Space::new().height(8));
            fa_col = fa_col.push(button(text("Setup Two-Factor Authentication").size(13)).on_press(Message::Setup2FA).padding([8,16]).class(ButtonType::Standard));
        }

        let fa_section = container(fa_col).padding(20).class(ContainerType::BorderedRound);

        let cu = container(column![
            text("Create User").size(14).class(TextType::Subtitle), Space::new().height(12),
            row![text("User").size(12).class(TextType::Dimmed).width(Length::Fixed(80.0)), fld(&self.create_user, "username", false, |v| Message::SetCreateUser(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(6),
            row![text("Pass").size(12).class(TextType::Dimmed).width(Length::Fixed(80.0)), fld(&self.create_pass, "min 8 chars", true, |v| Message::SetCreatePass(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(6),
            row![text("Role").size(12).class(TextType::Dimmed).width(Length::Fixed(80.0)), fld(&self.create_role, "user/admin", false, |v| Message::SetCreateRole(v))].align_y(alignment::Vertical::Center).spacing(8),
            Space::new().height(6),
            row![text("Apps").size(12).class(TextType::Dimmed).width(Length::Fixed(80.0)),
                apbtn(1, &self.grant_apps), Space::new().width(4),
                apbtn(2, &self.grant_apps), Space::new().width(4),
                apbtn(3, &self.grant_apps), Space::new().width(4),
                apbtn(4, &self.grant_apps),
            ].align_y(alignment::Vertical::Center).spacing(4),
            Space::new().height(12),
            button(text("Create & Grant Apps").size(13)).on_press(Message::CreateAndGrantUser).padding([8,16]).class(ButtonType::Standard),
        ]).padding(20).class(ContainerType::BorderedRound);
        container(scrollable(column![msg_display, Space::new().height(12), pwd_section, Space::new().height(12), fa_section, Space::new().height(12), cu]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }
}

impl Default for WebSslVpn {
    fn default() -> Self { Self {
        page: Page::Overview, session_tab: SessionTab::Active, show_session_cols: false,
        traffic_quota: 1_073_741_824, editing_quota: false, demo_mode: false, ebpf_active: true,
        uptime: 0, requests: 0, conns: 0, bytes_sent: 0, bytes_recv: 0,
        sent_history: Vec::new(), recv_history: Vec::new(),
        frame: 0, prev_bytes_sent: 0.0, prev_bytes_recv: 0.0,
        active_sessions: Vec::new(), closed_sessions: Vec::new(), apps: Vec::new(), logs: Vec::new(),
        old_password: String::new(), new_password: String::new(), confirm_password: String::new(),
        totp_code: String::new(), two_fa_setup_data: None, two_fa_enabled: false, qr_handle: None, settings_msg: None,
        create_user: String::new(), create_pass: String::new(), create_role: "user".into(),
        grant_apps: vec![1, 2, 3, 4],
    }}
}

fn stat(label: &str, val: &str, c: iced::Color) -> Element<'static, Message, StyleType> {
    let l = label.to_string(); let v = val.to_string();
    container(column![text(l).size(10).class(TextType::Dimmed), Space::new().height(4), text(v).size(24).class(TextType::Custom(c))]).padding(16).width(Length::Fill).class(ContainerType::BorderedRound).into()
}
fn fcol(dir: &str, bytes: u64, pct: f32, c: iced::Color, unlimited: bool) -> Element<'static, Message, StyleType> {
    let d = dir.to_string(); let pct_text = if unlimited { "--".into() } else { format!("{:.1}%", pct) };
    container(column![text(d).size(14).class(TextType::Subtitle), Space::new().height(8), text(fmt_bytes(bytes)).size(24).class(TextType::Custom(c)), Space::new().height(4), qbar(pct, c, unlimited), Space::new().height(4), text(pct_text).size(10).class(TextType::Dimmed)]).padding(16).width(Length::FillPortion(1)).class(ContainerType::BorderedRound).into()
}
fn btn(label: &str, n: usize, a: bool) -> Element<'static, Message, StyleType> {
    button(text(format!("{} ({})", label, n)).size(12)).on_press(Message::ToggleSessionTab).padding([4,10]).class(if a { ButtonType::TabActive } else { ButtonType::TabInactive }).into()
}
fn pbtn(label: &str, q: u64) -> Element<'static, Message, StyleType> {
    button(text(label.to_string()).size(12)).on_press(Message::SetQuota(q)).padding([2,8]).class(ButtonType::BorderedRound).into()
}
fn apbtn(id: i64, selected: &[i64]) -> Element<'static, Message, StyleType> {
    let on = selected.contains(&id);
    button(text(format!("App {id}")).size(11)).on_press(Message::ToggleGrantApp(id)).padding([4,8])
        .class(if on { ButtonType::TabActive } else { ButtonType::TabInactive }).into()
}
fn h(l: &str, w: u16) -> Element<'static, Message, StyleType> { text(l.to_string()).size(10).class(TextType::Dimmed).width(Length::FillPortion(w)).into() }
fn v(s: &str, w: u16, k: TextType) -> Element<'static, Message, StyleType> { text(s.to_string()).size(11).class(k).width(Length::FillPortion(w)).into() }
fn fld<'a>(val: &str, placeholder: &str, is_pw: bool, on_change: impl Fn(String) -> Message + 'a) -> Element<'a, Message, StyleType> {
    let input = if is_pw { text_input(placeholder, val).secure(true) } else { text_input(placeholder, val) };
    container(input.on_input(on_change).padding([8,10]).size(14)).class(ContainerType::BorderedRound).width(Length::Fill).into()
}

fn qbar(pct: f32, c: iced::Color, unlimited: bool) -> Element<'static, Message, StyleType> {
    if unlimited { return container(row![container(Space::new().height(4)).width(Length::Fill).class(ContainerType::SolidColor(c))]).into(); }
    let p = pct.clamp(0.0,100.0);
    container(row![container(Space::new().width(1).height(4)).width(Length::FillPortion((p*100.0) as u16)).class(ContainerType::SolidColor(c)), container(Space::new().width(1).height(4)).width(Length::FillPortion(((100.0-p)*100.0).max(1.0) as u16)).class(ContainerType::SolidColor(iced::Color{a:0.08,..c}))]).into()
}
fn bars(sent: &[f32], recv: &[f32]) -> Element<'static, Message, StyleType> {
    let p = StyleType::NordDark.get_palette();
    if sent.is_empty() { return container(column![container(Space::new().height(Length::Fixed(100.0)).width(Length::Fill)), Space::new().height(8), row![d(p.secondary), Space::new().width(4), text("Sent").size(10).class(TextType::Dimmed), Space::new().width(12), d(p.outgoing), Space::new().width(4), text("Received").size(10).class(TextType::Dimmed)].align_y(alignment::Vertical::Center).spacing(0)]).into(); }
    let max = sent.iter().chain(recv).cloned().fold(0.0f32, f32::max).max(1.0); let n = sent.len();
    let bs: Vec<_> = (0..n).map(|i| { let sh = (sent[i]/max*50.0).max(1.0); let rh = (recv[i]/max*50.0).max(1.0); column![container(Space::new().width(Length::Fixed(3.0)).height(Length::Fixed(sh))).class(ContainerType::SolidColor(p.secondary)), Space::new().height(1), container(Space::new().width(Length::Fixed(3.0)).height(Length::Fixed(rh))).class(ContainerType::SolidColor(p.outgoing))].into() }).collect();
    container(column![container(row(bs).spacing(1)).height(Length::Fixed(100.0)).width(Length::Fill), Space::new().height(8), row![d(p.secondary), Space::new().width(4), text("Sent").size(10).class(TextType::Dimmed), Space::new().width(12), d(p.outgoing), Space::new().width(4), text("Received").size(10).class(TextType::Dimmed)].align_y(alignment::Vertical::Center).spacing(0)]).into()
}
fn d(c: iced::Color) -> Element<'static, Message, StyleType> { container(Space::new().width(8).height(8)).class(ContainerType::SolidColor(c)).into() }
fn bpftable<'a>(rows: &[(&'a str, &'a str, &'a str)]) -> Element<'a, Message, StyleType> {
    let hdr = row![text("Name").size(10).class(TextType::Dimmed).width(Length::FillPortion(3)), text("Type").size(10).class(TextType::Dimmed).width(Length::FillPortion(3)), text("Value / Status").size(10).class(TextType::Dimmed).width(Length::FillPortion(2))].spacing(4);
    let body: Vec<Element<'a, Message, StyleType>> = rows.iter().map(|(n,t,v)| { let vc = if *v=="Attached" { TextType::Outgoing } else { TextType::Incoming }; container(row![text(*n).size(11).class(TextType::Standard).width(Length::FillPortion(3)), text(*t).size(11).class(TextType::Dimmed).width(Length::FillPortion(3)), text(*v).size(11).class(vc).width(Length::FillPortion(2))].spacing(4)).padding([2,0]).into() }).collect();
    column![hdr, Space::new().height(4), column(body).spacing(2)].into()
}
fn fmt_n(n: u64) -> String { n.to_string() }
fn fmt_t(s: u64) -> String { format!("{}m {}s", s/60, s%60) }
fn fmt_bytes(b: u64) -> String {
    if b == u64::MAX { return "Unlimited".into(); }
    if b>=1_073_741_824 { format!("{:.2} GB", b as f64/1_073_741_824.0) } else if b>=1_048_576 { format!("{:.2} MB", b as f64/1_048_576.0) } else if b>=1024 { format!("{:.2} KB", b as f64/1024.0) } else { format!("{} B", b) }
}
