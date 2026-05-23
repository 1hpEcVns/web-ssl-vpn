mod styles;

use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Element, Length, Task,
    alignment, Font, time,
};
use styles::{ContainerType, ButtonType, TextType, StyleType};

fn main() -> iced::Result {
    iced::application(WebSslVpn::boot, WebSslVpn::update, WebSslVpn::view)
        .title("Web SSL VPN")
        .theme(WebSslVpn::theme)
        .subscription(WebSslVpn::subscription)
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page { Overview, Network, Sessions, Apps, Audit, Ebpf }

impl Page {
    const ALL: [Page; 6] = [Page::Overview, Page::Network, Page::Sessions, Page::Apps, Page::Audit, Page::Ebpf];
    fn label(&self) -> &str {
        match self { Page::Overview => "Overview", Page::Network => "Network", Page::Sessions => "Sessions", Page::Apps => "Apps", Page::Audit => "Audit", Page::Ebpf => "eBPF" }
    }
}

#[derive(Debug, Clone)]
enum Message { SwitchPage(Page), Tick, ToggleSessionTab, ToggleSessionColumns, ExportLogs, SetQuota(u64), EditQuota, ToggleDemo }

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
}

#[derive(Debug, Clone)] struct AppInfo { name: String, url: String, desc: String }
#[derive(Debug, Clone)] struct LogEntry { ts: String, user: String, action: String, target: String, result: String }

#[derive(Debug, Clone)]
struct SessionInfo {
    host: String, dl_speed: u64, ul_speed: u64,
    dl_total: u64, ul_total: u64,
    source: String, target: String, connected: String,
}

impl WebSslVpn {
    fn theme(&self) -> StyleType { StyleType::NordDark }
    fn subscription(&self) -> iced::Subscription<Message> {
        time::every(std::time::Duration::from_secs(1)).map(|_| Message::Tick)
    }
    fn boot() -> (Self, Task<Message>) { (Self::default(), Task::none()) }

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::SwitchPage(p) => self.page = p,
            Message::ToggleSessionTab => { self.session_tab = match self.session_tab { SessionTab::Active => SessionTab::Closed, SessionTab::Closed => SessionTab::Active }; }
            Message::ToggleSessionColumns => { self.show_session_cols = !self.show_session_cols; }
            Message::ExportLogs => {}
            Message::EditQuota => { self.editing_quota = !self.editing_quota; }
            Message::SetQuota(val) => { self.traffic_quota = val; self.editing_quota = false; }
            Message::ToggleDemo => {
                self.demo_mode = !self.demo_mode;
                if !self.demo_mode {
                    self.uptime = 0;
                    self.requests = 0;
                    self.conns = 0;
                    self.bytes_sent = 0;
                    self.bytes_recv = 0;
                    self.sent_history.clear();
                    self.recv_history.clear();
                }
            }
            Message::Tick => {
                self.uptime += 1;
                if self.uptime % 3 == 0 {
                    self.requests = self.requests.saturating_add(1 + (self.uptime % 7));
                    self.bytes_sent = self.bytes_sent.wrapping_add(1024 * (20 + self.uptime % 80));
                    self.bytes_recv = self.bytes_recv.wrapping_add(1024 * (8 + self.uptime % 60));
                }
                self.conns = 2 + (self.uptime % 12) as u64;
                self.sent_history.push(self.bytes_sent as f32 / 1048576.0);
                self.recv_history.push(self.bytes_recv as f32 / 1048576.0);
                if self.sent_history.len() > 60 { self.sent_history.remove(0); self.recv_history.remove(0); }
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message, StyleType> {
        let demo_icon: Element<'_, Message, StyleType> = if self.demo_mode {
            row![
                container(text("DEMO").size(10)).padding([2, 6])
                    .class(ContainerType::Tooltip),
                button(text("X").size(10)).on_press(Message::ToggleDemo).padding([2, 4])
                    .class(ButtonType::BorderedRound),
            ].align_y(alignment::Vertical::Center).spacing(4).into()
        } else {
            Space::new().width(Length::Shrink).into()
        };

        let hdr = container(
            row![
                text("Web SSL VPN").font(Font::MONOSPACE).size(16).class(TextType::Incoming),
                Space::new().width(Length::Fill),
                demo_icon,
                Space::new().width(8),
                text(format!("Uptime {}s", self.uptime)).size(12).class(TextType::Dimmed),
            ].align_y(alignment::Vertical::Center)
        ).padding([12, 24]).class(ContainerType::BorderedRound);

        let demo_banner: Element<'_, Message, StyleType> = if self.demo_mode {
            container(
                row![
                    text("DEMO MODE").size(12).class(TextType::Incoming),
                    Space::new().width(8),
                    text("Data is simulated").size(11).class(TextType::Dimmed),
                    Space::new().width(Length::Fill),
                    button(text("Exit Demo").size(11)).on_press(Message::ToggleDemo).padding([3, 10])
                        .class(ButtonType::Standard),
                ].align_y(alignment::Vertical::Center)
            ).padding([6, 24]).class(ContainerType::BorderedRound).into()
        } else {
            Space::new().height(0).into()
        };

        let tabs = row(
            Page::ALL.iter().map(|p| {
                let a = self.page == *p;
                button(text(p.label()).size(12)).on_press(Message::SwitchPage(*p)).padding([8, 14])
                    .class(if a { ButtonType::TabActive } else { ButtonType::TabInactive }).into()
            }).collect::<Vec<_>>()
        ).spacing(4).padding([8, 24]);

        let body: Element<'_, Message, StyleType> = match self.page {
            Page::Overview => self.view_overview(),
            Page::Network => self.view_network(),
            Page::Sessions => self.view_sessions(),
            Page::Apps => self.view_apps(),
            Page::Audit => self.view_audit(),
            Page::Ebpf => self.view_ebpf(),
        };

        let footer = container(
            row![
                text("Web SSL VPN Gateway").size(10).class(TextType::Dimmed),
                Space::new().width(Length::Fill),
                text("v0.1.0").size(10).class(TextType::Dimmed),
            ]
        ).padding([8, 24]).class(ContainerType::BorderedRound);

        column![hdr, demo_banner, tabs, container(body).height(Length::Fill), footer].into()
    }

    fn view_overview(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        container(scrollable(column![
            row![
                stat("Requests", &fmt_n(self.requests), p.secondary),
                stat("Connections", &fmt_n(self.conns), p.outgoing),
                stat("Uptime", &fmt_t(self.uptime), p.starred),
            ].spacing(8),
            Space::new().height(16),
            container(column![
                row![text("Traffic History").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), text("60s").size(10).class(TextType::Dimmed)],
                Space::new().height(8),
                bars(&self.sent_history, &self.recv_history),
            ]).padding(16).class(ContainerType::BorderedRound),
        ]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_network(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        let q = self.traffic_quota;
        let unlimited = q == u64::MAX;
        let sp = if unlimited { 0.0 } else { ((self.bytes_sent as f64 / q as f64) * 100.0).min(100.0) as f32 };
        let rp = if unlimited { 0.0 } else { ((self.bytes_recv as f64 / q as f64) * 100.0).min(100.0) as f32 };

        let qrow = {
            let r: Element<'_, Message, StyleType> = if self.editing_quota {
                row![
                    pbtn("1 GB", 1_073_741_824), Space::new().width(4),
                    pbtn("5 GB", 5_368_709_120), Space::new().width(4),
                    pbtn("10 GB", 10_737_418_240), Space::new().width(4),
                    pbtn("Unlimited", u64::MAX),
                ].into()
            } else {
                button(text(format!("{}  |  Edit", fmt_bytes(q))).size(12)).on_press(Message::EditQuota).padding(4).class(ButtonType::BorderedRound).into()
            };
            row![text("Traffic Quota").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill), r].align_y(alignment::Vertical::Center)
        };

        container(scrollable(column![
            qrow, Space::new().height(8),
            row![fcol("Upload", self.bytes_sent, sp, p.secondary, unlimited), Space::new().width(8), fcol("Download", self.bytes_recv, rp, p.outgoing, unlimited)],
        ]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_sessions(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        let st = row![
            btn("Active", self.active_sessions.len(), self.session_tab == SessionTab::Active), Space::new().width(4),
            btn("Closed", self.closed_sessions.len(), self.session_tab == SessionTab::Closed), Space::new().width(Length::Fill),
            button(text("Columns").size(12)).on_press(Message::ToggleSessionColumns).padding([4, 8])
                .class(if self.show_session_cols { ButtonType::BorderedRoundSelected } else { ButtonType::BorderedRound }),
        ].spacing(0).align_y(alignment::Vertical::Center);

        let list = if self.session_tab == SessionTab::Active { &self.active_sessions } else { &self.closed_sessions };
        let hdr = row![h("Host",1), h("DL Speed",1), h("UL Speed",1), h("DL Total",1), h("UL Total",1), h("Source",2), h("Target",2), h("Time",1)].spacing(4);
        let rows: Vec<_> = list.iter().map(|s| container(row![
            v(&s.host,1,TextType::Incoming), v(&fmt_bytes(s.dl_speed),1,TextType::Custom(p.outgoing)),
            v(&fmt_bytes(s.ul_speed),1,TextType::Custom(p.secondary)), v(&fmt_bytes(s.dl_total),1,TextType::Standard),
            v(&fmt_bytes(s.ul_total),1,TextType::Standard), v(&s.source,2,TextType::Standard),
            v(&s.target,2,TextType::Standard), v(&s.connected,1,TextType::Dimmed),
        ].spacing(4)).padding([4,8]).class(ContainerType::BorderedRound).into()).collect();

        container(column![st, Space::new().height(8), container(hdr).padding([4,8]),
            scrollable(column(rows).spacing(4)).height(Length::Fill),
        ]).padding(24).height(Length::Fill).into()
    }

    fn view_apps(&self) -> Element<'_, Message, StyleType> {
        let cards: Vec<_> = self.apps.iter().map(|a| container(row![
            column![text(&a.name).size(14).class(TextType::Incoming), Space::new().height(4), text(&a.desc).size(12).class(TextType::Dimmed)].width(Length::FillPortion(3)),
            column![text("URL").size(10).class(TextType::Dimmed), text(&a.url).size(12).class(TextType::Standard)].width(Length::FillPortion(2)),
        ]).padding(16).class(ContainerType::BorderedRound).into()).collect();
        container(scrollable(column(cards).spacing(8).width(Length::Fill)).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }

    fn view_audit(&self) -> Element<'_, Message, StyleType> {
        let top = row![
            text("Audit Logs").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill),
            text(format!("{} entries", self.logs.len())).size(10).class(TextType::Dimmed), Space::new().width(8),
            button(text("Export").size(12)).on_press(Message::ExportLogs).padding([4,8]).class(ButtonType::BorderedRound),
        ].align_y(alignment::Vertical::Center);
        let hdr = row![h("Time",1), h("User",1), h("Action",2), h("Target",3), h("Result",1)].spacing(4);
        let rows: Vec<_> = self.logs.iter().map(|l| {
            let r = if l.result == "success" { TextType::Outgoing } else { TextType::Danger };
            container(row![v(&l.ts,1,TextType::Standard), v(&l.user,1,TextType::Standard), v(&l.action,2,TextType::Incoming), v(&l.target,3,TextType::Standard), v(&l.result,1,r)].spacing(4))
                .padding([4,8]).class(ContainerType::BorderedRound).into()
        }).collect();
        container(column![top, Space::new().height(8), container(hdr).padding([4,8]), scrollable(column(rows).spacing(4)).height(Length::Fill)]).padding(24).height(Length::Fill).into()
    }

    fn view_ebpf(&self) -> Element<'_, Message, StyleType> {
        let p = StyleType::NordDark.get_palette();
        let (sc, sl) = if self.ebpf_active { (p.outgoing, "ACTIVE") } else { (p.starred, "FALLBACK") };
        container(scrollable(column![
            container(row![
                text("eBPF Monitor").size(14).class(TextType::Subtitle), Space::new().width(Length::Fill),
                container(row![d(sc), Space::new().width(6), text(sl).size(11).class(TextType::Custom(sc))])
                    .padding([2, 10]).class(ContainerType::BorderedRound),
            ].align_y(alignment::Vertical::Center)),
            Space::new().height(12),
            row![
                stat("Bytes Sent", &fmt_bytes(self.bytes_sent), p.secondary),
                Space::new().width(8),
                stat("Bytes Recv", &fmt_bytes(self.bytes_recv), p.outgoing),
                Space::new().width(8),
                stat("Connections", &fmt_n(self.conns), p.starred),
            ].spacing(0),
            Space::new().height(16),
            container(column![
                text("BPF Maps").size(12).class(TextType::Subtitle),
                Space::new().height(6),
                bpftable(&[("BYTES_SENT", "Hash", "4096 B"), ("BYTES_RECV", "Hash", "8192 B"), ("CONN_COUNT", "Array", "12")]),
            ]).padding(14).class(ContainerType::BorderedRound),
            Space::new().height(12),
            container(column![
                text("BPF Programs").size(12).class(TextType::Subtitle),
                Space::new().height(6),
                bpftable(&[("tc_ingress", "SchedClassifier", "Attached"), ("tc_egress", "SchedClassifier", "Attached")]),
            ]).padding(14).class(ContainerType::BorderedRound),
        ]).height(Length::Fill)).padding(24).height(Length::Fill).into()
    }
}

impl Default for WebSslVpn {
    fn default() -> Self { Self {
        page: Page::Overview, session_tab: SessionTab::Active, show_session_cols: false,
        traffic_quota: 1_073_741_824, editing_quota: false, demo_mode: true, ebpf_active: true,
        uptime: 0, requests: 0, conns: 0, bytes_sent: 0, bytes_recv: 0,
        sent_history: Vec::new(), recv_history: Vec::new(),
        active_sessions: vec![
            SessionInfo { host: "admin-pc".into(), dl_speed: 524288, ul_speed: 65536, dl_total: 52428800, ul_total: 2097152, source: "192.168.1.100:54321".into(), target: "wiki.internal:3000".into(), connected: "5m 23s".into() },
            SessionInfo { host: "dev-laptop".into(), dl_speed: 262144, ul_speed: 131072, dl_total: 125829120, ul_total: 8388608, source: "10.0.0.55:61234".into(), target: "mail.internal:8080".into(), connected: "12m".into() },
        ],
        closed_sessions: vec![SessionInfo { host: "guest-vm".into(), dl_speed: 0, ul_speed: 0, dl_total: 5242880, ul_total: 524288, source: "192.168.1.200:45678".into(), target: "wiki.internal:3000".into(), connected: "3m".into() }],
        apps: vec![
            AppInfo { name: "Internal Wiki".into(), url: "wiki.internal:3000".into(), desc: "Company documentation".into() },
            AppInfo { name: "Mail Server".into(), url: "mail.internal:8080".into(), desc: "Roundcube webmail".into() },
        ],
        logs: vec![
            LogEntry { ts: "09:30".into(), user: "admin".into(), action: "login".into(), target: "/api/auth/login".into(), result: "success".into() },
            LogEntry { ts: "09:31".into(), user: "user1".into(), action: "proxy_access".into(), target: "wiki.internal:3000".into(), result: "success".into() },
            LogEntry { ts: "09:32".into(), user: "guest".into(), action: "access_denied".into(), target: "mail.internal:8080".into(), result: "denied".into() },
        ],
    }}
}

fn stat(label: &str, val: &str, c: iced::Color) -> Element<'static, Message, StyleType> {
    let l = label.to_string(); let v = val.to_string();
    container(column![text(l).size(10).class(TextType::Dimmed), Space::new().height(4), text(v).size(24).class(TextType::Custom(c))])
        .padding(16).width(Length::Fill).class(ContainerType::BorderedRound).into()
}
fn fcol(dir: &str, bytes: u64, pct: f32, c: iced::Color, unlimited: bool) -> Element<'static, Message, StyleType> {
    let d = dir.to_string();
    let pct_text = if unlimited { "--".into() } else { format!("{:.1}%", pct) };
    container(column![text(d).size(14).class(TextType::Subtitle), Space::new().height(8), text(fmt_bytes(bytes)).size(24).class(TextType::Custom(c)), Space::new().height(4), qbar(pct, c, unlimited), Space::new().height(4), text(pct_text).size(10).class(TextType::Dimmed)])
        .padding(16).width(Length::FillPortion(1)).class(ContainerType::BorderedRound).into()
}
fn btn(label: &str, n: usize, a: bool) -> Element<'static, Message, StyleType> {
    button(text(format!("{} ({})", label, n)).size(12)).on_press(Message::ToggleSessionTab).padding([4,10]).class(if a { ButtonType::TabActive } else { ButtonType::TabInactive }).into()
}
fn pbtn(label: &str, q: u64) -> Element<'static, Message, StyleType> {
    button(text(label.to_string()).size(12)).on_press(Message::SetQuota(q)).padding([2,8]).class(ButtonType::BorderedRound).into()
}
fn h(l: &str, w: u16) -> Element<'static, Message, StyleType> { text(l.to_string()).size(10).class(TextType::Dimmed).width(Length::FillPortion(w)).into() }
fn v(s: &str, w: u16, k: TextType) -> Element<'static, Message, StyleType> { text(s.to_string()).size(11).class(k).width(Length::FillPortion(w)).into() }
fn qbar(pct: f32, c: iced::Color, unlimited: bool) -> Element<'static, Message, StyleType> {
    if unlimited {
        return container(row![
            container(Space::new().height(4)).width(Length::Fill).class(ContainerType::SolidColor(c)),
        ]).into();
    }
    let p = pct.clamp(0.0, 100.0);
    container(row![container(Space::new().width(1).height(4)).width(Length::FillPortion((p*100.0) as u16)).class(ContainerType::SolidColor(c)), container(Space::new().width(1).height(4)).width(Length::FillPortion(((100.0-p)*100.0).max(1.0) as u16)).class(ContainerType::SolidColor(iced::Color{a:0.08,..c}))]).into()
}
fn bars(sent: &[f32], recv: &[f32]) -> Element<'static, Message, StyleType> {
    let p = StyleType::NordDark.get_palette();
    if sent.is_empty() {
        return container(column![
            container(Space::new().height(Length::Fixed(100.0)).width(Length::Fill)),
            Space::new().height(8),
            row![d(p.secondary), Space::new().width(4), text("Sent").size(10).class(TextType::Dimmed), Space::new().width(12), d(p.outgoing), Space::new().width(4), text("Received").size(10).class(TextType::Dimmed)]
                .align_y(alignment::Vertical::Center).spacing(0),
        ]).into();
    }
    let max = sent.iter().chain(recv).cloned().fold(0.0f32, f32::max).max(1.0);
    let n = sent.len();
    let bs: Vec<_> = (0..n).map(|i| {
        let sh = (sent[i]/max*50.0).max(1.0); let rh = (recv[i]/max*50.0).max(1.0);
        column![
            container(Space::new().width(Length::Fixed(3.0)).height(Length::Fixed(sh))).class(ContainerType::SolidColor(p.secondary)),
            Space::new().height(1),
            container(Space::new().width(Length::Fixed(3.0)).height(Length::Fixed(rh))).class(ContainerType::SolidColor(p.outgoing)),
        ].into()
    }).collect();
    container(column![container(row(bs).spacing(1)).height(Length::Fixed(100.0)).width(Length::Fill), Space::new().height(8),
        row![d(p.secondary), Space::new().width(4), text("Sent").size(10).class(TextType::Dimmed), Space::new().width(12), d(p.outgoing), Space::new().width(4), text("Received").size(10).class(TextType::Dimmed)].align_y(alignment::Vertical::Center).spacing(0),
    ]).into()
}
fn d(c: iced::Color) -> Element<'static, Message, StyleType> { container(Space::new().width(8).height(8)).class(ContainerType::SolidColor(c)).into() }
fn bpftable<'a>(rows: &[(&'a str, &'a str, &'a str)]) -> Element<'a, Message, StyleType> {
    let hdr = row![
        text("Name").size(10).class(TextType::Dimmed).width(Length::FillPortion(3)),
        text("Type").size(10).class(TextType::Dimmed).width(Length::FillPortion(3)),
        text("Value / Status").size(10).class(TextType::Dimmed).width(Length::FillPortion(2)),
    ].spacing(4);
    let body: Vec<Element<'a, Message, StyleType>> = rows.iter().map(|(n, t, v)| {
        let vc = if *v == "Attached" { TextType::Outgoing } else { TextType::Incoming };
        container(row![
            text(*n).size(11).class(TextType::Standard).width(Length::FillPortion(3)),
            text(*t).size(11).class(TextType::Dimmed).width(Length::FillPortion(3)),
            text(*v).size(11).class(vc).width(Length::FillPortion(2)),
        ].spacing(4)).padding([2, 0]).into()
    }).collect();
    column![hdr, Space::new().height(4), column(body).spacing(2)].into()
}
fn fmt_n(n: u64) -> String { n.to_string() }
fn fmt_t(s: u64) -> String { format!("{}m {}s", s/60, s%60) }
fn fmt_bytes(b: u64) -> String {
    if b == u64::MAX { return "Unlimited".into(); }
    if b>=1_073_741_824 { format!("{:.2} GB", b as f64/1_073_741_824.0) }
    else if b>=1_048_576 { format!("{:.2} MB", b as f64/1_048_576.0) }
    else if b>=1024 { format!("{:.2} KB", b as f64/1024.0) }
    else { format!("{} B", b) }
}
