# Web SSL VPN

基于 Web 门户的轻量级 SSL VPN 网关。HTTPS + 反向代理 + RBAC + eBPF 流量监控。

> 需求文档: [goal.md](goal.md) | UI 截图 [samples/](samples/) | 代码讲解 [samples/slides/](samples/slides/)

## 技术栈

| 层级 | 选型 |
|------|------|
| 代理引擎 | Pingora 0.8 (Cloudflare), TLS 1.3 + HTTP/2 |
| 前端 | Iced 0.14 → WebAssembly, WebGL, Trunk bundler |
| 样式 | Palette 配色 + ContainerType/ButtonType/TextType Catalog |
| 数据库 | Sea-ORM 2.0 + SQLite |
| 认证 | argon2, UUID v4 Session, HttpOnly Cookie |
| eBPF | aya 0.13, TC classifier, bpf-linker 编译 |
| 运行时 | Tokio async, Arc<Mutex<AppState>> |
| 构建 | Zig build system + Nix Flakes |

## 架构

```
浏览器 ──TLS──▶ Pingora ──proxy──▶ 内网应用
                 │    │
              SQLite  eBPF(TC)
              (会话)   (流量统计)
                       │
                  Iced WASM 仪表盘
```

## 功能矩阵

| 功能 | 来源 |
|------|------|
| HTTPS 门户 | TLS 1.2/1.3 终止, CA 证书 |
| 身份认证 | argon2 哈希, UUID Session, Cookie |
| RBAC | admin/user 角色, 应用级权限 |
| 反向代理 | `/proxy/{id}/*` 动态路由 |
| 审计日志 | 登录/代理/拒绝记录 |
| 演示模式 | `VPN_DEMO=true` 跳过认证 |
| 六页仪表盘 | Overview/Network/Sessions/Apps/Audit/eBPF |
| 实时流量图 | 60s 历史, 上传/下载配额 |
| eBPF 监控 | TC ingress/egress, 字节/连接计数 |

## 启动

```bash
nix develop --ignore-environment
zig build run
# → https://localhost:8443   admin / admin123
```

```bash
# 演示模式
VPN_DEMO=true zig build run

# eBPF 模式 (需 root)
VPN_EBPF_IFACE=eth0 zig build ebpf-run
```

## 构建命令

| 命令 | 说明 |
|------|------|
| `zig build check` | cargo check 全量 |
| `zig build test` | cargo test (21) |
| `zig build trunk` | WASM 前端 |
| `zig build run` | 全量 + 启动 |
| `zig build ebpf-build` | BPF 字节码 |
| `zig build ebpf-run` | BPF + sudo 启动 |
| `zig build release` | Release 构建 |

## 配置环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `VPN_HTTP_BIND` | `0.0.0.0:8080` | HTTP 地址 |
| `VPN_HTTPS_BIND` | `0.0.0.0:8443` | HTTPS 地址 |
| `VPN_DB_PATH` | `vpn.db` | 数据库 |
| `VPN_SESSION_HOURS` | `8` | 超时 |
| `VPN_DEMO` | `false` | 演示模式 |
| `VPN_EBPF_IFACE` | `lo` | eBPF 网卡 |

## API

| 方法 | 路径 | 权限 |
|------|------|------|
| POST | `/api/auth/login` | — |
| POST | `/api/auth/logout` | — |
| GET | `/api/auth/session` | — |
| GET | `/api/status` | — |
| GET | `/api/apps` | 登录 |
| POST | `/api/apps` | admin |
| DELETE | `/api/apps/{id}` | admin |
| GET | `/api/users` | admin |
| POST | `/api/users` | admin |
| PUT | `/api/users/{id}/permissions` | admin |
| GET | `/api/audit` | admin |
| GET | `/proxy/{app_id}/*` | 登录+权限 |

## 目录结构

```
web-ssl-vpn/
├── build.zig                 # Zig 构建编排
├── Cargo.toml                # Rust workspace (server/web/ebpf)
├── flake.nix                 # Nix 开发环境
├── goal.md                   # 需求文档
├── issues.md                 # 完成清单
├── test.zig                  # Zig test stub
│
├── certs/                    # TLS 证书
│   ├── ca.crt / ca.key
│   ├── server.crt / server.key
│   └── ext.cnf
│
├── server/                   # ── Pingora 后端 ──
│   ├── Cargo.toml
│   ├── build.rs              #   编译前构建 eBPF
│   ├── html/
│   │   ├── login.html        #   登录页（备用）
│   │   └── dashboard.html    #   仪表盘模板（备用）
│   └── src/
│       ├── main.rs           #   入口 / ProxyHttp / API / 反向代理
│       ├── db.rs             #   Sea-ORM 实体 + CRUD + 测试
│       ├── config.rs         #   ServerConfig + env
│       ├── status.rs         #   请求/字节/会话计数
│       └── ebpf.rs           #   TC 监控加载 + 回退
│
├── ebpf/                     # ── eBPF 程序 ──
│   ├── Cargo.toml
│   ├── .cargo/config.toml    #   bpf-linker 配置
│   └── src/
│       └── lib.rs            #   tc_ingress / tc_egress classifier
│
├── web/                      # ── Iced WASM 前端 ──
│   ├── Cargo.toml
│   ├── Trunk.toml
│   ├── index.html            #   WASM 入口
│   ├── dist/                 #   trunk build 产物
│   └── src/
│       ├── main.rs           #   6 页仪表盘 (TEA 模式)
│       └── styles/           #   Palette + Catalog 样式
│           ├── mod.rs
│           ├── button.rs
│           ├── container.rs
│           ├── text.rs
│           ├── scrollbar.rs
│           └── types/
│               ├── palette.rs
│               ├── palette_extension.rs
│               ├── custom_palette.rs
│               └── style_type.rs
│
└── samples/                  # 截图 + 代码讲解
    ├── 01-ebpf.png ... 06-overview.png
    └── slides/
```

## 许可证

MIT License
