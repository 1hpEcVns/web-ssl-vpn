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
| 认证 | argon2 (每用户随机盐), UUID v4 Session, HttpOnly Cookie |
| 安全 | CSRF Origin/Referer 检查, 登录频率限制, CSP/安全响应头 |
| eBPF | aya 0.13, TC classifier, bpf-linker 编译 |
| 运行时 | Tokio async, Arc<Mutex<AppState>>, 后台会话清理 |
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

后台任务每 5 分钟自动清理过期 session。

## 功能矩阵

| 功能 | 来源 |
|------|------|
| HTTPS 门户 | TLS 1.2/1.3 终止, CA 证书 |
| 身份认证 | argon2 随机盐哈希, UUID Session, HttpOnly Strict Cookie |
| RBAC | admin/user 角色, 应用级权限 |
| 反向代理 | `/proxy/{id}/*` 动态路由 |
| 审计日志 | 登录/代理/拒绝记录 |
| 演示模式 | `VPN_DEMO=true` 跳过认证 |
| CSRF 保护 | POST/PUT/DELETE 校验 Origin/Referer |
| 频率限制 | 登录 10 次/15 分钟, IP 级 |
| 安全响应头 | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 输入校验 | username/password/URL/app name 格式检查 |
| 会话详情 | SystemStats 返回 session_details[] (用户/IP/连接时间) |
| 定期清理 | 后台任务每 5 分钟清理过期 session |
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
VPN_EBPF_IFACE=eth0 VPN_EBPF_BPF_PATH=/path/to/ebpf zig build ebpf-run
```

## 构建命令

| 命令 | 说明 |
|------|------|
| `zig build check` | cargo check 全量 |
| `zig build test` | cargo test (42) |
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
| `VPN_EBPF_BPF_PATH` | — | eBPF 字节码路径 (自动搜索默认路径) |
| `VPN_LOG_LEVEL` | `info` | 日志级别 |
| `VPN_TLS_CERT` | `certs/server.crt` | TLS 证书 |
| `VPN_TLS_KEY` | `certs/server.key` | TLS 密钥 |

## API

| 方法 | 路径 | 权限 | CSRF 检查 |
|------|------|------|-----------|
| POST | `/api/auth/login` | — | ✓ |
| POST | `/api/auth/logout` | — | ✓ |
| GET | `/api/auth/session` | — | — |
| GET | `/api/status` | — | — |
| GET | `/api/apps` | 登录 | — |
| POST | `/api/apps` | admin | ✓ |
| DELETE | `/api/apps/{id}` | admin | ✓ |
| GET | `/api/users` | admin | — |
| POST | `/api/users` | admin | ✓ |
| PUT | `/api/users/{id}/permissions` | admin | ✓ |
| GET | `/api/audit` | admin | — |
| GET | `/proxy/{app_id}/*` | 登录+权限 | — |

## 目录结构

```
web-ssl-vpn/
├── build.zig                 # Zig 构建编排
├── Cargo.toml                # Rust workspace (server/web/ebpf)
├── flake.nix                 # Nix 开发环境
├── goal.md                   # 需求文档
├── test.zig                  # Zig test stub
│
├── certs/                    # TLS 证书 (自动生成)
│   ├── ca.crt / ca.key
│   ├── server.crt / server.key
│   └── ext.cnf
│
├── server/                   # ── Pingora 后端 ──
│   ├── Cargo.toml
│   ├── build.rs              #   编译前构建 eBPF
│   ├── html/
│   │   ├── login.html        #   登录页 (备用)
│   │   └── dashboard.html    #   仪表盘模板 (备用)
│   └── src/
│       ├── main.rs           #   入口 / ProxyHttp / API / 反向代理 / 集成测试
│       ├── db.rs             #   Sea-ORM 实体 + CRUD + 测试
│       ├── config.rs         #   ServerConfig + env 注入
│       ├── ratelimit.rs      #   登录频率限制器 + 测试
│       ├── status.rs         #   StatusCollector + 会话详情
│       └── ebpf.rs           #   TC 监控加载 + 回退 + 测试
│
├── ebpf/                     # ── eBPF 程序 ──
│   ├── Cargo.toml            #   [lib] 目标, bpf-linker 编译
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
    ├── 01-ebpf.png … 06-overview.png
    └── slides/               # 代码截图由 [charmbracelet/freeze](https://github.com/charmbracelet/freeze) 生成
```

## 安全特性

- **密码**: argon2 每用户随机 128-bit salt，不存明文
- **会话**: UUID v4 + HttpOnly + SameSite=Strict + 8h 过期 + 定期清理
- **CSRF**: 状态变更请求 (POST/PUT/DELETE) 校验 Origin/Referer 头
- **频率限制**: 登录端点 10 次/15 分钟，超出返回 429
- **响应头**: CSP / X-Frame-Options: DENY / X-Content-Type-Options: nosniff / Referrer-Policy: no-referrer
- **输入校验**: username (字母数字) / password (8-128 字符) / URL (host:port 格式) 均经验证

## 测试

42 个测试全覆盖，`cargo test` 全部通过：

| 模块 | 测试数 | 覆盖范围 |
|------|--------|---------|
| db.rs | 12 | CRUD, 权限, 种子数据, session 过期清理 |
| main.rs | 11 | 输入校验, 认证流程, 权限访问, 审计日志 |
| ebpf.rs | 7 | 回退, 路径搜索, 缺失文件, 统计结构体 |
| status.rs | 5 | 会话追踪, 请求计数, uptime |
| ratelimit.rs | 4 | 频率限制, 独立 IP, 窗口过期 |
| config.rs | 3 | 默认值, env 覆盖, TLS 检测 |

## 致谢

代码截图由 [charmbracelet/freeze](https://github.com/charmbracelet/freeze) 生成。字体: Maple Mono NF CN.

## 许可证

MIT License
