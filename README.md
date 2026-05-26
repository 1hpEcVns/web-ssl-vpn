# Web SSL VPN

基于 Web 门户的轻量级 SSL VPN 网关。HTTPS + 反向代理 + RBAC + 2FA + eBPF 流量监控。

> 需求文档: [goal.md](goal.md) | UI 截图 [samples/](samples/) | 代码讲解 [samples/slides/](samples/slides/)

## 技术栈

| 层级 | 选型 |
|------|------|
| 代理引擎 | Pingora 0.8 (Cloudflare), TLS 1.3 + HTTP/2 |
| 前端 | Iced 0.14 → WebAssembly, WebGL, Trunk bundler |
| 样式 | Palette 配色 + ContainerType/ButtonType/TextType Catalog |
| 数据库 | Sea-ORM 2.0 + SQLite |
| 认证 | argon2 (每用户随机盐), UUID v4 Session, HttpOnly Cookie, TOTP 2FA |
| 安全 | CSRF Origin/Referer 检查, 登录频率限制, CSP/安全响应头 |
| eBPF | aya 0.13, TC classifier, bpf-linker 编译 |
| 运行时 | Tokio async, Arc\<Mutex\<AppState\>\>, 后台会话清理 |
| 构建 | Zig build system + Nix Flakes |
| **桌面应用** | Iced 0.14 原生 wgpu/Vulkan/Metal, Rustls TLS, 60 FPS |

## 架构

```
┌─ 桌面应用 ───────────────────────────────────────────┐
│ iced wgpu → HTTPS ──┐                                 │
└─────────────────────┘                                 │
                         ┌──── 浏览器 WASM ────┐        │
                         │ WebGL → HTTPS ──────┤        │
                         └─────────────────────┘        │
                                      │                  │
浏览器/桌面 ──TLS──▶ Pingora ──proxy──▶ 内网应用         │
                 │    │
              SQLite  eBPF(TC)
              (会话)   (流量统计)
              (2FA)    │
                  Iced WASM 仪表盘
```

后台任务每 5 分钟自动清理过期 session。WASM 仪表盘每 5 秒轮询 `/api/status` 获取实时数据。

## 功能矩阵

| 功能 | 说明 |
|------|------|
| HTTPS 门户 | TLS 1.2/1.3 终止, 自签 CA 证书 |
| 身份认证 | argon2 随机盐哈希, UUID Session, HttpOnly Strict Cookie |
| **TOTP 2FA** | Google Authenticator 兼容, QR Code 扫码绑定, 两步登录 |
| **修改密码** | 验证旧密码后更新, 审计日志记录 |
| RBAC | admin/user 角色, 应用级权限 |
| 反向代理 | `/proxy/{app_id}/*` 动态路由, 响应体/头自动重写, 隐藏内部 IP 和 hostname |
| **地址隐藏** | 代理响应中 `127.0.0.1:3001` → `/proxy/1`, 浏览器只显示网关地址 |
| 审计日志 | 登录/2FA/代理/密码变更/拒绝记录, 含用户名 |
| 演示模式 | `VPN_DEMO=true` 跳过认证 |
| CSRF 保护 | POST/PUT/DELETE 校验 Origin/Referer |
| 频率限制 | 登录 10 次/15 分钟, IP 级 |
| 安全响应头 | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 输入校验 | username/password/URL/app name 格式检查 |
| 会话详情 | `/api/status` 返回 session_details[] (user/IP/连接时间) |
| 定期清理 | 后台任务每 5 分钟清理过期 session |
| **7 页仪表盘** | Overview/Network/Sessions/Apps/Audit/eBPF/Settings |
| 实时流量图 | 60s 历史差值, 上传/下载配额 |
| **GUI 设置页** | 修改密码、2FA 绑定/禁用、QR Code 扫码 |
| **前后端联通** | WASM 轮询 `/api/status`/`/api/apps`/`/api/audit`, 真实数据 |
| eBPF 监控 | TC ingress/egress, 字节/连接计数, BPF Maps 展示 |

## 启动

```bash
nix develop --ignore-environment
zig build ebpf-run
# → https://localhost:8443   admin / admin123
```

```bash
# 演示模式
VPN_DEMO=true zig build ebpf-run

# eBPF 模式 (需 root, 附加 TC BPF 到指定网卡)
VPN_EBPF_IFACE=eth0 zig build ebpf-run
```

### 启动模拟内网 (用于代理演示)

```bash
zig build ebpf-build   # 预构建 eBPF 字节码 (可选)
./mock_http &          # 启动 4 个模拟 HTTP 服务器 (wiki=3001, hr=5001, mail=8081, files=9001)
./demo_acl.sh          # 运行访问控制演示脚本
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
| `zig build desktop` | 原生桌面应用 |
| `zig build desktop-run` | 构建 + 启动桌面应用 |
| `zig build install-ca` | 安装 CA 证书到系统信任库 (sudo) |

### 原生桌面应用

```bash
# 一键构建并运行（自动连接 localhost:8443）
zig build desktop-run

# 或指定远程服务器
VPN_SERVER=https://vpn.example.com:8443 zig build desktop-run
```

桌面应用与 WASM 前端共享全部 UI（7 页仪表盘 + Settings），通过 `reqwest` + RusTLS 直连 VPN 后端，自动管理 session cookie，支持 60 FPS 原生 wgpu 渲染。

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

| 方法 | 路径 | 权限 | CSRF | 说明 |
|------|------|------|------|------|
| POST | `/api/auth/login` | — | ✓ | 登录 (如有 2FA 返回 `two_fa_required:true`) |
| POST | `/api/auth/login/2fa` | — | ✓ | 提交 TOTP 码完成 2FA 登录 |
| POST | `/api/auth/logout` | — | ✓ | 登出 |
| GET | `/api/auth/session` | — | — | 会话检查 |
| PUT | `/api/auth/password` | 登录 | ✓ | 修改密码 (`old_password` + `new_password`) |
| POST | `/api/auth/2fa/setup` | 登录 | ✓ | 生成 TOTP secret + QR URL |
| POST | `/api/auth/2fa/verify` | 登录 | ✓ | 验证 TOTP 码以启用 2FA |
| POST | `/api/auth/2fa/disable` | 登录 | ✓ | 验证后关闭 2FA |
| GET | `/api/status` | — | — | 实时统计 (uptime, bytes, sessions) |
| GET | `/api/apps` | 登录 | — | 应用列表 |
| POST | `/api/apps` | admin | ✓ | 创建应用 |
| DELETE | `/api/apps/{id}` | admin | ✓ | 删除应用 |
| GET | `/api/users` | admin | — | 用户列表 (含 totp_enabled 状态) |
| POST | `/api/users` | admin | ✓ | 创建用户 |
| PUT | `/api/users/{id}/permissions` | admin | ✓ | 设置用户应用权限 |
| GET | `/api/audit` | admin | — | 审计日志 (含 username) |
| GET | `/proxy/{app_id}/*` | 登录+权限 | — | 反向代理至内网应用 |

## 2FA 使用流程

```bash
# 1. 登录
curl -sk -c /tmp/jar -X POST $BASE/api/auth/login \
  -d '{"username":"admin","password":"admin123"}'

# 2. 设置 2FA (返回 secret + QR URL + QR PNG 供 Google Authenticator 扫码)
curl -sk -b /tmp/jar -X POST $BASE/api/auth/2fa/setup -d '{}'
# → {"secret":"BASE32...", "qr_url":"otpauth://totp/...", "qr_png":"data:image/png;base64,..."}

# 3. 用 Google Authenticator 扫码后, 输入验证码启用
curl -sk -b /tmp/jar -X POST $BASE/api/auth/2fa/verify \
  -d '{"code":"123456"}'

# 4. 再次登录 → 两步验证
curl -sk -c /tmp/jar2 -X POST $BASE/api/auth/login \
  -d '{"username":"admin","password":"admin123"}'
# → {"two_fa_required":true, "two_fa_challenge":"uuid..."}

curl -sk -c /tmp/jar2 -X POST $BASE/api/auth/login/2fa \
  -d '{"challenge_token":"uuid...","totp_code":"123456"}'
# → 登录成功
```

## 访问控制演示

```bash
# admin 代理访问全部应用
curl -sk -b /tmp/jar $BASE/proxy/1  # Internal Wiki  ✓
curl -sk -b /tmp/jar $BASE/proxy/2  # Mail Server  ✓

# 创建受限用户 alice, 仅授权 Wiki
curl -sk -b /tmp/jar -X POST $BASE/api/users \
  -d '{"username":"alice","password":"alice123","role":"user"}'
curl -sk -b /tmp/jar -X PUT $BASE/api/users/2/permissions -d '[1]'

# alice 登录 → 只能访问 Wiki, 其他返回 403
curl -sk -c /tmp/alice -X POST $BASE/api/auth/login \
  -d '{"username":"alice","password":"alice123"}'
curl -sk -b /tmp/alice $BASE/proxy/1  # ✓ Internal Wiki
curl -sk -b /tmp/alice $BASE/proxy/2  # ✗ 403 Access Denied
curl -sk -b /tmp/alice $BASE/proxy/4  # ✗ 403 Access Denied
```

## 目录结构

```
web-ssl-vpn/
├── build.zig                 # Zig 构建编排 (含 trunk/cargo/ebpf 步骤)
├── Cargo.toml                # Rust workspace (server/web/ebpf)
├── flake.nix                 # Nix 开发环境
├── goal.md                   # 需求文档
├── test.zig                  # Zig test stub
├── mock_http.rs              # 4 端口模拟 HTTP 服务器 (内网应用演示, 端口冲突自动跳过)
├── demo_acl.sh               # 访问控制演示脚本 (admin/alice)
├── mock_servers.py           # Python 版模拟服务器 (备用)
│
├── desktop/                  # ── Iced 原生桌面应用 ──
│   ├── Cargo.toml            #   wgpu + reqwest + RusTLS
│   └── src/
│       ├── main.rs           #   7 页仪表盘, 60 FPS 原生渲染
│       └── styles -> ../../web/src/styles/  (symlink)
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
│   │   └── login.html        #   登录页 (支持两步 2FA 验证)
│   └── src/
│       ├── main.rs           #   入口 / ProxyHttp / API / 反向代理 / 2FA / 密码变更 / CSRF / 测试
│       ├── db.rs             #   Sea-ORM 实体 + CRUD + TOTP + 密码更新 + 测试
│       ├── config.rs         #   ServerConfig + env 注入
│       ├── ratelimit.rs      #   登录频率限制器 + 测试
│       ├── status.rs         #   StatusCollector + session_details
│       └── ebpf.rs           #   TC 监控加载 + 回退 + 测试
│
├── ebpf/                     # ── eBPF 程序 ──
│   ├── Cargo.toml            #   [lib] 目标, bpf-linker 编译
│   ├── .cargo/config.toml    #   bpf-linker 配置
│   └── src/
│       └── lib.rs            #   tc_ingress / tc_egress classifier
│
├── web/                      # ── Iced WASM 前端 ──
│   ├── Cargo.toml            #   + gloo-net (HTTP), + gloo-console
│   ├── Trunk.toml
│   ├── index.html            #   WASM 入口
│   ├── dist/                 #   trunk build 产物
│   └── src/
│       ├── main.rs           #   7 页仪表盘, API 轮询(5s), 流量差值, 2FA 设置页, 密码修改
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
- **2FA**: TOTP (RFC 6238), Google Authenticator 兼容, 5 分钟 challenge 过期
- **会话**: UUID v4 + HttpOnly + SameSite=Strict + 8h 过期 + 定期清理
- **CSRF**: 状态变更请求 (POST/PUT/DELETE) 校验 Origin/Referer 头，兼容 HTTP/HTTPS
- **频率限制**: 登录端点 10 次/15 分钟，超出返回 429
- **代理隔离**: 响应体/头重写 `localhost:PORT` 和 `127.0.0.1:PORT` → `/proxy/{id}`，浏览器只看到网关地址；移除 Server/X-Powered-By 响应头
- **CSP**: `default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'`
- **响应头**: X-Frame-Options: DENY / X-Content-Type-Options: nosniff / Referrer-Policy: no-referrer
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
