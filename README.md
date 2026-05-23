# Web SSL VPN

基于Web门户的轻量级SSL VPN访问网关。利用HTTPS协议提供安全的Web登录门户，通过反向代理转发用户请求至内网Web服务器，无需客户端插件。

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Pingora 0.8 + Tokio |
| 前端 | Iced 0.14 WASM (sniffnet风格主题) |
| 样式 | Palette 配色系统 + ContainerType/ButtonType/TextType Catalog |
| 数据库 | Sea-ORM 2.0 + SQLite |
| 环境 | Nix Flakes + Zig build system |

## 功能特性

- **HTTPS安全门户**: TLS 1.2/1.3 终止，HTTP/2 支持
- **身份认证**: argon2 密码哈希，UUID 会话令牌，8小时过期
- **RBAC访问控制**: admin/user 角色，应用级权限映射
- **反向代理**: 动态路由 `/proxy/{app_id}/*`，浏览器地址栏始终显示网关地址
- **内嵌管理面板**: 应用管理、用户管理、权限配置、审计日志查看
- **安全审计日志**: 记录登录、代理访问、权限拒绝等操作
- **系统状态API**: `/api/status` 运行统计
- **实时仪表盘**: Iced WASM 五页仪表盘（Overview/Network/Sessions/Apps/Audit）
- **流量监控**: 60s 历史图表、上传/下载配额管理（可配置1G/5G/10G/无限）
- **会话管理**: Active/Closed 子标签页、连接详情表格
- **三套主题**: Nord Dark / Tokyo Dark / Catppuccin Dark

## 一键运行

```bash
nix develop --ignore-environment
zig build run
```

自动完成：证书生成 → CA信任文件 → Trunk编译WASM → Cargo编译启动。

默认账号: `admin` / `admin123`，访问 https://localhost:8443

**注意**: `--ignore-environment` 会清除宿主代理变量，如果依赖代理上网，需手动传递：

```bash
nix develop --ignore-environment --command bash -c '
  export http_proxy=http://127.0.0.1:7897
  export https_proxy=http://127.0.0.1:7897
  zig build run'
```

## 构建步骤

| 命令 | 说明 |
|------|------|
| `zig build check` | cargo check 检查 server + web 编译 |
| `zig build test` | cargo test 运行所有测试 |
| `zig build trunk` | trunk build iced WASM 前端 (debug) |
| `zig build wasm` | certs + trust + trunk 全套前端 |
| `zig build run` | 全量构建 + 启动服务 (debug) |
| `zig build release` | 发布构建: trunk --release + cargo --release |
| `zig build certs` | 生成 CA + 服务器证书 |
| `zig build trust` | 生成 ca-bundle.crt 信任包 |
| `zig build install-ca` | 安装 CA 到系统信任 (sudo) |

## 构建步骤

### 环境

```bash
nix develop --ignore-environment
```

### 服务器 (手动)

```bash
cargo run -p server
```

默认账号: `admin` / `admin123`，访问 https://localhost:8443

### 前端 WASM (手动)

```bash
cd web && trunk build
# 产物在 web/dist/
```

## API 端点

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录，返回 session cookie |
| POST | `/api/auth/logout` | 登出 |
| GET | `/api/auth/session` | 检查当前会话 |

### 应用管理 (admin)

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/apps` | 获取应用列表 |
| POST | `/api/apps` | 注册内网应用 `{name, description, url}` |
| DELETE | `/api/apps/{id}` | 删除应用 |

### 用户管理 (admin)

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/users` | 获取用户列表 |
| POST | `/api/users` | 创建用户 `{username, password, role}` |
| PUT | `/api/users/{id}/permissions` | 更新用户应用权限 `{app_ids: []}` |

### 审计 & 状态

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/audit` | 查看审计日志 (admin) |
| GET | `/api/status` | 系统运行状态 |

### 代理

| 路径 | 说明 |
|------|------|
| `/proxy/{app_id}/*` | 代理转发到注册的内网应用 |

## 项目结构

```
web-ssl-vpn/
├── server/
│   ├── src/
│   │   ├── main.rs          # 服务器入口，API路由，反向代理
│   │   ├── db.rs            # 数据库实体与CRUD操作
│   │   └── status.rs        # 系统状态收集
│   └── html/
│       ├── login.html        # 登录页面
│       └── dashboard.html    # 仪表盘模板
├── web/
│   ├── src/main.rs           # Iced WASM 前端
│   ├── index.html
│   └── dist/                 # 编译产出
├── certs/
│   ├── ca.crt                # CA 证书
│   ├── ca.key                # CA 私钥
│   ├── server.crt            # 服务器证书 (CA 签名)
│   ├── server.key            # 服务器私钥
│   └── ca-bundle.crt         # 合并信任包 (系统 + CA)
├── Cargo.toml                # Rust工作空间配置
├── flake.nix                 # Nix开发环境
├── build.zig                 # Zig构建脚本
└── README.md
```

## 使用流程

### 注册内网应用

1. 使用 admin 登录 https://localhost:8443
2. Admin Panel → Add Application
3. 填写名称、描述、URL (如 `127.0.0.1:3000`)
4. User Management → Permissions 为用户分配应用权限

### 启动内网测试服务

```bash
python -m http.server 3000 --bind 127.0.0.1
```

### 通过网关访问

```
https://localhost:8443/proxy/1/
```

## 许可证

MIT License
