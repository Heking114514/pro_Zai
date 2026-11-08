# Z.ai 注册与凭证提取协议技术报告

> 文档日期：2026-11-04
> 分析对象：`zai-batch-register` 本地工作台及两份浏览器网络抓包
> 文档类型：协议分析、状态机、集成与运维说明
> 安全边界：仅用于已授权的自有平台、测试环境或人工验证流程；不包含验证码自动破解、指纹伪造或绕过风控的实现。

## 1. 执行摘要

本项目是一个基于 FastAPI、Playwright 和 WebSocket 的本地注册工作台。浏览器负责页面交互和验证码展示，人工在 `/verify` 完成滑块，后端负责任务调度、邮箱池、代理池、邮箱验证和凭证提取。

两份抓包确认了以下主链路：

1. 打开 `https://chat.z.ai/auth`。
2. 页面可能显示英文登录方式选择页，也可能直接显示中文邮箱登录/注册表单。
3. 提交注册时调用 `POST /api/v1/auths/signup`，成功后进入邮箱验证页。
4. 邮箱中的验证链接打开激活页面，提交 `POST /api/v1/auths/finish_signup`。
5. 登录后进入 OAuth 授权页，授权结果通过回调返回 ZCode。
6. 邮箱侧使用每邮箱独立 JWT 调用邮件 API 获取原始邮件。

当前实现已经覆盖：

- 中英文认证页兼容
- 单密码框/双密码框激活表单兼容
- API 邮箱池及自动英文姓名生成
- HTTP/SOCKS5H 代理识别与限并发测试
- 人工滑块投屏 `/verify`

当前实现明确不包含：

- 纯协议注册
- 自动破解阿里云滑块
- 浏览器指纹伪造
- 绕过平台风控或设备限制

## 2. 适用范围与安全边界

### 2.1 适用场景

- 自有平台的注册流程联调
- 已获授权的测试账号创建
- 人工滑块工作台的维护
- 邮件池、代理池和任务调度的运维
- 对页面结构变化进行兼容性修复

### 2.2 非目标

本文不提供以下内容：

- `captcha_verify_param` 的生成算法
- 设备指纹、设备 MID 或反检测参数的伪造方法
- 绕过平台注册限制、频率限制或代理限制的步骤
- 自动完成滑块的代码或模型
- 真实密码、JWT、Cookie、邮箱验证 token 的样例值

如果目标是第三方平台，必须先确认其服务条款和书面授权。开源许可证不授予目标服务的自动化注册许可。

## 3. Evidence → Finding → Path

### 3.1 Evidence

| ID | 观察 | 来源 | 时间 | 哈希/引用 |
|---|---|---|---|---|
| E-001 | Z.ai 抓包共 112 条记录；`POST /api/v1/auths/signup` 返回 200，响应 `success=true` | `D:\Desktop\zai-2026-11-03.json`，sequence 60 | 2026-11-03 | SHA-256 `931FAA6ED7559D14E261210B855DD1634AAEA0128B1A767C9C53CB558EFC87B3` |
| E-002 | 邮件抓包共 453 条记录；包含 `finish_signup`、OAuth 授权和 CLI 回调 | `D:\Desktop\mail-2026-11-03.json`，sequence 20/395/433/437 | 2026-11-03 | SHA-256 `FFBCA61CC8862B28B42E91DAEBF688B05511C113560E3F2652A25DEBED49B0ED` |
| E-003 | 英文登录方式选择页存在 `Continue with Email`、`Continue with Google`、`Continue with Github` | `artifacts/chat-auth-proxy.png` | 2026-11-03 | SHA-256 `F36CAC35E2DE3558CFF4972A629E3B88220D38075058C35C55495CA5DA4BE5BC` |
| E-004 | 中文注册页存在名称、电子邮箱、密码输入框和“创建账号”按钮 | `artifacts/chat-auth-register.png` | 2026-11-03 | SHA-256 `57EC4A78E1DA5A13539799DE11985FC905E8A00E8EADBD05FC5118884C4A2DC2` |
| E-005 | 真实页面验证确认英文选择页、中文登录页、中文注册页均可进入 | Playwright DOM 检查，命令见附录 A | 2026-11-03 | 可复现命令 |
| E-006 | 代理测试成功返回公网出口 IP，项目批量测试限制为 6 路并发 | `/api/config/test-proxies`，本地服务 | 2026-11-03 | 运行日志 |
| E-007 | 邮件 API 使用 `Authorization: Bearer <JWT>`，返回 `count` 和 `results[].raw` | 邮件 API 实测及 `/opt/yangmao/src/yangmao/mail_api.py` | 2026-11-03 | 服务响应摘要 |

### 3.2 Findings

| ID | 结论 | 严重性 | 证据 | 状态 |
|---|---|---|---|---|
| F-001 | 认证页至少有英文选择页和中文直登/注册页两种布局，旧代码只适配英文布局 | high | E-003, E-004, E-005 | 已修复 |
| F-002 | 注册提交是 JSON API；核心字段为姓名、邮箱、密码、头像、验证码校验参数和 SSO 跳转参数 | high | E-001 | 已验证 |
| F-003 | 邮箱激活使用会话绑定的 `finish_signup`，需要用户名、邮箱、验证 token、密码和头像 | high | E-002 | 已验证 |
| F-004 | 登录后通过 `/auth/oauth/authorize`、`/api/oauth/authorize` 和 ZCode 回调完成授权 | high | E-002 | 已验证 |
| F-005 | 邮件 API 的凭据是每邮箱独立 JWT，不是共享 IMAP 密码 | medium | E-007 | 已验证 |
| F-006 | Chromium 不支持带用户名密码的 SOCKS5；自动模式必须优先 HTTP，或使用无认证 SOCKS5 | medium | E-006 | 已修复 |
| F-007 | 人工滑块可以投屏，但自动破解和指纹伪造不属于本项目目标 | high | 设计边界 | 明确排除 |

### 3.3 Path

```text
P-001 主注册路径
  A. 打开 /auth
     -> E-003/E-004 -> F-001
  B. 进入 Email 登录/注册表单
     -> E-005 -> F-001
  C. 填写姓名、邮箱、密码并提交
     -> E-001 -> F-002
  D. 页面进入验证码阶段，由人工完成滑块
     -> 设计边界 -> F-007
  E. 邮箱收到验证链接，打开 /auth/verify 或 /auth/verify_email
     -> E-002 -> F-003
  F. 提交 finish_signup，建立登录会话
     -> E-002 -> F-003
  G. 进入 OAuth 授权并回调 ZCode
     -> E-002 -> F-004
```

## 4. 系统架构

```mermaid
flowchart LR
    UI[WebUI /verify] -->|WebSocket| API[FastAPI app.py]
    API --> Q[任务队列]
    Q --> W[RegisterWorker]
    W --> B[Playwright Chromium]
    B --> P[代理池]
    B --> A[Z.ai 认证页]
    A --> C[人工滑块]
    A --> S[Signup API]
    S --> M[邮箱验证]
    M --> MA[Mail API 邮箱池]
    M --> F[finish_signup]
    F --> O[OAuth 授权]
    O --> T[JWT / Device MID]
```

### 4.1 组件职责

| 组件 | 文件 | 职责 |
|---|---|---|
| FastAPI 应用 | `app.py` | 路由、任务、配置、WebSocket、导出 |
| 注册工作器 | `register_worker.py` | 浏览器流程、页面兼容、滑块投屏 |
| 邮箱服务 | `email_service.py` | IMAP 与 API 邮箱池、邮件链接提取 |
| 代理管理 | `proxy_manager.py` | 协议识别、轮询、健康检查、熔断 |
| OAuth 工具 | `zcode_token.py` | CLI OAuth 与设备 MID 计算 |
| 配置存储 | `config_manager.py` | `config.json`、`tasks.json` |
| 前端 | `templates/`、`static/` | 任务、邮箱、代理、日志、滑块台 |

## 5. 认证页面状态机

```mermaid
stateDiagram-v2
    [*] --> AuthEntry
    AuthEntry --> ProviderChooser: 英文布局
    AuthEntry --> DirectLogin: 中文布局
    ProviderChooser --> DirectLogin: Continue with Email
    DirectLogin --> RegisterForm: Sign up / 注册
    AuthEntry --> RegisterForm: 已处于注册状态
    RegisterForm --> Captcha: 创建账号
    Captcha --> VerifyPage: 验证通过
    VerifyPage --> FinishSignup: 设置密码/提交
    FinishSignup --> OAuth: 登录会话建立
    OAuth --> TokenReady: 授权回调
```

### 5.1 页面变体

| 变体 | 初始可见元素 | 处理方式 |
|---|---|---|
| 英文选择页 | `Continue with Email`、Google、Github | 点击 Email，再点击 Sign up |
| 中文直登页 | 电子邮箱、密码、登录、注册 | 点击注册 |
| 中文注册页 | 名称、电子邮箱、密码、创建账号 | 直接填写 |
| 英文注册页 | Name、Email、Password、Create Account | 直接填写 |
| 已登录/已注册状态 | 可能直接跳主站 | 读取会话并继续 OAuth |

### 5.2 选择器策略

优先级从高到低：

1. 可见输入框类型：`input[type=email]`、`input[type=password]`、`input[type=text]`。
2. 可见按钮文本：`Continue with Email`、`Sign up`、`注册`、`创建账号`、`Create Account`。
3. 等待页面进入可交互状态后再判断布局，不使用固定 1.5 秒直接判断。
4. 所有选择器只操作当前可见元素，避免匹配隐藏的同名按钮。

## 6. 注册协议

### 6.1 页面入口

```text
GET https://chat.z.ai/auth
```

页面可能先显示登录方式选择页，也可能直接显示中文登录表单。应用不能假设只有一个固定布局。

### 6.2 注册提交

抓包确认的成功请求：

```http
POST /api/v1/auths/signup
Content-Type: application/json
```

请求字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 显示名称 |
| `email` | string | 注册邮箱 |
| `password` | string | 账号密码 |
| `profile_image_url` | string | 头像 data URI 或图片地址 |
| `captcha_verify_param` | string | 验证码组件返回的不透明校验参数 |
| `sso_redirect` | string/null | SSO 跳转参数 |

成功响应摘要：

```json
{
  "success": true
}
```

注意：

- 请求必须使用注册页当前的浏览器会话。
- `captcha_verify_param` 由页面验证码组件产生，本文不描述其生成算法。
- 不能把该请求简化成无会话的独立 HTTP 调用；会话、Cookie 和验证码状态需要保持一致。
- 文档中的字段名来自抓包，真实值不记录。

### 6.3 验证码交互边界

当前项目采用人工验证：

1. 浏览器打开验证码组件。
2. Playwright 通过 CDP 将页面画面推送到 `/verify`。
3. 人工在浏览器画布上拖动滑块。
4. 页面自身完成验证并把校验参数带回注册请求。

项目不包含：

- 滑块位置自动识别
- 自动拖动轨迹生成
- 验证码参数伪造
- 浏览器指纹伪造
- 绕过验证码的替代接口

## 7. 邮箱验证与激活协议

### 7.1 邮箱来源

当前项目支持两类邮箱：

| 模式 | 配置 | 适用情况 |
|---|---|---|
| IMAP | 主机、端口、账号、授权码 | 单账号或共享收件箱 |
| API 邮箱池 | 每行 `邮箱----JWT` 或 `邮箱----API地址----JWT` | 每邮箱独立 token 的 catch-all 服务 |

API 邮箱请求：

```http
GET https://mail.example.com/api/mails?limit=20&offset=0
Authorization: Bearer <mailbox-jwt>
```

响应结构：

```json
{
  "count": 1,
  "results": [
    {
      "raw": "<完整 MIME 邮件原文>"
    }
  ]
}
```

实现要点：

- JWT 必须按目标邮箱精确匹配。
- 邮件正文优先按 MIME 头解码。
- 只有存在 quoted-printable 标记时才做 quoted-printable 回退，避免把 URL 中的 `=abc` 误当成编码。
- 验证链接只从匹配目标邮箱的邮件中提取。

### 7.2 激活页面

邮件链接可能包含：

```text
/auth/verify?email=<email>&username=<username>
/auth/verify_email?token=<token>
```

页面可能要求：

- 一个密码框
- 两个密码框（密码和确认密码）
- 中英文提交按钮

当前实现兼容：

```text
Complete Registration
完成注册
创建账号
完成
确认
```

### 7.3 finish_signup

抓包确认的激活请求：

```http
POST /api/v1/auths/finish_signup
Content-Type: application/json
```

请求字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `username` | string | 用户名 |
| `email` | string | 邮箱 |
| `token` | string | 验证链接中的一次性 token |
| `password` | string | 设置或确认的密码 |
| `profile_image_url` | string | 头像 data URI 或图片地址 |

成功响应包含用户对象和登录 token。响应中的真实 token 不写入本文档。

关键约束：

- `finish_signup` 与验证链接、浏览器会话绑定。
- 不能在新会话中用同一 token 重新提交。
- 激活后应读取当前页面的 `localStorage` token，并继续同一会话的 OAuth 流程。

## 8. OAuth 与凭证提取

### 8.1 观察到的请求链

```text
GET  /auth/oauth/authorize?client_id=...&redirect_uri=...&response_type=...&state=...
GET  /api/oauth/authorize/info?client_id=...&redirect_uri=...
POST /api/oauth/authorize
GET  https://zcode.z.ai/api/v1/oauth/cli/callback/zai?code=...&state=...
```

`POST /api/oauth/authorize` 的响应会返回 `redirect_url`，随后浏览器访问 ZCode 回调。

### 8.2 当前实现

`zcode_token.py` 使用：

1. CLI OAuth 初始化。
2. 在已登录浏览器中打开授权页。
3. 处理授权复选框和继续按钮。
4. 轮询 CLI token。
5. 解析 `sub` 并计算稳定的 `device_mid`。

### 8.3 凭证字段

| 字段 | 说明 |
|---|---|
| `web_jwt` | 浏览器会话 token |
| `cli_jwt` | Coding Plan/CLI 专用 token |
| `access_token` | 授权返回的访问 token |
| `sub` | 用户标识 |
| `device_mid` | 由用户标识派生的稳定设备标识 |

真实值必须通过本地配置或运行时内存传递，不能写入日志、截图或公开文档。

## 9. 数据模型

### 9.1 任务

```json
{
  "id": "task_<random>",
  "name": "<display-name>",
  "email": "<mailbox>",
  "password": "<redacted>",
  "status": "PENDING",
  "message": "等待执行",
  "created_at": "YYYY-MM-DD HH:MM:SS"
}
```

### 9.2 配置

```json
{
  "mail_provider": "api",
  "mail_api_url": "https://mail.example.com/api/mails?limit=20&offset=0",
  "mail_api_pool": "<redacted>",
  "proxy_enabled": true,
  "proxy_strategy": "round_robin",
  "proxy_pool": "<redacted>",
  "headless": true,
  "concurrency": 1
}
```

### 9.3 邮箱池

每行一个条目：

```text
<mailbox>----<jwt>
<mailbox>----<api-url>----<jwt>
```

保存后 API 返回脱敏值。真实 JWT 不应出现在前端日志、CSV 导出或聊天记录中。

## 10. 代理策略

### 10.1 支持格式

```text
host:port:user:password
user:password@host:port
http://host:port
http://user:password@host:port
socks5://host:port
socks5h://host:port
```

### 10.2 自动识别规则

1. 显式写了 `http://` 或 `socks5://` 时尊重显式协议。
2. 未写协议时先探测 SOCKS5 握手。
3. 带用户名密码且代理只支持认证 SOCKS5 时，自动模式选择 HTTP，因为 Chromium 不支持带认证 SOCKS5。
4. 无认证 SOCKS5 可以使用 `socks5h`。
5. 不兼容 Playwright 的代理不会进入浏览器轮换池。

### 10.3 健康检查

- 批量测试最多 6 路并发。
- 单个节点失败后重试 2 次。
- 连续失败 3 次才熔断。
- 成功一次即清除失败计数。
- 代理池启用但没有可用节点时阻止直连，避免泄漏本机 IP。

## 11. 当前实现映射

| 能力 | 文件 | 状态 |
|---|---|---|
| 中英文认证页 | `register_worker.py` | 已完成 |
| 单/双密码激活表单 | `register_worker.py` | 已完成 |
| API 邮箱池 | `email_service.py` | 已完成 |
| 自动英文姓名和随机密码 | `app.py` | 已完成 |
| 邮箱池任务自动生成 | `app.py`、`static/app.js` | 已完成 |
| 代理协议识别 | `proxy_manager.py` | 已完成 |
| 代理限并发与失败阈值 | `proxy_manager.py` | 已完成 |
| 人工滑块 `/verify` | `app.py`、`templates/verify.html` | 已完成 |
| 纯协议注册 | 未实现 | 非目标 |
| 自动验证码破解 | 未实现 | 非目标 |
| 指纹伪造 | 未实现 | 非目标 |

## 12. 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 找不到 Email 按钮 | 页面处于中文直登布局，或 JavaScript 未渲染完成 | 等待邮箱输入框/Email 按钮出现，再判断布局 |
| 创建账号按钮超时 | 页面仍是登录布局，或按钮文案变化 | 检查可见按钮文本，兼容注册/Create Account |
| 激活页不跳转 | 页面只有一个密码框，旧代码只处理两个 | 填写所有可见密码框并匹配中英文提交按钮 |
| 验证链接无效 | token 过期、已使用或会话不匹配 | 重新发送验证邮件，使用同一浏览器会话 |
| 邮件 API 返回 401 | JWT 与邮箱不匹配或已失效 | 重新导入该邮箱凭据 |
| 代理 SSL EOF | 代理协议错误、节点不稳定或证书链异常 | 自动重试/切换节点，检查 HTTP/SOCKS5 兼容性 |
| 浏览器提示 SOCKS5 authentication unsupported | Chromium 不支持带认证 SOCKS5 | 改用 HTTP 代理 |
| 任务一直等待验证码 | 代理出口被限制或验证码组件未加载 | 更换未使用出口，检查 CDN/验证码资源 |

## 13. 安全与隐私

1. `config.json`、`tasks.json` 包含邮箱密码、代理密码和 token，必须限制文件权限。
2. `/verify` 和主控制台只应监听 `127.0.0.1`，不要暴露到公网。
3. 不要把真实 JWT 写入 README、日志、截图或提交记录。
4. 代理账号和邮箱 JWT 应按最小权限和最短有效期管理。
5. 导出文件 `tokens.txt`、CSV 和账号 JSON 应加密存储或及时删除。
6. 发生 token 泄漏时，先撤销 token，再轮换邮箱和代理凭据。
7. 任何自动化流程都应保留审计记录，并遵守目标平台的服务条款。

## 14. 自有平台的合规实现建议

如果目标是你真正自有的平台，建议把“纯协议”设计为官方 API，而不是模拟浏览器：

```mermaid
sequenceDiagram
    participant Client as Web/App
    participant Backend as Owned Backend
    participant Captcha as Official Captcha
    participant Mail as Owned Mail
    Client->>Backend: POST /signup/session
    Backend-->>Client: challenge_id + image
    Client->>Client: Human solves slider
    Client->>Backend: POST /signup/verify
    Backend->>Captcha: Verify challenge
    Captcha-->>Backend: valid / invalid
    Backend->>Mail: Send verification
    Client->>Backend: POST /signup/finish
    Backend-->>Client: account + official token
```

推荐原则：

- 只暴露验证码 challenge，不暴露内部注册协议。
- 由后端校验 challenge，不信任客户端自报“已通过”。
- 邮箱验证 token 一次性、短有效期、与注册会话绑定。
- 设备标识由官方服务端签发，不做客户端指纹伪造。
- 对注册、验证码、邮件和登录接口做速率限制与审计。

## 15. 验收清单

- [x] 能识别英文登录方式选择页。
- [x] 能识别中文登录页并切换注册。
- [x] 能填写名称、邮箱、密码。
- [x] 能处理一个或两个密码框的激活页。
- [x] 能通过邮件 API 读取并匹配目标邮箱。
- [x] 能限制代理测试并发并处理重试/熔断。
- [x] 人工滑块仍由 `/verify` 完成。
- [x] 真实 token、密码、验证码参数未写入文档。
- [ ] 纯协议注册未实现，且不在当前安全边界内。
- [ ] 自动验证码破解未实现，且不在当前安全边界内。

## 附录 A：可复现检查命令

以下命令仅用于检查页面结构和表单可见性，不提交注册：

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = (Join-Path (Get-Location) '.playwright-browsers')
$env:TMP = (Join-Path (Get-Location) '.tmp')
$env:TEMP = $env:TMP
$env:TMPDIR = $env:TMP
@'
import asyncio
from config_manager import load_config
from proxy_manager import get_next_task_proxy
from register_worker import RegisterWorker
from playwright.async_api import async_playwright

async def main():
    cfg = load_config()
    proxy = get_next_task_proxy(cfg)
    worker = RegisterWorker(cfg, None)
    async with async_playwright() as p:
        opts = {"headless": True}
        if proxy:
            opts["proxy"] = proxy["playwright_cfg"]
        browser = await p.chromium.launch(**opts)
        page = await browser.new_page(viewport={"width": 1280, "height": 800})
        await page.goto("https://chat.z.ai/auth", wait_until="domcontentloaded", timeout=45000)
        name, email, password, button = await worker._prepare_email_signup(page, "diagnostic")
        print(await name.get_attribute("placeholder"))
        print(await email.get_attribute("placeholder"))
        print(await password.get_attribute("placeholder"))
        print((await button.inner_text()).strip())
        await browser.close()

asyncio.run(main())
'@ | .\.venv\Scripts\python.exe -
```

## 附录 B：抓包文件清单

| 文件 | 记录数 | SHA-256 |
|---|---:|---|
| `D:\Desktop\zai-2026-11-03.json` | 112 | `931FAA6ED7559D14E261210B855DD1634AAEA0128B1A767C9C53CB558EFC87B3` |
| `D:\Desktop\mail-2026-11-03.json` | 453 | `FFBCA61CC8862B28B42E91DAEBF688B05511C113560E3F2652A25DEBED49B0ED` |

## 附录 C：结论

该项目的可维护部分已经形成完整的“浏览器会话 + 人工验证码 + 邮箱池 + 代理池”链路。抓包足以支持页面兼容、邮件激活和 OAuth 诊断，但不足以支持安全、合规的纯协议注册；纯协议所需的设备、会话和验证码证据不应通过模拟或伪造绕过。

后续应优先验证：

1. 中文/英文注册页的结构变化。
2. 激活页密码框数量和提交按钮文案。
3. 邮箱池 JWT 与目标邮箱的精确匹配。
4. 代理协议与 Playwright 的兼容性。
5. 人工滑块是否仍能稳定投屏到 `/verify`。
