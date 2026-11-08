# pro-zai

`pro-zai` 是一个本地自托管的 Z.ai 注册工作台。它把协议注册流程和人工验证码步骤分开：邮箱、代理、任务队列、注册、收信、激活和 OAuth 换票由服务端处理，只有需要人工拖动滑块时才打开可见 Chromium。

英文说明：[README.en.md](README.en.md)

## 功能

1. 通过 HTTP 协议建立 Z.ai 访客会话。
2. 可选检查邮箱是否已经注册。
3. 仅在验证码阶段打开一个可见 Chromium 窗口。
4. 由操作者亲手完成滑块验证。
5. 捕获验证token和同会话 Cookie。
6. 继续通过协议提交注册、收信、激活和 OAuth 换票。
7. 分别保存 ZCode CLI JWT 和 Web JWT。
8. 可选把完成账号导入兼容的 `zcode2api`。

本项目不识别滑块缺口、不生成拖动轨迹、不调用第三方验证码平台、不通过 CDP 推流，也不会把验证码会话发送到另一台机器。

## 环境要求

- Python 3.10+
- 能显示可见窗口的桌面环境
- 能访问 Z.ai 接口和配置的邮箱服务
- 只有启用账号导入时才需要 `zcode2api`

## 安装

```powershell
git clone git@github.com:Heking114514/pro_Zai.git
cd pro_Zai

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

macOS 或 Linux 激活虚拟环境：

```bash
source .venv/bin/activate
```

## 配置

复制安全模板：

```powershell
Copy-Item config.example.json config.json
```

然后只填写实际使用的服务。

| 字段 | 用途 |
| --- | --- |
| `mail_provider` | `imap`、`api` 或 `cf_dynamic` |
| `mail_api_pool` | API 邮箱池 JWT |
| `imap_*` | IMAP 邮箱参数 |
| `cf_mail_*` | 动态邮箱服务参数 |
| `proxy_*` | 可选代理参数 |
| `registration_mode` | 保持为 `protocol` |
| `captcha_timeout_sec` | 等待人工滑块的超时秒数 |
| `target_count` | 本次队列处理账号数 |
| `zcode2api_enabled` | 是否启用 `zcode2api` 导入 |
| `zcode2api_url` | 兼容 `zcode2api` 的基础地址 |
| `zcode2api_admin_password` | 导入接口使用的管理员密码 |

以下文件不得提交：

- `config.json`
- `tasks.json`
- `tokens.txt`
- `data/`
- `logs/`
- 浏览器配置和账号数据库

Docker 环境变量：

```dotenv
PRO_ZAI_DATA_DIR=/app/data
PRO_ZAI_PASSWORD=
PRO_ZAI_SESSION_SECRET=
TZ=Asia/Shanghai
```

## 本地启动

Windows 推荐：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

也可以直接启动：

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

打开：

- 控制台：<http://127.0.0.1:8765>
- 健康检查：<http://127.0.0.1:8765/api/health>
- Debug 日志：<http://127.0.0.1:8765/api/debug-log>
- 抓包记录：<http://127.0.0.1:8765/api/traffic-log>

运行数据会写入 `logs/` 和 `data/`。

## 注册流程

1. 在控制台配置邮箱。
2. 设置目标账号数。
3. 导入任务或从邮箱池生成任务。
4. 点击开始。队列一次只打开一个验证码窗口。
5. 任务提示需要验证时，切换到弹出的 Chromium。
6. 亲手完成滑块。
7. 不要手动关闭窗口。程序检测成功后会自动关闭并继续协议流程。
8. 在任务结果中获取 CLI JWT。

超过 `captcha_timeout_sec` 或手动关闭验证码窗口会结束当前任务。

## Token 与账号导入

`tokens.txt` 只导出 ZCode CLI JWT。Web JWT 单独导出，不会混入 CLI token 文件。

每个成功任务都可以导入兼容的 `zcode2api`：

```json
{
  "zcode2api_enabled": true,
  "zcode2api_url": "http://your-zcode2api-host:6889",
  "zcode2api_admin_password": "<管理员密码>",
  "zcode2api_auto_import": true
}
```

控制台会遮蔽接口返回的敏感值。真实配置必须留在本地。

## 目录结构

```text
app.py                    FastAPI 应用和任务接口
protocol_client.py        Z.ai HTTP 协议客户端
protocol_registration.py  注册、邮件激活和 OAuth 主流程
protocol_fingerprint.py   协议指纹辅助
captcha_window.py         人工验证码窗口
email_service.py          IMAP 和 API 邮箱
cf_mail.py                动态邮箱服务
proxy_manager.py          代理池
zcode_token.py            ZCode OAuth 和设备标识
zcode2api_import.py       可选账号导入
config_manager.py         配置与任务持久化
templates/index.html      控制台页面
static/app.js             控制台交互
tests/                    回归测试
docs/                     协议与部署文档
```

## 测试

```powershell
python -m pytest -q
```

测试覆盖任务路由、邮箱服务、认证、运行时门禁和协议代理重试。

## Docker

```powershell
docker build -t pro-zai:latest .
Copy-Item .env.example .env
docker compose up -d
```

部署和反向代理说明见 [DEPLOY.md](DEPLOY.md)。

## 安全说明

- 可见 Chromium 只用于人工验证码交互。
- 验证 token、Cookie、JWT、邮箱凭据和代理密码都属于敏感信息。
- 日志和抓包会脱敏，但运行文件仍应按私有数据处理。
- 对非本机开放控制台前，必须设置 `PRO_ZAI_PASSWORD` 和 `PRO_ZAI_SESSION_SECRET`。
- 公网访问时通过反向代理启用 HTTPS。

## 许可证

见 [LICENSE](LICENSE)。
