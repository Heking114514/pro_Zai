# pro-zai

`pro-zai` is a self-hosted Z.ai registration workbench that separates the
protocol flow from the human CAPTCHA step. Email sources, proxies, the task
queue, registration, email verification, and OAuth exchange run in the
application. A visible Chromium window is opened only when a human must complete
the slider.

Chinese documentation: [README.md](README.md)

## Features

1. Establishes a Z.ai guest session through the HTTP protocol client.
2. Optionally checks whether an email address is already registered.
3. Opens one visible Chromium window only for CAPTCHA verification.
4. Waits for the operator to complete the slider manually.
5. Captures the verification token and session cookies.
6. Continues signup, email verification, and OAuth over HTTP.
7. Stores the ZCode CLI JWT separately from the Web JWT.
8. Optionally imports completed accounts into a compatible `zcode2api`.

The project does not solve CAPTCHAs, generate slider trajectories, call a
third-party CAPTCHA service, stream the browser over CDP, or transfer a CAPTCHA
session to another machine.

## Requirements

- Python 3.10+
- A desktop session with a visible Chromium window
- Network access to Z.ai and the configured mail service
- `zcode2api` only when account import is enabled

## Installation

```powershell
git clone git@github.com:Heking114514/pro_Zai.git
cd pro_Zai

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

## Configuration

Create the runtime configuration from the safe template:

```powershell
Copy-Item config.example.json config.json
```

Populate only the services you intend to use.

| Field | Purpose |
| --- | --- |
| `mail_provider` | `imap`, `api`, or `cf_dynamic` |
| `mail_api_pool` | Mailbox JWT pool for API mode |
| `imap_*` | IMAP mailbox settings |
| `cf_mail_*` | Dynamic mail service settings |
| `proxy_*` | Optional proxy configuration |
| `registration_mode` | Keep this at `protocol` |
| `captcha_timeout_sec` | Maximum wait for human verification |
| `target_count` | Number of accounts handled by the queue |
| `zcode2api_enabled` | Enable import to `zcode2api` |
| `zcode2api_url` | Base URL of a compatible `zcode2api` instance |
| `zcode2api_admin_password` | Admin password used by the import API |

Never commit:

- `config.json`
- `tasks.json`
- `tokens.txt`
- `data/`
- `logs/`
- browser profiles and account databases

Docker environment variables:

```dotenv
PRO_ZAI_DATA_DIR=/app/data
PRO_ZAI_PASSWORD=
PRO_ZAI_SESSION_SECRET=
TZ=Asia/Shanghai
```

## Run locally

Recommended on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

Or start the server directly:

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

Open:

- Web console: <http://127.0.0.1:8765>
- Health check: <http://127.0.0.1:8765/api/health>
- Debug log: <http://127.0.0.1:8765/api/debug-log>
- Traffic log: <http://127.0.0.1:8765/api/traffic-log>

Runtime data is written to `logs/` and `data/`.

## Registration workflow

1. Configure a mail provider in the Web console.
2. Set the target account count.
3. Import tasks or generate them from the mailbox pool.
4. Start the queue. Only one CAPTCHA window is opened at a time.
5. When verification is requested, switch to the visible Chromium window.
6. Complete the slider manually.
7. Do not close the window manually. The application closes it after success
   and continues the protocol flow.
8. Retrieve the CLI JWT from the task result.

Closing the browser manually or exceeding `captcha_timeout_sec` ends the current
task.

## Tokens and account import

The `tokens.txt` export contains only ZCode CLI JWTs. Web JWTs are exported
separately and are never mixed into the CLI token file.

Each successful task can be imported into a compatible `zcode2api` deployment:

```json
{
  "zcode2api_enabled": true,
  "zcode2api_url": "http://your-zcode2api-host:6889",
  "zcode2api_admin_password": "<admin password>",
  "zcode2api_auto_import": true
}
```

The console masks secrets returned by the configuration API. Keep the real
configuration local.

## Project layout

```text
app.py                    FastAPI application and task API
protocol_client.py        Z.ai HTTP protocol client
protocol_registration.py  Registration, verification, and OAuth workflow
protocol_fingerprint.py   Client fingerprint helpers
captcha_window.py         Visible Chromium CAPTCHA handoff
email_service.py          IMAP and API mailbox support
cf_mail.py                Dynamic mailbox provider
proxy_manager.py          Proxy pool management
zcode_token.py            ZCode OAuth and device identity
zcode2api_import.py       Optional account import client
config_manager.py         Configuration and task persistence
templates/index.html      Web console
static/app.js             Web console behavior
tests/                    Focused regression tests
docs/                     Protocol and deployment notes
```

## Tests

```powershell
python -m pytest -q
```

The tests cover task routing, email providers, authentication, runtime gates,
and protocol proxy retries.

## Docker

```powershell
docker build -t pro-zai:latest .
Copy-Item .env.example .env
docker compose up -d
```

See [DEPLOY.md](DEPLOY.md) for deployment and reverse-proxy notes.

## Security

- The visible Chromium window is for human CAPTCHA interaction only.
- Verification tokens, cookies, JWTs, mailbox credentials, and proxy
  credentials are sensitive.
- Logs and traffic captures are sanitized, but runtime files are still private.
- Set `PRO_ZAI_PASSWORD` and `PRO_ZAI_SESSION_SECRET` before exposing the
  console beyond localhost.
- Use HTTPS through a reverse proxy for network access.

## License

See [LICENSE](LICENSE).
