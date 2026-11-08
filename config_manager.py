import json
import os
from typing import Dict, Any, List

DATA_DIR = os.environ.get(
    "PRO_ZAI_DATA_DIR",
    os.path.dirname(__file__),
)
os.makedirs(DATA_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")

DEFAULT_CONFIG = {
    "mail_provider": "imap",
    "mail_api_url": "https://mail.example.com/api/mails?limit=20&offset=0",
    "mail_api_pool": "",
    "cf_mail_base": "https://mail.example.com",
    "cf_mail_domain": "example.com",
    "cf_mail_site_password": "",
    "cf_mail_create_timeout_sec": 20,
    "imap_host": "",
    "imap_port": 993,
    "imap_ssl": True,
    "imap_user": "",
    "imap_pass": "",
    "imap_folder": "INBOX",
    "headless": False,
    "registration_mode": "protocol",
    "protocol_fallback_browser": False,
    "protocol_impersonate": "auto",
    "protocol_locale": "zh-CN",
    "protocol_timezone": "Asia/Shanghai",
    "protocol_timezone_offset_min": -480,
    "protocol_timeout_sec": 30,
    "protocol_oauth_timeout_sec": 30,
    "protocol_check_exists_before_signup": True,
    "protocol_direct_signup": True,
    "captcha_timeout_sec": 600,
    "manual_verify_timeout_sec": 600,
    "email_poll_timeout_sec": 90,
    "default_password": "",
    "auto_verify_email": True,
    "target_count": 1,
    "zcode2api_enabled": False,
    "zcode2api_url": "http://127.0.0.1:6789",
    "zcode2api_admin_password": "",
    "zcode2api_auto_import": True,
    "zcode2api_timeout_sec": 20,
    "proxy_enabled": False,
    "proxy_strategy": "round_robin",
    "proxy_pool": "",
    "proxy_server": "",
    "proxy_username": "",
    "proxy_password": ""
}

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = DEFAULT_CONFIG.copy()
                res.update(data)
                return res
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg: Dict[str, Any]):
    current = load_config()
    current.update(cfg)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2, ensure_ascii=False)

def load_tasks() -> List[Dict[str, Any]]:
    if os.path.exists(TASKS_FILE):
        try:
            with open(TASKS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_tasks(tasks: List[Dict[str, Any]]):
    with open(TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, indent=2, ensure_ascii=False)
