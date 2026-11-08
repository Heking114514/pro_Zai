"""Deploy the locally built pro-zai image to a password-authenticated SSH host.

Credentials are read from environment variables and never written to disk:
    PRO_ZAI_SSH_HOST
    PRO_ZAI_SSH_USER
    PRO_ZAI_SSH_PASSWORD
    PRO_ZAI_SSH_PORT (optional, default 22)
"""

from __future__ import annotations

import json
import os
import posixpath
import subprocess
import sys
import tempfile
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parent
REMOTE_DIR = "/opt/pro-zai"
LOCAL_IMAGE = "pro-zai:local"
REMOTE_IMAGE = "pro-zai:latest"


def run(client: paramiko.SSHClient, command: str, timeout: int = 120) -> str:
    print("+", command)
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if output.strip():
        print(output.rstrip())
    if error.strip():
        print(error.rstrip(), file=sys.stderr)
    if status:
        raise RuntimeError(f"Remote command failed ({status}): {command}")
    return output


def upload_text(client: paramiko.SSHClient, remote_path: str, text: str) -> None:
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "w") as handle:
            handle.write(text)
    finally:
        sftp.close()


def main() -> int:
    host = os.environ["PRO_ZAI_SSH_HOST"]
    user = os.environ.get("PRO_ZAI_SSH_USER", "root")
    password = os.environ["PRO_ZAI_SSH_PASSWORD"]
    port = int(os.environ.get("PRO_ZAI_SSH_PORT", "22"))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=user,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
    )
    try:
        run(client, f"mkdir -p {REMOTE_DIR}/data")
        run(client, "systemctl enable --now docker", timeout=60)
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        upload_text(client, posixpath.join(REMOTE_DIR, "compose.yaml"), compose)
        env_text = "\n".join(
            [
                "PRO_ZAI_DATA_DIR=/app/data",
                "TZ=Asia/Shanghai",
                f"PRO_ZAI_PASSWORD={os.environ.get('PRO_ZAI_WEB_PASSWORD', '')}",
                f"PRO_ZAI_SESSION_SECRET={os.environ.get('PRO_ZAI_SESSION_SECRET', '')}",
                "",
            ]
        )
        upload_text(client, posixpath.join(REMOTE_DIR, ".env"), env_text)
        config_path = ROOT / "config.json"
        if config_path.is_file():
            server_config = json.loads(config_path.read_text(encoding="utf-8"))
            server_config.update(
                {
                    "registration_mode": "protocol",
                    "headless": False,
                    "protocol_fallback_browser": False,
                    "concurrency": 1,
                    "mail_provider": "cf_dynamic",
                }
            )
            upload_text(
                client,
                posixpath.join(REMOTE_DIR, "data", "config.json"),
                json.dumps(server_config, ensure_ascii=False, indent=2),
            )

        print("Saving and uploading Docker image...")
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as image_file:
            image_path = Path(image_file.name)
        try:
            subprocess.run(
                ["docker", "save", "-o", str(image_path), LOCAL_IMAGE],
                check=True,
            )
            sftp = client.open_sftp()
            try:
                sftp.put(str(image_path), "/tmp/pro-zai-image.tar")
            finally:
                sftp.close()
            run(client, "docker load -i /tmp/pro-zai-image.tar", timeout=300)
            run(
                client,
                f"docker tag {LOCAL_IMAGE} {REMOTE_IMAGE}",
                timeout=30,
            )
        finally:
            image_path.unlink(missing_ok=True)
            run(client, "rm -f /tmp/pro-zai-image.tar", timeout=30)

        run(client, f"cd {REMOTE_DIR} && docker-compose up -d --force-recreate", timeout=180)
        run(client, f"cd {REMOTE_DIR} && docker-compose ps", timeout=60)
        run(
            client,
            "curl -fsS --max-time 15 http://127.0.0.1:8009/api/health",
            timeout=30,
        )
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
