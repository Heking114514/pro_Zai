"""Build and start pro-zai directly on the deployment server.

The script uploads only source files and asks the server to pull/build the base
image. This avoids transferring the 1+ GB image through a slow SSH link.

Environment:
    PRO_ZAI_SSH_HOST
    PRO_ZAI_SSH_USER
    PRO_ZAI_SSH_PASSWORD
    PRO_ZAI_SSH_PORT (default 22)
    PRO_ZAI_WEB_PASSWORD (optional WebUI gate)
    PRO_ZAI_SESSION_SECRET (optional session signing key)
"""

from __future__ import annotations

import io
import json
import os
import posixpath
import sys
import tarfile
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parent
REMOTE_DIR = "/opt/pro-zai"
INCLUDE = (
    "app.py",
    "auth_gate.py",
    "captcha_solver.py",
    "cf_mail.py",
    "config.example.json",
    "config_manager.py",
    "debug_log.py",
    "email_service.py",
    "protocol_client.py",
    "protocol_fingerprint.py",
    "protocol_registration.py",
    "captcha_window.py",
    "debug_log.py",
    "traffic_log.py",
    "proxy_manager.py",
    "register_worker.py",
    "requirements.txt",
    "zcode_token.py",
    "Dockerfile",
    ".dockerignore",
    "compose.yaml",
    "static",
    "templates",
    "scripts",
)


def run(client: paramiko.SSHClient, command: str, timeout: int = 300) -> str:
    print("+", command, flush=True)
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if output.strip():
        print(output.rstrip(), flush=True)
    if error.strip():
        print(error.rstrip(), file=sys.stderr, flush=True)
    if status:
        raise RuntimeError(f"Remote command failed ({status}): {command}")
    return output


def source_archive() -> io.BytesIO:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name in INCLUDE:
            path = ROOT / name
            if not path.exists():
                continue
            archive.add(path, arcname=name, recursive=True)
        server_config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        server_config.update(
            {
                "registration_mode": "protocol",
                "headless": False,
                "protocol_fallback_browser": False,
                "captcha_timeout_sec": 600,
                "concurrency": 1,
                "mail_provider": "cf_dynamic",
            }
        )
        config_bytes = json.dumps(
            server_config,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        info = tarfile.TarInfo("config.json")
        info.size = len(config_bytes)
        info.mode = 0o600
        archive.addfile(info, io.BytesIO(config_bytes))
    stream.seek(0)
    return stream


def upload_runtime_config(client: paramiko.SSHClient) -> None:
    """Update the mounted config consumed by the running container.

    The image also contains a config.json, but PRO_ZAI_DATA_DIR points at
    /app/data, whose bind-mounted config takes precedence. Writing only the
    source-tree file leaves the deployed runtime on stale settings.
    """

    server_config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    server_config.update(
        {
            "registration_mode": "protocol",
            "headless": False,
            "protocol_fallback_browser": False,
            "captcha_timeout_sec": 600,
            "concurrency": 1,
            "mail_provider": "cf_dynamic",
        }
    )
    payload = json.dumps(server_config, ensure_ascii=False, indent=2)
    sftp = client.open_sftp()
    try:
        path = posixpath.join(REMOTE_DIR, "data", "config.json")
        with sftp.open(path, "w") as handle:
            handle.write(payload)
    finally:
        sftp.close()


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        os.environ["PRO_ZAI_SSH_HOST"],
        port=int(os.environ.get("PRO_ZAI_SSH_PORT", "22")),
        username=os.environ.get("PRO_ZAI_SSH_USER", "root"),
        password=os.environ["PRO_ZAI_SSH_PASSWORD"],
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
    )
    try:
        run(client, f"mkdir -p {REMOTE_DIR}/data")
        run(client, f"find {REMOTE_DIR} -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {{}} +")
        sftp = client.open_sftp()
        try:
            sftp.putfo(source_archive(), "/tmp/pro-zai-source.tar.gz")
        finally:
            sftp.close()
        run(client, f"tar -xzf /tmp/pro-zai-source.tar.gz -C {REMOTE_DIR}")
        run(client, "rm -f /tmp/pro-zai-source.tar.gz")
        upload_runtime_config(client)

        env_lines = [
            "PRO_ZAI_DATA_DIR=/app/data",
            "TZ=Asia/Shanghai",
            f"PRO_ZAI_PASSWORD={os.environ.get('PRO_ZAI_WEB_PASSWORD', '')}",
            f"PRO_ZAI_SESSION_SECRET={os.environ.get('PRO_ZAI_SESSION_SECRET', '')}",
            "",
        ]
        sftp = client.open_sftp()
        try:
            with sftp.open(posixpath.join(REMOTE_DIR, ".env"), "w") as handle:
                handle.write("\n".join(env_lines))
        finally:
            sftp.close()

        run(
            client,
            f"cd {REMOTE_DIR} && docker build -t pro-zai:latest .",
            timeout=1800,
        )
        # docker-compose 1.29 cannot recreate containers built by newer Docker
        # because its image inspection no longer sees ContainerConfig. Remove
        # every service container in this compose project, including the old
        # auto-prefixed name, while keeping the bind-mounted data intact.
        run(
            client,
            "docker ps -aq "
            "--filter label=com.docker.compose.project=pro-zai "
            "--filter label=com.docker.compose.service=pro-zai "
            "| xargs -r docker rm -f",
            timeout=60,
        )
        run(
            client,
            f"cd {REMOTE_DIR} && docker-compose up -d --no-recreate",
            timeout=300,
        )
        run(client, f"cd {REMOTE_DIR} && docker-compose ps", timeout=60)
        run(
            client,
            "curl -fsS --max-time 20 http://127.0.0.1:8009/api/health",
            timeout=30,
        )
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
