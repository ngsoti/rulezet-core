import json
import os
import platform
import subprocess
import sys
from datetime import datetime

from flask import current_app


# ──────────────────────────────────────────────
# System information
# ──────────────────────────────────────────────

def get_system_info() -> dict:
    """Gather server, OS, and runtime information."""
    import socket
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'unknown'

    disk = _get_disk_usage()
    memory = _get_memory_info()

    import flask
    cfg = current_app.config
    return {
        'hostname': hostname,
        'os': platform.system(),
        'os_release': platform.release(),
        'os_full': platform.platform(),
        'architecture': platform.machine(),
        'python_version': sys.version.split()[0],
        'python_full': sys.version,
        'flask_version': flask.__version__,
        'environment': os.environ.get('FLASKENV', 'unknown'),
        'debug': cfg.get('DEBUG', False),
        'cwd': os.getcwd(),
        'pid': os.getpid(),
        'flask_url': cfg.get('FLASK_URL', '127.0.0.1'),
        'flask_port': cfg.get('FLASK_PORT', 7009),
        'db_uri': _mask_db_uri(cfg.get('SQLALCHEMY_DATABASE_URI', '')),
        'disk': disk,
        'memory': memory,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
    }


def _mask_db_uri(uri: str) -> str:
    if '@' in uri:
        scheme_creds, rest = uri.rsplit('@', 1)
        if ':' in scheme_creds:
            base = scheme_creds.rsplit(':', 1)[0]
            return f"{base}:***@{rest}"
    return uri


def _get_disk_usage() -> dict:
    try:
        import shutil
        total, used, free = shutil.disk_usage('/')
        return {
            'total_gb': round(total / 2 ** 30, 1),
            'used_gb': round(used / 2 ** 30, 1),
            'free_gb': round(free / 2 ** 30, 1),
            'percent': round(used / total * 100, 1),
        }
    except Exception:
        return {}


def _get_memory_info() -> dict:
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            'total_gb': round(mem.total / 2 ** 30, 1),
            'available_gb': round(mem.available / 2 ** 30, 1),
            'percent': mem.percent,
        }
    except Exception:
        return {}


# ──────────────────────────────────────────────
# Installed packages
# ──────────────────────────────────────────────

def get_installed_packages() -> list:
    """Return installed Python packages sorted alphabetically."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--format=json'],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            pkgs = json.loads(result.stdout)
            return sorted(pkgs, key=lambda p: p.get('name', '').lower())
    except Exception:
        pass

    try:
        import importlib.metadata as im
        return sorted(
            [{'name': d.name, 'version': d.version} for d in im.distributions()],
            key=lambda p: p['name'].lower(),
        )
    except Exception:
        return []


# ──────────────────────────────────────────────
# Git submodules
# ──────────────────────────────────────────────

def get_git_submodules() -> list:
    """Return information about all git submodules."""
    cwd = os.getcwd()
    submodules = []
    try:
        result = subprocess.run(
            ['git', 'submodule', 'status'],
            capture_output=True, text=True, timeout=15, cwd=cwd,
        )
        for line in result.stdout.splitlines():
            line = line.rstrip()
            if not line:
                continue
            flag = line[0] if line[0] in ('+', '-', 'U') else ' '
            parts = line.lstrip('+-U ').split()
            if len(parts) < 2:
                continue
            sha = parts[0]
            path = parts[1]
            describe = ' '.join(parts[2:]).strip('()')
            url = _submodule_url(path, cwd)
            commit = _submodule_last_commit(path, cwd)
            status_label = {' ': 'up-to-date', '+': 'modified', '-': 'not initialized', 'U': 'conflict'}.get(flag, 'unknown')
            submodules.append({
                'path': path,
                'name': path.split('/')[-1],
                'sha': sha[:8],
                'sha_full': sha,
                'url': url,
                'flag': flag,
                'status': status_label,
                'describe': describe,
                'last_commit_msg': commit.get('msg', ''),
                'last_commit_date': commit.get('date', ''),
                'last_commit_author': commit.get('author', ''),
            })
    except Exception:
        pass
    return submodules


def _submodule_url(path: str, cwd: str) -> str:
    try:
        r = subprocess.run(
            ['git', 'config', f'submodule.{path}.url'],
            capture_output=True, text=True, timeout=5, cwd=cwd,
        )
        return r.stdout.strip()
    except Exception:
        return ''


def _submodule_last_commit(path: str, cwd: str) -> dict:
    try:
        full = os.path.join(cwd, path)
        if not os.path.isdir(full):
            return {}
        r = subprocess.run(
            ['git', 'log', '-1', '--format=%s|%ad|%an', '--date=short'],
            capture_output=True, text=True, timeout=5, cwd=full,
        )
        parts = r.stdout.strip().split('|')
        return {
            'msg': parts[0] if parts else '',
            'date': parts[1] if len(parts) > 1 else '',
            'author': parts[2] if len(parts) > 2 else '',
        }
    except Exception:
        return {}


def update_submodule(path: str) -> dict:
    """Pull latest commit for a submodule."""
    cwd = os.getcwd()
    try:
        result = subprocess.run(
            ['git', 'submodule', 'update', '--remote', '--merge', '--', path],
            capture_output=True, text=True, timeout=120, cwd=cwd,
        )
        return {
            'success': result.returncode == 0,
            'output': result.stdout.strip(),
            'error': result.stderr.strip(),
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'output': ''}


# ──────────────────────────────────────────────
# App configuration
# ──────────────────────────────────────────────

def get_app_config() -> dict:
    """Return current application configuration (sensitive values masked)."""
    cfg = current_app.config
    secret = cfg.get('SECRET_KEY') or ''
    mail_pwd = cfg.get('MAIL_PASSWORD') or ''
    github_token = os.environ.get('GITHUB_TOKEN') or ''
    return {
        'mail': {
            'server': cfg.get('MAIL_SERVER', ''),
            'port': cfg.get('MAIL_PORT', ''),
            'use_tls': cfg.get('MAIL_USE_TLS', False),
            'use_ssl': cfg.get('MAIL_USE_SSL', False),
            'username': cfg.get('MAIL_USERNAME', ''),
            'default_sender': cfg.get('MAIL_DEFAULT_SENDER', ''),
            'password_set': bool(mail_pwd),
            'password_preview': (mail_pwd[:2] + '••••' + mail_pwd[-2:]) if len(mail_pwd) >= 4 else '••••',
        },
        'app': {
            'flask_url': cfg.get('FLASK_URL', '127.0.0.1'),
            'flask_port': cfg.get('FLASK_PORT', 7009),
            'debug': cfg.get('DEBUG', False),
            'environment': os.environ.get('FLASKENV', 'unknown'),
            'secret_key_set': bool(secret),
            'secret_key_preview': (secret[:4] + '••••••••') if secret else 'not set',
            'secret_key_length': len(secret),
            'github_token_set': bool(github_token),
            'github_token_preview': '••••••••••••' if github_token else 'not set',
        },
    }


def read_env_file() -> dict:
    """Read .env file as a key→value dict."""
    env_path = os.path.join(os.getcwd(), '.env')
    data = {}
    if not os.path.exists(env_path):
        return data
    with open(env_path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or '=' not in stripped:
                continue
            key, _, val = stripped.partition('=')
            data[key.strip()] = val.strip().strip('"').strip("'")
    return data


_ENV_ALLOWED = {
    'SECRET_KEY',
    'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD',
    'MAIL_USE_TLS', 'MAIL_USE_SSL', 'MAIL_DEFAULT_SENDER',
    'FLASK_URL', 'FLASK_PORT',
    'GITHUB_TOKEN',
}


def write_env_value(key: str, value: str) -> bool:
    """Update or append a single key in the .env file."""
    if key not in _ENV_ALLOWED:
        return False
    env_path = os.path.join(os.getcwd(), '.env')
    lines = []
    found = False
    if os.path.exists(env_path):
        with open(env_path) as f:
            raw = f.read()
        for line in raw.splitlines(keepends=True):
            stripped = line.strip()
            line_key = stripped.split('=')[0].strip() if '=' in stripped else ''
            if stripped and not stripped.startswith('#') and line_key == key:
                lines.append(f"{key}='{value}'\n")
                found = True
            else:
                # Ensure every line ends with a newline
                lines.append(line if line.endswith('\n') else line + '\n')
    if not found:
        lines.append(f"{key}='{value}'\n")
    try:
        with open(env_path, 'w') as f:
            f.writelines(lines)
        return True
    except Exception:
        return False


def generate_secret_key() -> str:
    """Generate a new cryptographically secure SECRET_KEY."""
    import secrets
    return secrets.token_urlsafe(48)


# ──────────────────────────────────────────────
# Email test
# ──────────────────────────────────────────────

def send_test_email(recipient: str) -> dict:
    """Send a test email using Flask-Mail's current configuration."""
    from flask_mail import Message
    try:
        mail_ext = current_app.extensions.get('mail')
        if not mail_ext:
            return {'success': False, 'error': 'Flask-Mail extension not initialised'}
        msg = Message(
            subject='Rulezet — Test Email',
            recipients=[recipient],
            html=(
                '<div style="font-family:sans-serif;max-width:520px;margin:0 auto;">'
                '<div style="background:#0d6efd;padding:24px 32px;border-radius:8px 8px 0 0;">'
                '<h2 style="color:#fff;margin:0;font-size:1.4rem;">Rulezet</h2>'
                '</div>'
                '<div style="border:1px solid #dee2e6;border-top:0;padding:32px;border-radius:0 0 8px 8px;">'
                '<h3 style="margin-top:0;color:#212529;">Test Email</h3>'
                '<p style="color:#495057;">This is a <strong>test email</strong> sent from the Rulezet admin settings panel.</p>'
                '<p style="color:#495057;">If you received this message, your SMTP configuration is working correctly.</p>'
                '<hr style="border-color:#dee2e6;">'
                '<small style="color:#6c757d;">Sent automatically from Rulezet — do not reply.</small>'
                '</div></div>'
            ),
        )
        mail_ext.send(msg)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
