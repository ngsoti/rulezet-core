#!/usr/bin/env python3
"""
manage.py — Rulezet management script

Usage:
    python3 manage.py <command>

Commands:
    init        First-time setup: install deps + init DB
    start       Start the dev server
    start-prod  Start with Gunicorn (production)
    test        Run the test suite
    update      git pull + install deps + ensure ollama + DB migrations
    backup      Backup the PostgreSQL database
    restore     Restore a PostgreSQL backup (interactive)
    deploy      Full deployment: backup + update + start-prod
    db          Run Flask-Migrate commands (upgrade by default)
    db-init     Create tables + admin user (python3 app.py -i)
    db-reload   Drop + recreate DB (python3 app.py -r)
    help        Show this help message
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / "env"
VENV_BIN = VENV / "bin"

PYTHON   = str(VENV_BIN / "python3")
FLASK    = str(VENV_BIN / "flask")
GUNICORN = str(VENV_BIN / "gunicorn")
PYTEST   = str(VENV_BIN / "pytest")
PIP      = str(VENV_BIN / "pip")


# ── Helpers ───────────────────────────────────────────────────────────────────

def header(text: str) -> None:
    print(f"\n\033[1;34m{'─' * 52}\033[0m")
    print(f"\033[1;34m  {text}\033[0m")
    print(f"\033[1;34m{'─' * 52}\033[0m")


def ok(text: str) -> None:
    print(f"\033[1;32m  ✓ {text}\033[0m")


def info(text: str) -> None:
    print(f"\033[0;37m  · {text}\033[0m")


def error(text: str) -> None:
    print(f"\033[1;31m  ✗ {text}\033[0m", file=sys.stderr)


def app_version() -> str:
    try:
        return (ROOT / "version").read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def _venv_env() -> dict:
    """Build an environment dict that activates the virtualenv."""
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(VENV)
    env["PATH"] = str(VENV_BIN) + os.pathsep + env.get("PATH", "")
    env.pop("PYTHONHOME", None)
    return env


def run(cmd: list[str], cwd: Path = ROOT, check: bool = True, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = _venv_env()
    if extra_env:
        env.update(extra_env)
    info(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, env=env)
    # returncode 130 = Ctrl+C sent to child process
    if result.returncode in (130, -2):
        raise KeyboardInterrupt
    if check and result.returncode != 0:
        error(f"Command failed: {' '.join(cmd)}")
        sys.exit(result.returncode)
    return result


def _confirm(prompt: str) -> bool:
    """Ask for confirmation. Returns True if confirmed, False if cancelled (or Ctrl+C)."""
    try:
        answer = input(f"\033[1;33m  {prompt} [yes/N]: \033[0m").strip().lower()
        return answer == "yes"
    except KeyboardInterrupt:
        return False


def _check_venv() -> None:
    if not VENV_BIN.exists():
        error(f"Virtualenv not found at {VENV}")
        print(f"\n  Create it first:\n    python3 -m venv {VENV}\n    python3 manage.py init\n")
        sys.exit(1)


OLLAMA_MODEL = "qwen2.5:1.5b"

# Set as the rule_fixer agent's default_model (AIAgentConfig, set directly
# in the DB, not here) once pulled. Kept separate from OLLAMA_MODEL since
# that one is the chatbot's default and the two agents don't have to share
# a model.
#
# Was hf.co/vtriple/threatflux-0.6B-gguf (a 0.6B YARA-specific fine-tune) —
# swapped out after it missed an actual production bug (a string identifier
# missing its leading '$') that qwen2.5-coder:7b caught correctly once the
# prompt was also fixed to highlight the exact flagged line (see
# rule_fixer_agent.py's _line_context — a small YARA-specific model is not
# a substitute for solid general instruction-following on precise, localized
# text edits). Larger (~4.7GB vs ~1.2GB) and slower, but confirmed to
# actually work on real broken rules where the smaller one didn't.
OLLAMA_RULE_FIXER_MODEL = "qwen2.5-coder:7b"

# Pinned, not "latest": 0.32.1+ segfaults on every model on Intel Sapphire
# Rapids Xeons (e.g. Xeon Silver 4410Y — production's CPU) — its AMX-aware
# CPU inference path crashes on this CPU generation even with
# OLLAMA_LLM_LIBRARY=cpu forced and a from-scratch reinstall/re-pulled
# model. 0.5.7 predates that code path (falls back to a plain avx2 runner)
# and was confirmed working. Bump this only after confirming a newer
# release fixes the Sapphire Rapids crash — briefly bumped to 0.33.0 for
# Qwen3 support (a since-abandoned rule_fixer model needed it), reverted
# once rule_fixer moved to qwen2.5-coder:7b, which needs nothing newer than
# this — same architecture family as qwen2.5:1.5b/3b, already confirmed
# working here.
OLLAMA_VERSION = "0.5.7"


def _install_ollama() -> bool:
    info(f"Installing Ollama {OLLAMA_VERSION} (this may prompt for your sudo password)…")
    result = subprocess.run(
        f"curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION={OLLAMA_VERSION} sh",
        shell=True,
    )
    if result.returncode != 0:
        error("Ollama installation failed or was skipped — the chat assistant will "
              "report a connection error until it's installed manually "
              f"(curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION={OLLAMA_VERSION} sh).")
        return False
    return True


def _ensure_ollama() -> None:
    """Best-effort: install Ollama (used by the in-app chat assistant), pinned
    to OLLAMA_VERSION (see comment above — NOT "latest", a known segfault on
    Sapphire Rapids CPUs), and pull the default model if missing. Mirrors
    install.sh/update.sh's step — manage.py's start-prod/update never call
    those scripts, so without this an instance driven only through manage.py
    never gets Ollama set up."""
    import shutil as _shutil

    info("Checking for Ollama (used by the chat assistant)…")
    ollama_bin = _shutil.which("ollama")

    if not ollama_bin:
        if not _install_ollama():
            return
        ollama_bin = _shutil.which("ollama")
        if not ollama_bin:
            return
        ok(f"Ollama {OLLAMA_VERSION} installed")
    else:
        version = subprocess.run([ollama_bin, "--version"], capture_output=True, text=True, check=False)
        if OLLAMA_VERSION not in (version.stdout or ""):
            info(f"Ollama is installed but not pinned version {OLLAMA_VERSION} "
                 f"({(version.stdout or '').strip() or 'unknown version'}) — reinstalling the pinned version…")
            if not _install_ollama():
                return
            ok(f"Ollama downgraded/reinstalled to {OLLAMA_VERSION}")
        else:
            ok(f"Ollama {OLLAMA_VERSION} is already installed")

    try:
        listed = subprocess.run([ollama_bin, "list"], capture_output=True, text=True, check=False)
        already_listed = listed.stdout or ""
        for model_name, used_by in (
            (OLLAMA_MODEL, "the chat assistant"),
            (OLLAMA_RULE_FIXER_MODEL, "the Rule Fixer agent"),
        ):
            if model_name not in already_listed:
                info(f"Pulling the {model_name} model (used by {used_by})…")
                pulled = subprocess.run([ollama_bin, "pull", model_name])
                if pulled.returncode == 0:
                    ok(f"{model_name} pulled")
                else:
                    error(f"Could not pull {model_name} — run 'ollama pull {model_name}' manually.")
            else:
                ok(f"{model_name} already pulled")
    except OSError as e:
        error(f"Could not check/pull Ollama models: {e}")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_help() -> None:
    W = "\033[1;37m"
    B = "\033[1;34m"
    G = "\033[1;32m"
    Y = "\033[1;33m"
    D = "\033[0;37m"
    R = "\033[0m"

    print(f"""
{B}╔════════════════════════════════════════════════════╗
║              Rulezet — manage.py                   ║
╚════════════════════════════════════════════════════╝{R}

{W}Usage:{R}
    {G}python3 manage.py{R} {Y}<command>{R}

{W}Commands:{R}

  {G}init{R}          {D}First-time setup:{R}
                  {D}  install deps from requirements.txt → init DB{R}
                  {D}→ Run once after cloning the repo{R}

  {G}start{R}         {D}Start the development server (FLASKENV=development){R}
                  {D}→ Use this for local development{R}

  {G}start-prod{R}    {D}Full production launch:{R}
                  {D}  backup → git pull → pip install → ensure ollama → db upgrade{R}
                  {D}  → flask run --host=0.0.0.0 --port=80{R}
                  {D}→ Use this on the production server (needs root for port 80){R}

  {G}test{R}          {D}Run the full test suite (FLASKENV=testing){R}

  {G}update{R}        {D}git pull + pip install + ensure ollama + flask db upgrade{R}
                  {D}→ Use this after pulling new code{R}

  {G}backup{R}        {D}Backup PostgreSQL database to backup/dumps/{R}

  {G}restore{R}       {D}Restore a backup interactively{R}

  {G}deploy{R}        {D}Full deployment: backup → update → start-prod{R}

  {G}db{R}            {D}Run Flask-Migrate commands (defaults to upgrade){R}
                  {D}→ python3 manage.py db            # flask db upgrade{R}
                  {D}→ python3 manage.py db migrate -m "msg"{R}
                  {D}→ python3 manage.py db downgrade{R}

  {G}db-init{R}       {D}Create tables + admin user (app.py -i){R}
                  {D}→ Use after a fresh DB creation{R}

  {G}db-reload{R}     {D}DROP + recreate the entire database (app.py -r){R}
                  {D}→ Destructive — wipes all data{R}

  {G}help{R}          {D}Show this message{R}

{W}Examples:{R}

  {D}# Fresh install{R}
  {G}python3 -m venv env{R}
  {G}python3 manage.py init{R}
  {G}python3 manage.py start{R}

  {D}# Daily development{R}
  {G}python3 manage.py start{R}

  {D}# After pulling new code{R}
  {G}python3 manage.py update{R}

  {D}# Generate + apply a migration{R}
  {G}python3 manage.py db migrate -m "add column X"{R}
  {G}python3 manage.py db upgrade{R}

  {D}# Production deployment{R}
  {G}python3 manage.py deploy{R}

{W}Project root:{R} {D}{ROOT}{R}
""")


def cmd_init() -> None:
    _check_venv()
    header("Initialising Rulezet (first-time setup)")

    info("Installing Python dependencies…")
    run([PIP, "install", "-r", "requirements.txt"])
    ok("Dependencies installed")

    info("Initialising database (tables + admin user)…")
    run([PYTHON, "app.py", "-i"], extra_env={"FLASKENV": "development"})
    ok("Database initialised")

    header("Init complete")
    ok("Ready. Run:  python3 manage.py start")


def cmd_start() -> None:
    _check_venv()
    url = f"http://{os.environ.get('FLASK_URL', '127.0.0.1')}:{os.environ.get('FLASK_PORT', 7009)}"
    header(f"Starting Rulezet v{app_version()} (development)")
    info(f"Serving at {url}")
    info("Press CTRL+C to stop")
    try:
        run([PYTHON, "app.py"], extra_env={"FLASKENV": "development"})
    except KeyboardInterrupt:
        print("\n\033[0;37m  · Server stopped.\033[0m")


def cmd_start_prod() -> None:
    _check_venv()

    # 1. Backup
    cmd_backup()

    # 2. Pull + deps + migrations
    header("Updating Rulezet")
    info("Pulling latest code…")
    run(["git", "pull"])
    ok("Code updated")

    info("Syncing Python dependencies…")
    run([PIP, "install", "-r", "requirements.txt"])
    ok("Dependencies up to date")

    _ensure_ollama()

    info("Running database migrations…")
    run([FLASK, "db", "upgrade"], extra_env={"FLASKENV": "production"})
    ok("Database schema up to date")

    # 3. Start
    public_url = os.environ.get("INSTANCE_PUBLIC_URL") or "http://0.0.0.0:80"
    header(f"Starting Rulezet v{app_version()} (production)")
    info(f"Serving at {public_url}")
    info("Press CTRL+C to stop")
    try:
        run([FLASK, "run", "--host=0.0.0.0", "--port=80"], extra_env={"FLASKENV": "production"})
    except KeyboardInterrupt:
        print("\n\033[0;37m  · Server stopped.\033[0m")


def cmd_test() -> None:
    _check_venv()
    header("Running tests")
    run([PYTEST, "tests"], extra_env={"FLASKENV": "testing"})
    ok("Tests done")


def cmd_backup() -> None:
    header("Backing up database")
    script = ROOT / "backup" / "scripts" / "backup_rulezet.sh"
    if not script.exists():
        error(f"Backup script not found: {script}")
        sys.exit(1)
    run(["bash", str(script)])
    ok("Backup complete")


def cmd_restore() -> None:
    header("Restoring database")
    print("\033[1;31m  WARNING: This will DROP the current database.\033[0m")
    if not _confirm("Are you sure you want to restore?"):
        info("Cancelled.")
        return
    script = ROOT / "backup" / "scripts" / "restore_rulezet.sh"
    if not script.exists():
        error(f"Restore script not found: {script}")
        sys.exit(1)
    # Forward extra args (e.g. a specific dump filename)
    extra = sys.argv[2:]
    run(["bash", str(script)] + extra)


def cmd_update() -> None:
    _check_venv()
    header("Updating Rulezet")

    info("Pulling latest code…")
    run(["git", "pull"])
    ok("Code updated")

    info("Syncing Python dependencies…")
    run([PIP, "install", "-r", "requirements.txt"])
    ok("Dependencies up to date")

    _ensure_ollama()

    info("Running database migrations…")
    run([FLASK, "db", "upgrade"], extra_env={"FLASKENV": "development"})
    ok("Database schema up to date")

    info("Seeding default data (formats, platform-tag configs)…")
    run([PYTHON, "app.py", "--seed-defaults"], extra_env={"FLASKENV": "development"})
    ok("Default data up to date")


def cmd_deploy() -> None:
    cmd_start_prod()


def cmd_db() -> None:
    """flask db [upgrade|downgrade|migrate …]  — defaults to upgrade."""
    _check_venv()
    sub = sys.argv[2:] if len(sys.argv) > 2 else ["upgrade"]
    run([FLASK, "db"] + sub, extra_env={"FLASKENV": "development"})
    ok(f"flask db {' '.join(sub)} done")


def cmd_db_init() -> None:
    _check_venv()
    header("Initialising database (tables + admin user)")
    run([PYTHON, "app.py", "-i"], extra_env={"FLASKENV": "development"})
    ok("Done")


def cmd_db_reload() -> None:
    _check_venv()
    header("Reloading database (DROP + recreate)")
    print("\033[1;31m  WARNING: This will wipe ALL data.\033[0m")
    if not _confirm("Are you sure you want to wipe and recreate the database?"):
        info("Cancelled.")
        return
    run([PYTHON, "app.py", "-r"], extra_env={"FLASKENV": "development"})
    ok("Database reloaded")


# ── Entry point ───────────────────────────────────────────────────────────────

COMMANDS: dict[str, object] = {
    "init":       cmd_init,
    "start":      cmd_start,
    "start-prod": cmd_start_prod,
    "test":       cmd_test,
    "update":     cmd_update,
    "backup":     cmd_backup,
    "restore":    cmd_restore,
    "deploy":     cmd_deploy,
    "db":         cmd_db,
    "db-init":    cmd_db_init,
    "db-reload":  cmd_db_reload,
    "help":       cmd_help,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        cmd_help()
        sys.exit(0)
    try:
        COMMANDS[sys.argv[1]]()
    except KeyboardInterrupt:
        print("\n\033[0;37m  · Stopped.\033[0m")
        sys.exit(0)


if __name__ == "__main__":
    main()
