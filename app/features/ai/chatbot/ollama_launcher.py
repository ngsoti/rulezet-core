"""Best-effort auto-start for the local Ollama server the chatbot talks to.

Mirrors how the background job worker auto-starts alongside the app
(app/__init__.py) — same idea here: if Ollama is already running (e.g. as a
systemd service after `curl -fsSL https://ollama.com/install.sh | sh`), do
nothing. If it isn't, and the `ollama` binary is actually installed, spawn
`ollama serve` as a detached background process so the dev server doesn't
need a second terminal running it. If the binary isn't installed at all,
this stays silent — the chatbot will just report a clear connection error
when someone actually tries to use it, same as before this existed.
"""

import shutil
import subprocess

import requests as http_requests


def ensure_ollama_running(base_url: str = 'http://localhost:11434') -> None:
    try:
        http_requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=1)
        return  # already up
    except http_requests.RequestException:
        pass

    ollama_bin = shutil.which('ollama')
    if not ollama_bin:
        print("[chatbot] 'ollama' isn't installed — the chat widget will report a "
              "connection error until you install it (see docs/releases or ask the assistant).")
        return

    try:
        subprocess.Popen(
            [ollama_bin, 'serve'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        print("[chatbot] Started 'ollama serve' in the background.")
    except OSError as e:
        print(f"[chatbot] Failed to start 'ollama serve' automatically: {e}")
