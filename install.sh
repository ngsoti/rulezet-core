#!/bin/bash

# Couleurs
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RESET="\033[0m"

echo -e "${CYAN}🚀 Starting the installation process...${RESET}"

sudo apt install -y python3.12-venv
python3 -m venv env
. env/bin/activate

echo -e "${CYAN}📦 Install the Python dependencies...${RESET}"
pip install -r requirements.txt

echo -e "${CYAN}🐘 Install PostgreSQL ...${RESET}"
./install_postgresql.sh

# Ollama (powers the in-app chat assistant prototype — optional, never blocks install)
#
# Pinned, not "latest": 0.32.1+ segfaults on every model on Intel Sapphire
# Rapids Xeons (e.g. Xeon Silver 4410Y) — its AMX-aware CPU inference path
# crashes on this CPU generation even with OLLAMA_LLM_LIBRARY=cpu forced and
# a from-scratch reinstall/re-pulled model. 0.5.7 predates that code path
# (falls back to a plain avx2 runner) and was confirmed working. Bump this
# only after confirming a newer release fixes the Sapphire Rapids crash.
OLLAMA_VERSION="0.5.7"
echo -e "${CYAN}🤖 Checking for Ollama ${OLLAMA_VERSION} (used by the chat assistant)...${RESET}"
if command -v ollama >/dev/null 2>&1 && ollama --version 2>/dev/null | grep -q "$OLLAMA_VERSION"; then
    echo -e "${GREEN}✔ Ollama ${OLLAMA_VERSION} is already installed.${RESET}"
else
    if command -v ollama >/dev/null 2>&1; then
        echo -e "${CYAN}Ollama is installed but not pinned version ${OLLAMA_VERSION} — reinstalling the pinned version (this may prompt for your sudo password)...${RESET}"
    else
        echo -e "${CYAN}Ollama not found — installing ${OLLAMA_VERSION} (this may prompt for your sudo password)...${RESET}"
    fi
    if curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION="$OLLAMA_VERSION" sh; then
        echo -e "${GREEN}✔ Ollama ${OLLAMA_VERSION} installed.${RESET}"
    else
        echo -e "${CYAN}⚠ Ollama installation failed or was skipped — the chat assistant will report a connection error until it's installed manually (curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION=${OLLAMA_VERSION} sh).${RESET}"
    fi
fi
if command -v ollama >/dev/null 2>&1 && ! ollama list 2>/dev/null | grep -q '^qwen2.5:1.5b'; then
    echo -e "${CYAN}Pulling the qwen2.5:1.5b model (used by the chat assistant)...${RESET}"
    ollama pull qwen2.5:1.5b || echo -e "${CYAN}⚠ Could not pull qwen2.5:1.5b — run 'ollama pull qwen2.5:1.5b' manually.${RESET}"
fi

chmod +x ./launch.sh

# Init required git submodules
echo -e "${CYAN}📂 Initialising git submodules...${RESET}"
git submodule update --init --recursive --depth 1 app/modules/rulezet-cast
git submodule update --init --recursive --depth 1 app/modules/pivotick

# CTI submodule (mitre/cti) — large repo, only initialise if not already present
if [ ! -f "app/modules/cti/enterprise-attack/enterprise-attack.json" ]; then
    echo -e "${CYAN}🛡️  Cloning MITRE ATT&CK CTI data (shallow, may take a moment)...${RESET}"
    git submodule update --init --depth 1 app/modules/cti
else
    echo -e "${GREEN}✔ MITRE CTI submodule already present.${RESET}"
fi

. env/bin/activate

echo -e "${GREEN}🎮 Launch the application...${RESET}"
./launch.sh -i
