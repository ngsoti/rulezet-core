#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' 

echo -e "${YELLOW}--- Starting Update Process ---${NC}"

# 1. BACKUP
echo -e "\n${YELLOW}[1/6] Running Backup...${NC}"
if bash backup/scripts/backup_rulezet.sh; then
    echo -e "${GREEN}✔ Backup completed successfully.${NC}"
else
    echo -e "${RED}✘ Backup failed! Stopping update for safety.${NC}"
    exit 1
fi

# 2. GIT PULL
echo -e "\n${YELLOW}[2/6] Pulling latest changes from Git...${NC}"
if git pull; then
    echo -e "${GREEN}✔ Git pull successful.${NC}"
else
    echo -e "${RED}✘ Git pull failed! Check your internet connection or conflicts.${NC}"
    exit 1
fi

# 3. DATABASE UPGRADE
echo -e "\n${YELLOW}[3/6] Upgrading Database...${NC}"
 export FLASKENV=development    
if flask db upgrade; then
    echo -e "${GREEN}✔ Database upgrade successful.${NC}"
else
    echo -e "${RED}✘ Database upgrade failed! See errors above.${NC}"
    exit 1
fi

# 3.1 SUBMODULES UPDATE
echo -e "\n${YELLOW}Updating Git submodules...${NC}"
# Update all submodules except cti (too large for --remote; cti data is refreshed via the admin UI)
git submodule update --remote app/modules/rulezet-cast app/modules/pivotick app/modules/misp-taxonomies app/modules/misp-galaxy 2>/dev/null || git submodule update --remote
# Update cti with shallow fetch to keep the footprint small
echo -e "${YELLOW}Pulling latest MITRE CTI data (shallow)...${NC}"
git submodule update --remote --depth 1 app/modules/cti 2>/dev/null && \
    echo -e "${GREEN}✔ CTI data updated.${NC}" || \
    echo -e "${RED}⚠ CTI update skipped (no network or submodule not initialised).${NC}"

# 4. REQUIREMENTS CHECK
echo -e "\n${YELLOW}[4/6] Checking and installing requirements...${NC}"
if [ -f "requirements.txt" ]; then
    # Install what's in requirements.txt
    if pip install -r requirements.txt; then
        echo -e "${GREEN}✔ Requirements installed.${NC}"
    else
        echo -e "${RED}✘ Error during pip install -r requirements.txt${NC}"
        exit 1
    fi
    
    # Check for missing dependencies in the whole project
    echo -e "${YELLOW}Searching for missing libraries in project...${NC}"
    # 'pip check' verifies if installed packages have compatible dependencies
    if pip check; then
        echo -e "${GREEN}✔ No dependency conflicts found.${NC}"
    else
        echo -e "${RED}⚠ Dependency conflicts or missing packages detected!${NC}"
        # We don't exit here as pip check is often strict, but we warn the user.
    fi
else
    echo -e "${RED}✘ requirements.txt not found! Skipping installation.${NC}"
fi

# 5. OLLAMA (powers the in-app chat assistant prototype — optional, never blocks the update)
#
# Pinned, not "latest": 0.32.1+ segfaults on every model on Intel Sapphire
# Rapids Xeons (e.g. Xeon Silver 4410Y) — its AMX-aware CPU inference path
# crashes on this CPU generation even with OLLAMA_LLM_LIBRARY=cpu forced and
# a from-scratch reinstall/re-pulled model. 0.5.7 predates that code path
# (falls back to a plain avx2 runner) and was confirmed working. Bump this
# only after confirming a newer release fixes the Sapphire Rapids crash.
OLLAMA_VERSION="0.5.7"
echo -e "\n${YELLOW}[5/6] Checking for Ollama ${OLLAMA_VERSION} (used by the chat assistant)...${NC}"
if command -v ollama >/dev/null 2>&1 && ollama --version 2>/dev/null | grep -q "$OLLAMA_VERSION"; then
    echo -e "${GREEN}✔ Ollama ${OLLAMA_VERSION} is already installed.${NC}"
else
    if command -v ollama >/dev/null 2>&1; then
        echo -e "${YELLOW}Ollama is installed but not pinned version ${OLLAMA_VERSION} — reinstalling the pinned version (this may prompt for your sudo password)...${NC}"
    else
        echo -e "${YELLOW}Ollama not found — installing ${OLLAMA_VERSION} (this may prompt for your sudo password)...${NC}"
    fi
    if curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION="$OLLAMA_VERSION" sh; then
        echo -e "${GREEN}✔ Ollama ${OLLAMA_VERSION} installed.${NC}"
    else
        echo -e "${RED}⚠ Ollama installation failed or was skipped — the chat assistant will report a connection error until it's installed manually (curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION=${OLLAMA_VERSION} sh).${NC}"
    fi
fi
if command -v ollama >/dev/null 2>&1 && ! ollama list 2>/dev/null | grep -q '^qwen2.5:1.5b'; then
    echo -e "${YELLOW}Pulling the qwen2.5:1.5b model (used by the chat assistant)...${NC}"
    ollama pull qwen2.5:1.5b || echo -e "${RED}⚠ Could not pull qwen2.5:1.5b — run 'ollama pull qwen2.5:1.5b' manually.${NC}"
fi

# 6. LAUNCH
echo -e "\n${YELLOW}[6/6] Everything looks good. Launching...${NC}"
echo -e "${GREEN}Ready to start the engine.${NC}"
bash launch.sh -l