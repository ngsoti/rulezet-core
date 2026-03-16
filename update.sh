#!/bin/bash

# Couleurs pour la lisibilité
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}--- Starting Update Process ---${NC}"

# 1. BACKUP
echo -e "\n${YELLOW}[1/5] Running Backup...${NC}"
if bash backup/scripts/backup_rulezet.sh; then
    echo -e "${GREEN}✔ Backup completed successfully.${NC}"
else
    echo -e "${RED}✘ Backup failed! Stopping update for safety.${NC}"
    exit 1
fi

# 2. GIT PULL
echo -e "\n${YELLOW}[2/5] Pulling latest changes from Git...${NC}"
if git pull; then
    echo -e "${GREEN}✔ Git pull successful.${NC}"
else
    echo -e "${RED}✘ Git pull failed! Check your internet connection or conflicts.${NC}"
    exit 1
fi

# 3. DATABASE UPGRADE
echo -e "\n${YELLOW}[3/5] Upgrading Database...${NC}"
export FLASK_ENV=development # Note: common typo fix, usually FLASK_ENV
if flask db upgrade; then
    echo -e "${GREEN}✔ Database upgrade successful.${NC}"
else
    echo -e "${RED}✘ Database upgrade failed! See errors above.${NC}"
    exit 1
fi

# 4. REQUIREMENTS CHECK
echo -e "\n${YELLOW}[4/5] Checking and installing requirements...${NC}"
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

# 5. LAUNCH
echo -e "\n${YELLOW}[5/5] Everything looks good. Launching...${NC}"
echo -e "${GREEN}Ready to start the engine.${NC}"
bash launch.sh -l