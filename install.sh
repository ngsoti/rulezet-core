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

chmod +x ./launch.sh

. env/bin/activate

echo -e "${GREEN}🎮 Launch the application...${RESET}"
./launch.sh -i
