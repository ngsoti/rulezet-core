#!/bin/bash

# Couleurs
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RESET="\033[0m"

echo -e "${CYAN}🔧 Installation de python3.12-venv...${RESET}"
sudo apt install -y python3.12-venv

echo -e "${CYAN}🐍 Création de l'environnement virtuel...${RESET}"
python3 -m venv env

echo -e "${CYAN}✅ Activation de l'environnement virtuel...${RESET}"
. env/bin/activate

echo -e "${CYAN}📦 Installation des dépendances Python...${RESET}"
pip install -r requirements.txt

echo -e "${CYAN}🐘 Installation de PostgreSQL via le script dédié...${RESET}"
./install_postgresql.sh

echo -e "${CYAN}🚀 Rend le script de lancement exécutable...${RESET}"
chmod +x ./launch.sh

. env/bin/activate

echo -e "${GREEN}🎮 Lancement de l'application...${RESET}"
./launch.sh -i
