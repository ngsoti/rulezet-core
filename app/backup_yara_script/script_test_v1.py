import uuid
import datetime
import os

from flask_login import current_user

from app import db
from app.rule.rule_core import add_rule_core 

# Fonction pour analyser le fichier YARA et ajouter la règle
def parse_yara_rule():
    file_path = 'app/test.yar' 
    with open(file_path, 'r') as file:
        content = file.read()


    title = "Untitled"
    description = ""
    license = "Unknown"
    source_url = file_path 


    lines = content.splitlines()

    for line in lines:
        line = line.strip()
        

        if line.startswith("rule "):
            title = line.split("rule")[1].split("{")[0].strip()
        

        elif "description" in line:
            description = line.split("=")[-1].strip(' "')
        

        elif "license" in line:
            license = line.split("=")[-1].strip(' "')

    # Créer un dictionnaire de la règle
    rule_dict = {
        "format": "YARA",  
        "title": title, 
        "license": license or "Unknown", 
        "description": description or "Imported YARA rule",  
        "source": source_url,
        "author": current_user 
    }

    try:
        add_rule_core(rule_dict)  
    except Exception as e:
        print(f"Erreur lors de l'ajout de la règle '{title}': {e}")

