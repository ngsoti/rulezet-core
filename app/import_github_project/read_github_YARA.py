import os
from git import Repo

def clone_or_access_repo(repo_url, local_dir):
    """Cloner ou accéder à un dépôt Git."""
    if not os.path.exists(local_dir):
        repo = Repo.clone_from(repo_url, local_dir)
    else:
        repo = Repo(local_dir)  # Accède à un dépôt déjà existant
    return repo


def get_yara_files_from_repo(repo_dir):
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):  # Parcours le répertoire
        for file in files:
            if file.endswith('.yar'):
                yara_files.append(os.path.join(root, file))  # Ajoute le chemin complet du fichier
    return yara_files

def parse_yara_rule(file_path):
    """Lire et analyser une règle YARA depuis un fichier."""
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

    rule_dict = {
        "format": "YARA",  
        "title": title, 
        "license": license or "Unknown", 
        "description": description or "Imported YARA rule",  
        "source": source_url,
        "author": "unknown"  
    }

    return rule_dict
