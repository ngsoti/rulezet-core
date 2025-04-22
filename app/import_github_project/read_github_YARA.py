import asyncio
import os
import shutil
import git
import hashlib
import re
from git import Repo
import tempfile


def get_repo_name_from_url(repo_url):
    """Extract the repository name from its Git URL."""
    # delete the last /  if there is and we split with /  the different part of the url to take the last ( the titile ) "https://github.com/user/repo" → ["https:", "", "github.com", "user", "repo"]
    name = repo_url.rstrip('/').split('/')[-1]
    # in many case there is .hit juste after the title 
    if name.endswith('.git'):
        name = name[:-4] #remove the 4 last letter .git to have the complete title
    return name
    
    # get_repo_name_from_url("https://github.com/user/mon-depot.git")
    # Résultat : "mon-depot"

    # get_repo_name_from_url("https://github.com/user/mon-depot/")
    # Résultat : "mon-depot"



def clone_or_access_repo(repo_url):
    """Clone or acces the repository from Git URL."""
    # folder racine to git clone
    base_dir = "Rules_Github"
    os.makedirs(base_dir, exist_ok=True) # create the folder if not exist

    #take the repo name 
    repo_name = get_repo_name_from_url(repo_url)
    # repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')

    # build the complete path 
    repo_dir = os.path.join(base_dir, repo_name)

    if not os.path.exists(repo_dir):
        Repo.clone_from(repo_url, repo_dir)
    else:
        pass

    return repo_dir



# Keep it 
def get_yara_files_from_repo(repo_dir):
    """Retrieve all .yar , rule and .yara files from a local repository."""
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yar', '.yara', '.rule')):
                yara_files.append(os.path.join(root, file))
    return yara_files

# Keep it 
def load_known_licenses(license_file_path="app/rule/import_licenses/licenses.txt"):
    """load all the licenses in  licenses.txt."""
    with open(license_file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]




def save_yara_rules_as_is(repo_url, output_dir="app/rule/output_rules"):
    """
    Retrieve all YARA rules from a Git repository and save each rule exactly as it is
    without any modification.
    Each rule is saved in a file named after the rule's title.
    """
    
    repo_dir = clone_or_access_repo(repo_url)
    yara_files = get_yara_files_from_repo(repo_dir)

    os.makedirs(output_dir, exist_ok=True)

    for yara_file in yara_files:
        with open(yara_file, 'r', encoding="utf-8", errors="ignore") as file:
            raw_content = file.read()

        rule_title_final = ""
        rule_title = re.match(r'rule\s+([^\s{]+)', raw_content)
        rule_title_with_error_match = re.search(r'\brule\s*:?\s*([^\s{]+)', raw_content)


        if rule_title:
            rule_title_final = rule_title.group(1).strip()

        elif rule_title_with_error_match:
            rule_title_final = rule_title_with_error_match.group(1).strip()
        else:
            rule_title_final = "Untitled"

        file_name = f"{rule_title_final}.yar"
        file_path = os.path.join(output_dir, file_name)

        with open(file_path, 'w', encoding="utf-8") as output_file:
            output_file.write(raw_content)





def delete_existing_repo_folder(local_dir):
    """Delete the existing folder if it exists."""
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)



# def parse_yara_rule(file_path, repo_dir=None, repo_url=None, known_licenses=None, branch="main"):
#     """
#     Read and parse a YARA rule from a file, try to detect metadata and GitHub URL for the rule.
#     """
#     if known_licenses is None:
#         known_licenses = load_known_licenses()


    
#     # Read the file content
#     with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
#         raw_content = file.read()

#     cleaned_content = re.sub(r'/\*.*?\*/', '', raw_content, flags=re.DOTALL)
#     lines = cleaned_content.splitlines()

#     # Default metadata
#     title = "Untitled"
#     description = "Imported YARA rule"
#     license = "Unknown"
#     author = "Unknown"

#     # Extract metadata from rule content
#     for line in lines:
#         line = line.strip()
#         if line.lower().startswith("rule "):
#             title_match = re.match(r'rule\s+([^\s{]+)', line, re.IGNORECASE)
#             if title_match:
#                 title = title_match.group(1).strip()
#         elif line.lower().startswith("description"):
#             description = line.split("=", 1)[-1].strip().strip(' "')
#         elif line.lower().startswith("license"):
#             license = line.split("=", 1)[-1].strip().strip(' "')
#         elif line.lower().startswith("author"):
#             author = line.split("=", 1)[-1].strip().strip(' "')

#     # Build GitHub URL if possible
#     source_url = file_path
#     if repo_dir and repo_url and "github.com" in repo_url:
#         relative_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")
#         if repo_url.endswith(".git"):
#             repo_url = repo_url[:-4]

#         # Construct GitHub URL for the file
#         source_url = f"https://github.com/{'/'.join(repo_url.split('/')[-2:])}/blob/{branch}/{relative_path}"

#         # save a rule into a file to download it later
#         save_yara_rules_as_is(repo_url)
#     return {
#         "format": "YARA",
#         "title": title,
#         "license": license or "Unknown",
#         "description": description,
#         "source": source_url,
#         "version": "1.0",
#         "author": author or "Unknown"
#     }




def parse_yara_rule(file_path, repo_dir=None, repo_url=None, known_licenses=None, branch="main"):
    """
    Read and parse a YARA rule from a file, try to detect metadata and GitHub URL for the rule.
    Also return the full raw rule content in 'maRegle'.
    """
    if known_licenses is None:
        known_licenses = load_known_licenses()

    # Read the file content
    with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
        raw_content = file.read() 

    cleaned_content = re.sub(r'/\*.*?\*/', '', raw_content, flags=re.DOTALL)
    lines = cleaned_content.splitlines()

    # Default metadata
    title = "Untitled"
    description = "Imported YARA rule"
    license = "Unknown"
    author = "Unknown"

    # Extract metadata from rule content
    for line in lines:
        line = line.strip()

        # Traitement du titre de la règle avec "rule" ou "rule:"
        if line.lower().startswith("rule "):
            title_match = re.match(r'^\s*rule\s+([^\s{]+)', line, re.IGNORECASE)  # Gestion de "rule nom {"
            if title_match:
                title = title_match.group(1).strip()
        elif line.lower().startswith("rule:"):  # Nouveau cas pour "rule: nom {"
            title_match = re.match(r'^\s*rule\s*:?\s*([^\s{]+)', line, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()

        # Traitement de la description
        elif line.lower().startswith("description"):
            description = line.split("=", 1)[-1].strip().strip(' "')

        # Traitement de la licence
        elif line.lower().startswith("license"):
            license = line.split("=", 1)[-1].strip().strip(' "')

        # Traitement de l'auteur
        elif line.lower().startswith("author"):
            author = line.split("=", 1)[-1].strip().strip(' "')

    # Build GitHub URL if possible
    source_url = file_path
    if repo_dir and repo_url and "github.com" in repo_url:
        relative_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        # Construct GitHub URL for the file
        source_url = f"https://github.com/{'/'.join(repo_url.split('/')[-2:])}/blob/{branch}/{relative_path}"
    
    save_yara_rules_as_is(repo_url)

    return {
        "format": "YARA",
        "title": title,
        "license": license or "Unknown",
        "description": description,
        "source": source_url,
        "version": "1.0",
        "author": author or "Unknown",
        "to_string": raw_content  
    }

