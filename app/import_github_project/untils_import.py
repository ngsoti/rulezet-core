#---------------------------------------------------------------------------------------For_all_rules_types----------------------------------------------------------------------------------------------------------#

import os
import shutil
from urllib.parse import urlparse

from git import Repo
import requests

def get_repo_name_from_url(repo_url):
    """Extract the full repository path (owner/repo) from its Git URL."""
    parts = repo_url.rstrip('/').split('/')
    if len(parts) < 2:
        return None  # URL invalide
    owner = parts[-2]
    repo = parts[-1]
    if repo.endswith('.git'):
        repo = repo[:-4]
    return f"{owner}/{repo}"
  
    # get_repo_name_from_url("https://github.com/user/mon-depot.git")
    # result : "mon-depot"



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
    existe = True
    if not os.path.exists(repo_dir):
        existe = False
        Repo.clone_from(repo_url, repo_dir)
    else:
        pass

    return repo_dir , existe

def load_known_licenses(license_file_path="app/rule/import_licenses/licenses.txt"):
    """load all the licenses in  licenses.txt."""
    with open(license_file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def delete_existing_repo_folder(local_dir):
    """Delete the existing folder if it exists."""
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)

def clean_rule_filename_Yara(filename):
    if filename.lower().endswith(('.yar', '.yara')):
        return filename.rsplit('.', 1)[0]
    return filename

# take all the external param
def build_externals_dict(vars_list):
    externals = {}
    for var in vars_list:
        var_name = var['name']
        var_type = var['type']
        if var_type == 'int':
            externals[var_name] = 0
        elif var_type == 'bool':
            externals[var_name] = False
        elif var_type == 'bytes':
            externals[var_name] = b""
        else:
            externals[var_name] = ""
    return externals



def get_github_repo_author(repo_url):
    # Extraire owner et repo depuis l’URL
    parts = repo_url.rstrip(".git").split("/")
    owner, repo = parts[-2], parts[-1]

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        return {
            "author": data.get("owner", {}).get("login"),
            "html_url": data.get("owner", {}).get("html_url"),
            "description": data.get("description"),
            "created_at": data.get("created_at"),
        }
    else:
        return {"error": f"Failed to fetch repo info (status: {response.status_code})"}




#----------------------------------------------------------------------------------------LICENSE--------------------------------------------------------------------------------------------------------------------#

# use API GITHUB 
def extract_owner_repo(github_url):
    parsed = urlparse(github_url)
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) >= 2:
        owner = path_parts[0]
        repo = path_parts[1].replace('.git', '')  
        return owner, repo
    else:
        return None, None

def get_license_name(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/license"
    headers = {"Accept": "application/vnd.github.v3+json"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json().get('license', {}).get('name', '(Unknown license)')
    elif response.status_code == 404:
        return "(No license file found)"
    else:
        return f"(Error: {response.status_code})"

def get_license_file_from_github_repo(repo_dir):
    """Retrieve the first line of the license from a GitHub repository folder."""

    # list of differents names of license file
    possible_filenames = [
        "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE.rst",
        "COPYING", "COPYING.txt", "COPYING.md"
    ]

    for filename in possible_filenames:
        license_path = os.path.join(repo_dir, filename)
        if os.path.isfile(license_path):
            with open(license_path, 'r', encoding='utf-8') as f:
                for line in f:
                    first_line = line.strip()
                    if first_line:  # Ignore blank lines
                        return first_line
                return "(Empty license file)"
    
    return "(No license file found)"