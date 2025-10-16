#---------------------------------------------------------------------------------------For_all_rules_types----------------------------------------------------------------------------------------------------------#

import os
import re
import shutil
from urllib.parse import urlparse
from flask_login import current_user
import datetime
from git import Repo
from urllib.parse import urlparse
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
    repo_name=repo_name+".git"
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
        return True
    else:
        return False


def clean_rule_filename_Yara_v2(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

    match = re.search(r'\brule\s+(\w+)\s*{', content)
    if match:
        return match.group(1)

    return os.path.splitext(os.path.basename(filepath))[0]


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



def get_github_repo_author(repo_url , license_from_github):
    # Extraire owner et repo depuis l’URL
    parts = repo_url.rstrip(".git").split("/")
    owner, repo = parts[-2], parts[-1]

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        return {
            "author": data.get("owner", {}).get("login"),
            "repo_url": repo_url,
            "html_url": data.get("owner", {}).get("html_url"),
            "description": data.get("description"),
            "created_at": data.get("created_at"),
            "license_from_github": license_from_github
        }
    else:
        return {"error": f"Failed to fetch repo info (status: {response.status_code})" ,"repo_url": repo_url,}



#################
#   GITHUB API  #
#################

def github_repo_to_api_url(git_url: str) -> str:
    """Get the url to speak with the github api"""
    if git_url.endswith(".git"):
        git_url = git_url[:-4]

    parts = git_url.rstrip("/").split("/")

    owner = parts[-2]
    repo = parts[-1]

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    return api_url

def extract_github_repo_metadata(data: dict, selected_license: str) -> dict:
    """
    Extract useful metadata from a GitHub repository API response.
    
    Args:
        data (dict): JSON response from GitHub's repo API.
    
    Returns:
        dict: Simplified metadata about the repository.
    """
    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "full_name": data.get("full_name"),
        "private": data.get("private", False),
        "author": data.get("owner", {}).get("login"),
        "author_url": data.get("owner", {}).get("html_url"),
        "author_avatar": data.get("owner", {}).get("avatar_url"),
        "repo_url": data.get("html_url"),
        "api_url": data.get("url"),
        "description": data.get("description"),
        "homepage": data.get("homepage"),
        "language": data.get("language"),
        "topics": data.get("topics", []),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "pushed_at": data.get("pushed_at"),
        "license": (
            data.get("license", {}).get("spdx_id")
            if data.get("license")
            else selected_license
        ),
        "license_name": (
            data.get("license", {}).get("name")
            if data.get("license")
            else selected_license
        ),
        "stars": data.get("stargazers_count", 0),
        "watchers": data.get("watchers_count", 0),
        "forks": data.get("forks_count", 0),
        "open_issues": data.get("open_issues_count", 0),
        "default_branch": data.get("default_branch"),
        "visibility": data.get("visibility"),
        "archived": data.get("archived", False),
        "disabled": data.get("disabled", False),
    }


def github_repo_metadata(repo_url: str, selected_license: str) -> dict:
    """
    Fetch metadata of a GitHub repository from its clone URL.
    
    Args:
        repo_url (str): GitHub repo URL (https://github.com/... or ending with .git)
    
    Returns:
        dict: Extracted repository metadata.
    """
    # --- Build API URL ---
    api_url = github_repo_to_api_url(repo_url)

    # --- Call GitHub API ---
    response = requests.get(api_url)
    response.raise_for_status()  # raise exception if request failed
    data = response.json()

    # --- Extract metadata ---
    return extract_github_repo_metadata(data , selected_license)



def valider_repo_github(repo_url: str) -> bool:
    """
    Vérifie qu'une chaîne est bien une URL de dépôt GitHub valide.
    """
    try:
        parsed = urlparse(repo_url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc != "github.com":
            return False
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) < 2:
            return False
        return True
    except Exception:
        return False


###############
#   License   #
###############

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

def get_licst_license() -> list:
    licenses = []
    with open("app/rule/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                licenses.append(line)
    return licenses

import subprocess

def git_pull_repo(repo_dir):
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "pull"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        return False
    

def fill_all_void_field(form_dict: dict) -> dict:
    """Fill all the void fields of a rule form with default values."""

    form_dict['author'] = getattr(current_user, "first_name", "Unknown")

    if not form_dict.get('description'):
        form_dict['description'] = "No description for the rule"

    if not form_dict.get('source'):
        first = getattr(current_user, "first_name", "")
        last = getattr(current_user, "last_name", "")
        form_dict['source'] = f"{first} {last}".strip() or "Unknown source"

    if not form_dict.get('license'):
        form_dict['license'] = "No license"

    if not form_dict.get('version'):
        form_dict['version'] = "1.0"

    if not form_dict.get('creation_date'):
        form_dict['creation_date'] = datetime.datetime.now(tz=datetime.timezone.utc),

    if not form_dict.get('cve_id'):
        form_dict['cve_id'] = "None"

    return form_dict
