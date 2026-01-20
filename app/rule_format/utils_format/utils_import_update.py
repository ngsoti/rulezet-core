#---------------------------------------------------------------------------------------For_all_rules_types----------------------------------------------------------------------------------------------------------#

import os
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
  

def clone_or_access_repo(repo_url):
    """Clone or access the repository from a GitHub URL without asking for credentials."""
    base_dir = "app/rule_from_github/Rules_Github"
    os.makedirs(base_dir, exist_ok=True)

    repo_name = get_repo_name_from_url(repo_url)
    repo_dir = os.path.join(base_dir, repo_name)
    
    existe = os.path.exists(repo_dir)
    if not existe:
        status , msg = is_github_repo_accessible(repo_url)
        if not status:
            raise Exception(f"The repo {repo_url} is not accessible : {msg}")
        
        try:
            Repo.clone_from(repo_url, repo_dir)
        except Exception as e:
            raise Exception(f"Eror during the clone of the repo : {str(e)}")

    return repo_dir, existe


def is_github_repo_accessible(repo_url):
    """Verify if a GitHub repository is public and accessible."""
    try:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").replace(".git", "")
        api_url = f"https://api.github.com/repos/{path}"

        response = requests.get(api_url, timeout=5)

        # A status code of 200 indicates the repository is accessible
        return response.status_code == 200 , ""
    except Exception as e:
        return False , response.text

def delete_existing_repo_folder(local_dir):
    """Delete the existing folder if it exists."""
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)
        return True
    else:
        return False

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
            print("Invalid scheme")
            return False
        if parsed.netloc != "github.com":
            print("Invalid netloc")
            return False
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) < 2:
            print("Invalid path")
            return False
        return True
    except Exception as e:
        print(e)
        return False

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

    form_dict['author'] = current_user.first_name + " " + current_user.last_name

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
