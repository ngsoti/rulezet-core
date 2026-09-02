#---------------------------------------------------------------------------------------For_all_rules_types----------------------------------------------------------------------------------------------------------#

import os
import shutil
import subprocess
from urllib.parse import urlparse
from flask_login import current_user
import datetime

from urllib.parse import urlparse
from git import Repo
import requests


def _github_auth_headers() -> dict:
    """Authorization header for GitHub API calls, if GITHUB_TOKEN is configured.
    Unauthenticated calls are capped at 60 req/hour by GitHub and start failing
    under normal admin usage (repeated imports/branch checks/metadata lookups)."""
    token = os.environ.get('GITHUB_TOKEN')
    return {'Authorization': f'Bearer {token}'} if token else {}


def get_github_host() -> str:
    """Hostname that rule-import features treat as "GitHub" — github.com by
    default, or a self-hosted GitHub Enterprise Server / offline mirror when
    GITHUB_HOST is configured (Admin -> Server Settings -> Security)."""
    host = os.environ.get('GITHUB_HOST', 'github.com').strip().strip('/')
    return host or 'github.com'


def get_github_api_base() -> str:
    """Base URL for GitHub REST API calls, matching get_github_host().

    github.com is served from the separate api.github.com host; a GitHub
    Enterprise Server instance (or compatible offline mirror) serves its API
    from the same host under /api/v3, per GitHub's own documentation."""
    host = get_github_host()
    if host == 'github.com':
        return 'https://api.github.com'
    return f'https://{host}/api/v3'

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
  

def clone_or_access_repo(repo_url, branch=None):
    """Clone or access the repository from a GitHub URL.

    If *branch* is specified the repo is cloned on that branch and cached in a
    separate directory so it does not collide with the default-branch clone.
    """
    base_dir = "app/rule_from_github/Rules_Github"
    os.makedirs(base_dir, exist_ok=True)

    repo_name = get_repo_name_from_url(repo_url)
    # Use a branch-specific subfolder so different branches don't overwrite each other
    dir_suffix = f"--{branch}" if branch else ""
    repo_dir = os.path.join(base_dir, repo_name + dir_suffix)

    existe = os.path.exists(repo_dir)
    if not existe:
        status, msg = is_github_repo_accessible(repo_url)
        if not status:
            raise Exception(f"The repo {repo_url} is not accessible: {msg}")
        try:
            kwargs = {"branch": branch, "depth": 1} if branch else {"depth": 1}
            Repo.clone_from(repo_url, repo_dir, **kwargs)
        except Exception as e:
            # Remove the partially-created directory so a retry starts fresh
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir, ignore_errors=True)
            err = str(e)
            if branch and ("Remote branch" in err and "not found" in err or
                           "not found in upstream" in err):
                raise Exception(f"Branch '{branch}' does not exist in this repository.")
            if "Repository not found" in err or "not found" in err.lower():
                raise Exception("Repository not found or not accessible. Check the URL.")
            if "Authentication failed" in err:
                raise Exception("Authentication failed — the repository may be private.")
            raise Exception(f"Clone failed: {err.split('stderr:')[-1].strip()[:200]}")
    else:
        # Repo already cached — make sure we are on the right branch and up-to-date
        if branch:
            try:
                repo = Repo(repo_dir)
                repo.git.checkout(branch)
                repo.remotes.origin.pull()
            except Exception as e:
                err = str(e)
                if "did not match any" in err or "pathspec" in err or "not found" in err.lower():
                    raise Exception(f"Branch '{branch}' does not exist in this repository.")
                raise Exception(f"Error switching to branch '{branch}': {err.split('stderr:')[-1].strip()[:200]}")

    return repo_dir, existe


def is_github_repo_accessible(repo_url):
    """Verify if a GitHub repository is public and accessible."""
    try:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").replace(".git", "")
        api_url = f"{get_github_api_base()}/repos/{path}"

        response = requests.get(api_url, headers=_github_auth_headers(), timeout=5)

        # A status code of 200 indicates the repository is accessible
        return response.status_code == 200 , "" if response.status_code == 200 else response.text
    except Exception as e:
        return False , str(e)

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

def get_github_branches(repo_url: str) -> tuple[list[str], str | None]:
    """Return (branch_names, error_message) for a GitHub repository.

    error_message is None on success, a string on failure.
    """
    import os
    clean = repo_url.rstrip('/')
    if clean.endswith('.git'):
        clean = clean[:-4]
    repo_name = get_repo_name_from_url(clean)
    if not repo_name:
        return [], "Could not parse repository name from URL."
    api_url = f"{get_github_api_base()}/repos/{repo_name}/branches?per_page=100"
    headers = {}
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        res = requests.get(api_url, headers=headers, timeout=8)
        if res.status_code == 401 and token:
            from app.features.notification.notification_core import notify_admins_github_token_invalid
            notify_admins_github_token_invalid(
                'The configured GITHUB_TOKEN was rejected (401 Bad credentials) while fetching '
                'branches for a GitHub import. GitHub-backed features are down until it is replaced.'
            )
            return [], "GITHUB_TOKEN is invalid or expired — all admins have been alerted."
        if res.status_code == 403:
            return [], "GitHub API rate limit exceeded. Add a GITHUB_TOKEN to .env to increase the limit."
        if res.status_code == 404:
            return [], "Repository not found or is private."
        if res.status_code != 200:
            return [], f"GitHub API returned status {res.status_code}."
        return [b['name'] for b in res.json()], None
    except Exception as exc:
        return [], f"Network error: {exc}"


def github_repo_to_api_url(git_url: str) -> str:
    """Get the url to speak with the github api"""
    if git_url.endswith(".git"):
        git_url = git_url[:-4]

    parts = git_url.rstrip("/").split("/")

    owner = parts[-2]
    repo = parts[-1]

    api_url = f"{get_github_api_base()}/repos/{owner}/{repo}"
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
    response = requests.get(api_url, headers=_github_auth_headers(), timeout=8)
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
        if parsed.netloc != get_github_host():
            return False
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) < 2:
            return False
        return True
    except Exception as e:
        return False

def get_licst_license() -> list:
    licenses = []
    with open("app/features/rule/utils/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                licenses.append(line)
    return licenses

def git_pull_repo(repo_dir):
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "pull"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=120,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def get_repo_head_sha(repo_dir):
    """Current HEAD commit SHA of a local clone, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
            timeout=10,
        )
        return result.stdout.strip() or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def get_changed_files_between(repo_dir, sha_before, sha_after):
    """Repo-relative paths that changed between two commits, or None if the diff
    can't be computed (e.g. sha_before fell out of a shallow clone's history) —
    callers should treat None as "diff unknown, re-check everything"."""
    if not sha_before or not sha_after or sha_before == sha_after:
        return set()
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "diff", "--name-only", sha_before, sha_after],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
            timeout=15,
        )
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None



def fill_all_void_field(form_dict: dict) -> dict:
    """Fill all the void fields of a rule form with default values."""

    if not form_dict.get('author'):
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
