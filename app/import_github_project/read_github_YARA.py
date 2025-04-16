import os
import git
import hashlib
import re

# === Git & Parsing Functions ===



def get_repo_name_from_url(repo_url):
    """Extract the repository name from its Git URL."""
    name = repo_url.rstrip('/').split('/')[-1]
    if name.endswith('.git'):
        name = name[:-4]
    return name

def clone_or_access_repo(repo_url, base_dir="repos"):
    """
    Clone a Git repository into a uniquely named local directory.
    Returns the Git repo object.
    """
    os.makedirs(base_dir, exist_ok=True)

    repo_name = get_repo_name_from_url(repo_url)
    

    repo_hash = hashlib.md5(repo_url.encode()).hexdigest()[:8]
    local_dir = os.path.join(base_dir, f"{repo_name}_{repo_hash}")

    if not os.path.exists(local_dir):
        repo = git.Repo.clone_from(repo_url, local_dir)
    else:
        repo = git.Repo(local_dir)

    return repo, local_dir


def get_yara_files_from_repo(repo_dir):
    """Retrieve all .yar , rule and .yara files from a local repository."""
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yar', '.yara', '.rule')):
                yara_files.append(os.path.join(root, file))
    return yara_files



def parse_yara_rule(file_path):
    """Read and parse a YARA rule from a file, ignoring /* ... */ comments."""
    with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
        raw_content = file.read()

    cleaned_content = re.sub(r'/\*.*?\*/', '', raw_content, flags=re.DOTALL)


    lines = cleaned_content.splitlines()


    title = "Untitled"
    description = "Imported YARA rule"
    license = "Unknown"
    author = "Unknown"
    source_url = file_path

    for line in lines:
        line = line.strip()
        if line.lower().startswith("rule "):
            title_match = re.match(r'rule\s+([^\s{]+)', line, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
        elif line.lower().startswith("description"):
            description = line.split("=", 1)[-1].strip().strip(' "')
        elif line.lower().startswith("license"):
            license = line.split("=", 1)[-1].strip().strip(' "')
        elif line.lower().startswith("author"):
            author = line.split("=", 1)[-1].strip().strip(' "')


    return {
        "format": "YARA",
        "title": title,
        "license": license or "Unknown",
        "description": description,
        "source": source_url,
        "version": "1.0",
        "author": author or "Unknown"
    }
