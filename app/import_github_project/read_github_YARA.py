import os
import git



# === Git & Parsing Functions ===

def clone_or_access_repo(repo_url, local_dir):
    """Clone or access a Git repository."""
    if not os.path.exists(local_dir):
        repo = git.Repo.clone_from(repo_url, local_dir)
    else:
        print("Repository already cloned. Accessing local directory.")
        repo = git.Repo(local_dir)
    return repo

def get_yara_files_from_repo(repo_dir):
    """Retrieve all .yar and .yara files from a local repository."""
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yar', '.yara')):
                yara_files.append(os.path.join(root, file))
    return yara_files

def parse_yara_rule(file_path):
    """Read and parse a YARA rule from a file."""
    with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
        content = file.read()

    title = "Untitled"
    description = ""
    license = "Unknown"
    source_url = file_path

    for line in content.splitlines():
        line = line.strip() # remove the uselss
        if line.startswith("rule "):
            title = line.split("rule")[1].split("{")[0].strip()
        elif "description" in line:
            description = line.split("=")[-1].strip(' "')
        elif "license" in line:
            license = line.split("=")[-1].strip(' "')

    return {
        "format": "YARA",
        "title": title,
        "license": license or "Unknown",
        "description": description or "Imported YARA rule",
        "source": source_url,
        "version": "1.0",
        "author": "script"  # or "admin" or another default
    }
