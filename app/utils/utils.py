import subprocess
import os
import re
import uuid
import random
import string
import difflib
from ..db_class.db import User

def isUUID(uid):
    try:
        uuid.UUID(str(uid))
        return True
    except ValueError:
        return False

def generate_api_key(length=60):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def get_user_api(api_key):
    """Get a user by its api key"""
    return User.query.filter_by(api_key=api_key).first()

def get_user_from_api(headers):
    """Try to get bot user by matrix id. If not, get basic user"""
    if "MATRIX-ID" in headers:
        bot = User.query.filter_by(last_name="Bot", first_name="Matrix").first()
        if bot:
            if bot.api_key == headers.get("X-API-KEY"):
                user = User.query.filter_by(matrix_id=headers["MATRIX-ID"]).first()
                if user:
                    return user
    user = get_user_api(headers.get("X-API-KEY"))
    return user


def verif_api_key(headers):
    key = headers.get("X-API-KEY")
    if not key:
        return False
    user = get_user_api(key)
    return user is not None


def create_specific_dir(specific_dir):
    if not os.path.isdir(specific_dir):
        os.mkdir(specific_dir)

def form_to_dict(form):
    """Parse a form into a dict"""
    loc_dict = dict()
    for field in form._fields:
        if field == "files_upload":
            loc_dict[field] = dict()
            loc_dict[field]["data"] = form._fields[field].data
            loc_dict[field]["name"] = form._fields[field].name
        elif not field == "submit" and not field == "csrf_token":
            loc_dict[field] = form._fields[field].data
    return loc_dict


import difflib

def generate_diff_html(text_old: str, text_new: str) -> str:
    """
    Generate an HTML representation of the diff between two multi-line texts.
    Lines added are highlighted in green,
    lines removed in red,
    unchanged lines are left plain.

    Args:
        text_old (str): The original text.
        text_new (str): The modified text.

    Returns:
        str: An HTML string with colored diff.
    """
    lines_old = text_old.strip().splitlines()
    lines_new = text_new.strip().splitlines()

    diff = difflib.ndiff(lines_old, lines_new)
    html_lines = []

    for line in diff:
        if line.startswith('+ '):
            html_lines.append(f'<span style="background-color:#d4edda; display:block;">{line[2:]}</span>')
        elif line.startswith('- '):
            html_lines.append(f'<span style="background-color:#f8d7da; display:block;">{line[2:]}</span>')
        elif line.startswith('? '):
            # ignore diff hints line
            continue
        else:
            # unchanged lines
            content = line[2:] if line.startswith('  ') else line
            html_lines.append(f'<span style="display:block;">{content}</span>')

    return ''.join(html_lines)




def generate_side_by_side_diff_html(text_old: str, text_new: str) -> tuple[str, str]:
    def normalize(line):
        return line.strip()

    normalized_old = [normalize(line) for line in text_old.strip().splitlines()]
    normalized_new = [normalize(line) for line in text_new.strip().splitlines()]

    lines_old_raw = text_old.strip().splitlines()
    lines_new_raw = text_new.strip().splitlines()

    map_old = dict(zip(normalized_old, lines_old_raw))
    map_new = dict(zip(normalized_new, lines_new_raw))

    diff = difflib.ndiff(normalized_old, normalized_new)

    old_lines_html = []
    new_lines_html = []

    for line in diff:
        code = line[:2]
        content = line[2:]

        original_old = map_old.get(content, "")
        original_new = map_new.get(content, "")

        if code == '  ':  # unchanged
            old_lines_html.append(f'<div style="white-space: pre; margin:0;">{original_old}</div>')
            new_lines_html.append(f'<div style="white-space: pre; margin:0;">{original_new}</div>')
        elif code == '- ':  # removed from old
            if content not in normalized_new:
                old_lines_html.append(f'<div style="background-color:#f8d7da; white-space: pre; margin:0;" class="red">{original_old}</div>')
                new_lines_html.append('<div style="white-space: pre; margin:0;"></div>')
        elif code == '+ ':  # added in new
            if content not in normalized_old:
                old_lines_html.append('<div style="white-space: pre; margin:0;"></div>')
                new_lines_html.append(f'<div style="background-color:#d4edda; white-space: pre; margin:0;" class="green" >{original_new}</div>')
        elif code == '? ':
            continue

    return ''.join(old_lines_html), ''.join(new_lines_html)


def detect_cve(text):
    """
    Detect various types of vulnerability identifiers in the given text.
    Returns a tuple: (True, list_of_matches) if any found, otherwise (False, []).
    """

    vulnerability_patterns = re.compile(
        r"\b(CVE[-\s]\d{4}[-\s]\d{4,7})\b"                  # CVE pattern
        r"|\b(GCVE-\d+-\d{4}-\d+)\b"                        # GCVE pattern
        r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
        r"|\b(PYSEC-\d{4}-\d{2,5})\b"                       # PYSEC pattern
        r"|\b(GSD-\d{4}-\d{4,5})\b"                         # GSD pattern
        r"|\b(wid-sec-w-\d{4}-\d{4})\b"                     # CERT-Bund pattern
        r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"               # Cisco pattern
        r"|\b(RHSA-\d{4}:\d{4})\b"                          # RedHat pattern
        r"|\b(msrc_CVE-\d{4}-\d{4,})\b"                     # MSRC CVE pattern
        r"|\b(CERTFR-\d{4}-[A-Z]{3}-\d{3})\b",              # CERT-FR pattern
        re.IGNORECASE,
    )

    matches = re.findall(vulnerability_patterns, text)

    # Flatten the list of tuples into a list of non-empty matches
    all_matches = [match for group in matches for match in group if match]

    if all_matches:
        return True, all_matches
    else:
        return False, ""

def update_or_clone_repo(repo_url: str) -> str | None:
    """
    Clone or update a GitHub repo into Rules_Github/<owner>/<repo>.
    Returns the local repo path on success, or None on error.
    """
    try:
        parts = repo_url.rstrip("/").replace(".git", "").split("/")
        owner, repo = parts[-2], parts[-1]
    except Exception:
        print("Invalid repo URL format.")
        return None

    base_dir = "Rules_Github"
    local_repo_path = os.path.join(base_dir, owner, repo)

    try:
        if not os.path.exists(local_repo_path):
            os.makedirs(os.path.join(base_dir, owner), exist_ok=True)
            subprocess.run(["git", "clone", repo_url, local_repo_path], check=True)
        else:
            subprocess.run(["git", "-C", local_repo_path, "pull"], check=True)
    except Exception as e:
        print(f"Git error: {e}")
        return None

    return local_repo_path

def bump_version(version: str) -> str:
    """
    Smartly increments a version string:
    - If it's float-like ("1", "1.0", "2.5"), increments the decimal part.
    - If it's semver-like ("1.0.0", "2.3.4"), increments the last segment.
    - If format is unknown, returns the original version unchanged.
    """
    version = version.strip()

    try:
        val = float(version)
        return str(round(val + 0.1, 1))
    except ValueError:
        pass

    if re.match(r'^\d+(\.\d+)*$', version):
        parts = version.split(".")
        parts[-1] = str(int(parts[-1]) + 1) 
        return ".".join(parts)

    return version

def get_version():
    version_file = os.path.join(os.getcwd(), "version")
    with open(version_file, "r") as f:
        return f.readline().strip()