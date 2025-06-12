import os
import re
import uuid
import random
import string
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
            if bot.api_key == headers["X-API-KEY"]:
                user = User.query.filter_by(matrix_id=headers["MATRIX-ID"]).first()
                if user:
                    return user
    return get_user_api(headers["X-API-KEY"])


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


# def generate_side_by_side_diff_html(text_old: str, text_new: str) -> tuple[str, str]:
#     """
#     Generate side-by-side diff HTML of two texts.
#     Returns a tuple (old_html, new_html) where:
#     - old_html: old content with deleted lines highlighted in red,
#     - new_html: new content with added lines highlighted in green.
#     Unchanged lines are normal.

#     Args:
#         text_old (str): original text
#         text_new (str): modified text

#     Returns:
#         tuple[str, str]: (old_html, new_html)
#     """
#     lines_old = text_old.strip().splitlines()
#     lines_new = text_new.strip().splitlines()

#     diff = difflib.ndiff(lines_old, lines_new)

#     old_lines_html = []
#     new_lines_html = []

#     for line in diff:
#         code = line[:2]
#         content = line[2:]

#         if code == '  ':  # unchanged
#             old_lines_html.append(f'<span style="display:block;">{content}</span>')
#             new_lines_html.append(f'<span style="display:block;">{content}</span>')
#         elif code == '- ':  # line removed from old
#             old_lines_html.append(f'<span style="background-color:#f8d7da; display:block;">{content}</span>')
#             new_lines_html.append('<span style="display:block;"></span>')  # empty placeholder
#         elif code == '+ ':  # line added in new
#             old_lines_html.append('<span style="display:block;"></span>')  # empty placeholder
#             new_lines_html.append(f'<span style="background-color:#d4edda; display:block;">{content}</span>')
#         elif code == '? ':  # diff hints line, ignore
#             continue

#     return ''.join(old_lines_html), ''.join(new_lines_html)

import difflib

def generate_side_by_side_diff_html(text_old: str, text_new: str) -> tuple[str, str]:
    """
    Generate side-by-side diff HTML of two texts, ignoring differences that are only whitespace.
    Returns a tuple (old_html, new_html) where:
    - old_html: old content with deleted lines highlighted in red,
    - new_html: new content with added lines highlighted in green.
    Unchanged lines are normal.

    Args:
        text_old (str): original text
        text_new (str): modified text

    Returns:
        tuple[str, str]: (old_html, new_html)
    """
    # Preprocessing: normalize whitespace by stripping and collapsing spaces
    def normalize(line):
        return line.strip()

    # Mapping from normalized line to original
    normalized_old = [normalize(line) for line in text_old.strip().splitlines()]
    normalized_new = [normalize(line) for line in text_new.strip().splitlines()]

    lines_old_raw = text_old.strip().splitlines()
    lines_new_raw = text_new.strip().splitlines()

    # Build a mapping from normalized line to full line
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
            old_lines_html.append(f'<span style="display:block;">{original_old}</span>')
            new_lines_html.append(f'<span style="display:block;">{original_new}</span>')
        elif code == '- ':  # removed from old
            if content not in normalized_new:  # ignore if only whitespace difference
                old_lines_html.append(f'<span style="background-color:#f8d7da; display:block;">{original_old}</span>')
                new_lines_html.append('<span style="display:block;"></span>')
        elif code == '+ ':  # added in new
            if content not in normalized_old:  # ignore if only whitespace difference
                old_lines_html.append('<span style="display:block;"></span>')
                new_lines_html.append(f'<span style="background-color:#d4edda; display:block;">{original_new}</span>')
        elif code == '? ':  # hint line, ignore
            continue

    return ''.join(old_lines_html), ''.join(new_lines_html)


# def detect_cve(text):
#     pattern = r'\bCVE-\d{4}-\d{4,7}\b'
#     matches = re.findall(pattern, text, re.IGNORECASE)

#     if matches:
#         return True, matches
#     else:
#         return False, []
    



import re

def detect_cve(text):
    """
    Detect various types of vulnerability identifiers in the given text.
    Returns a tuple: (True, list_of_matches) if any found, otherwise (False, []).
    """

    vulnerability_patterns = re.compile(
        r"\b(CVE-\d{4}-\d{4,7})\b"                         # CVE pattern
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
        return False, []
