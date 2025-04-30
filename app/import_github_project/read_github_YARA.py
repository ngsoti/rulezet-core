import asyncio
import json
import os
import shutil
from urllib.parse import urlparse
import git
import hashlib
import re
from git import Repo
import requests

from app.import_github_project.untils_import import clone_or_access_repo


#---------------------------------------------------------------------------------------Yara_Rules------------------------------------------------------------------------------------------------------------------#




def get_yara_files_from_repo(repo_dir):
    """Retrieve all .yar , rule and .yara files from a local repository."""
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yar', '.yara', '.rule')):
                yara_files.append(os.path.join(root, file))
    return yara_files


def count_braces_outside_strings(line):
    # Variable to track if we're inside single or double quotes
    in_single_quote = False
    in_double_quote = False
    escaped = False  # To handle escape sequences
    count = 0  # Brace counter

    for char in line:
        if escaped:
            escaped = False
            continue

        # If a backslash is found, treat the next character as escaped
        if char == "\\":
            escaped = True
            continue

        # Toggle single quote state when not inside double quotes
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
        # Toggle double quote state when not inside single quotes
        elif char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        # Count braces only if not inside quotes
        elif not in_single_quote and not in_double_quote:
            if char == "{":
                count += 1
            elif char == "}":
                count -= 1

    return count


def save_yara_rules_as_is(repo_url, output_dir="app/rule/output_rules/Yara"):
    """
    Retrieve all YARA rules from a Git repository and save each rule exactly as it is
    without any modification.
    Each rule is saved in a file named after the rule's title.
    """
    
    # Clone or access the given repository
    repo_dir = clone_or_access_repo(repo_url)
    
    # Get the list of YARA files from the repository
    yara_files = get_yara_files_from_repo(repo_dir)

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Process each YARA file
    for yara_file in yara_files:
        with open(yara_file, 'r', encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        inside_rule = False
        brace_count = 0
        current_rule_lines = []
        rule_index = 0

        # Read each line of the YARA file
        for line in lines:
            stripped = line.strip()

            # Check if the line starts a new rule
            if not inside_rule and re.match(r'^\s*rule\b', stripped):
                inside_rule = True
                brace_count = 0
                current_rule_lines = [line]

                # Count braces on the first line outside of quotes
                brace_count += count_braces_outside_strings(line)

            # Process lines inside the rule
            elif inside_rule:
                current_rule_lines.append(line)
                brace_count += count_braces_outside_strings(line)

                # If brace count reaches zero, the rule is complete
                if brace_count == 0:
                    # Join all lines of the rule
                    raw_rule = ''.join(current_rule_lines)

                    # Extract the rule title, supporting both "rule" and "rule:"
                    title_match = re.search(r'\brule\s*:?\s*([^\s{(]+)', raw_rule)
                    if title_match:
                        rule_title_final = title_match.group(1).strip()
                    else:
                        rule_title_final = f"Untitled_{rule_index}"

                    # Generate a safe file name using the rule title
                    file_name = f"{rule_title_final}.yar"
                    file_path = os.path.join(output_dir, file_name)

                    # Write the rule to a new file
                    with open(file_path, 'w', encoding="utf-8") as output_file:
                        output_file.write(raw_rule.strip())

                    rule_index += 1
                    inside_rule = False
                    current_rule_lines = []
    return repo_dir


def read_and_parse_all_yara_rules_from_folder(license_from_github,folder_path="app/rule/output_rules/Yara", repo_dir=None, repo_url=None, known_licenses=None, branch="main"):
    """
    Read all .yar files in the folder line by line, extract metadata and return a list of rules
    in JSON format (title, license, description, author, etc.).
    """

    rules_json = []

    if not os.path.isdir(folder_path):
        raise FileNotFoundError(f"Folder '{folder_path}' does not exist.")
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)

        if os.path.isfile(file_path) and filename.lower().endswith(".yar"):
            
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
                raw_content = file.read()

            cleaned_content = re.sub(r'/\*.*?\*/', '', raw_content, flags=re.DOTALL)
            lines = cleaned_content.splitlines()

            # Default metadata
            title = "Untitled"
            description = "Imported YARA rule"
            license = license_from_github or "Unknown"
            author = "Unknown"
            version = "1.0"

            

            # Parse line by line
            for line in lines:
                line = line.strip()

                # if line.lower().startswith("rule "):
                #     title_match = re.match(r'^\s*rule\s+([^\s{]+)', line, re.IGNORECASE)
                #     if title_match:
                #         title = title_match.group(1).strip()
                if line.lower().startswith("rule "):
                    title_match = re.match(r'^\s*rule\s+([^\s{]+)', line, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()
                        if ':' in title:
                            title = title.split(':')[0].strip()

                elif line.lower().startswith("rule:"):
                    title_match = re.match(r'^\s*rule\s*:?\s*([^\s{]+)', line, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()

                elif line.lower().startswith("description"):
                    description = line.split("=", 1)[-1].strip().strip(' "')

                elif line.lower().startswith("license"):
                    license = line.split("=", 1)[-1].strip().strip(' "')

                elif line.lower().startswith("author"):
                    author = line.split("=", 1)[-1].strip().strip(' "')

                elif line.lower().startswith("version"):
                    version = line.split("=", 1)[-1].strip().strip(' "')

            
            
            
            # Build GitHub URL if repo details are provided
            # source_url = file_path
            # if repo_dir and repo_url and "github.com" in repo_url:
            #     relative_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")
            #     if repo_url.endswith(".git"):
            #         repo_url = repo_url[:-4]

            #     source_url = f"https://github.com/{'/'.join(repo_url.split('/')[-2:])}/blob/{branch}/{relative_path}"

            source_url = repo_url

            
            rule_dict = {
                "format": "YARA",
                "title": title,
                "license": license,
                "description": description,
                "source": source_url,
                "version": version or "1.0",
                "author": author or "Unknown",
                "to_string": raw_content
            }
            
            
            rules_json.append(rule_dict)

    return rules_json

    
# ---------------------------------------------------------------------------------------------------------------------------Old_Version----------------------------------------------------------------------------------------------------------------


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

        if line.lower().startswith("rule "):
            title_match = re.match(r'^\s*rule\s+([^\s{]+)', line, re.IGNORECASE) 
            if title_match:
                title = title_match.group(1).strip()
        elif line.lower().startswith("rule:"):  
            title_match = re.match(r'^\s*rule\s*:?\s*([^\s{]+)', line, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()


        elif line.lower().startswith("description"):
            description = line.split("=", 1)[-1].strip().strip(' "')


        elif line.lower().startswith("license"):
            license = line.split("=", 1)[-1].strip().strip(' "')


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
    
    #save_yara_rules_as_is(repo_url)

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



