import re
import os
import yara
import asyncio
import aiofiles
from flask_login import current_user
from concurrent.futures import ThreadPoolExecutor

from app.utils.utils import detect_cve
from ..rule import rule_core as RuleModel

YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho"}

def get_yara_files_from_repo(repo_dir):
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.yar', '.yara', '.rule')):
                yara_files.append(os.path.join(root, file))
    return yara_files

def insert_import_module(rule_text, module_name):
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text

def extract_meta_from_rule(rule_text):
    meta = {}
    meta_block = re.search(r'meta\s*:\s*(.*?)\n\s*\w+\s*:', rule_text, re.DOTALL)
    if meta_block:
        entries = re.findall(r'(\w+)\s*=\s*"(.*?)"', meta_block.group(1))
        for key, val in entries:
            meta[key] = val
    return meta

async def read_file_async(filepath):
    async with aiofiles.open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = await f.read()
    return content

def yara_compile_source(source, externals):
    return yara.compile(source=source, externals=externals)



async def parse_yara_rules_from_repo_async(repo_dir, license_from_github, repo_url):
    imported = 0
    skipped = 0
    bad_rules_count = 0
    bad_rules = []

    yara_files = get_yara_files_from_repo(repo_dir)
    executor = ThreadPoolExecutor(max_workers=4)

    for filepath in yara_files:
        try:
            content = await read_file_async(filepath)

            raw_blocks = re.findall(r'(?s)(rule\s+\w+.*?condition\s*:\s*[^}]+})', content)

            rule_blocks = []
            for block in raw_blocks:
                first_lines = block.strip().splitlines()
                for line in first_lines:
                    if "rule" in line:
                        if line.strip().startswith("//"):
                            break
                        rule_blocks.append(block)
                        break

            for current_rule_text in rule_blocks:
                externals = {}
                compiled = False
                attempts = 0
                max_attempts = 10

                while not compiled and attempts < max_attempts:
                    try:
                        # Compile YARA source in thread to avoid blocking event loop
                        await asyncio.get_event_loop().run_in_executor(
                            executor,
                            yara_compile_source,
                            current_rule_text,
                            externals
                        )
                        compiled = True
                    except yara.SyntaxError as e:
                        error_msg = str(e)

                        match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                        if match_id:
                            var_name = match_id.group(1)
                            if var_name in YARA_MODULES:
                                current_rule_text = insert_import_module(current_rule_text, var_name)
                            else:
                                externals[var_name] = "example.txt"
                            attempts += 1
                            continue

                        match_not_structure = re.search(r'"(\w+)" is not a structure', error_msg)
                        if match_not_structure:
                            bad_rules.append({
                                "file": filepath,
                                "error": error_msg,
                                "content": current_rule_text
                            })
                            bad_rules_count += 1
                            break

                        bad_rules.append({
                            "file": filepath,
                            "error": error_msg,
                            "content": current_rule_text
                        })
                        bad_rules_count += 1
                        break

                if compiled:
                    try:
                        meta = extract_meta_from_rule(current_rule_text)
                        rule_name_match = re.search(r'rule\s+(\w+)', current_rule_text)
                        rule_name = rule_name_match.group(1) if rule_name_match else "unknown_rule"
                        r , cve = detect_cve(meta.get("description", "No description provided"))

                        rule_dict = {
                            "format": "yara",
                            "title": rule_name,
                            "license": meta.get("license", license_from_github),
                            "description": meta.get("description", "No description provided"),
                            "source": repo_url,
                            "version": meta.get("version", "1.0"),
                            "author": meta.get("author", "Unknown"),
                            "to_string": current_rule_text,
                            "cve_id": cve
                        }

                        result = {"valid": True, "rule": rule_dict}
                        success = RuleModel.add_rule_core(result["rule"], current_user)

                        if success:
                            imported += 1
                        else:
                            skipped += 1
                    except Exception as e:
                        error_msg = f"Unexpected parsing error: {e}"
                        bad_rules.append({
                            "file": filepath,
                            "error": error_msg,
                            "content": current_rule_text
                        })
                        bad_rules_count += 1

        except Exception as e:
            bad_rules.append({
                "file": filepath,
                "error": str(e),
                "content": ""
            })
            bad_rules_count += 1

    #print(f"\nParsing complete. Imported: {imported}, Skipped: {skipped}, Failed: {bad_rules_count}")
    return imported, skipped, bad_rules_count, bad_rules



def extract_first_match(raw_content, keys):
    for key in keys:
        value = extract_metadata_value(raw_content, key)
        if value:
            return value
    return None


def extract_metadata_value(text, key):
    """Extract the value of a meta field from a YARA rule."""
    pattern = rf"{key}\s*=\s*\"([^\"]+)\""
    match = re.search(pattern, text)
    return match.group(1) if match else None

####################
#   search title   #
####################

def find_yara_rule_by_title(repo_dir, title):
    yara_files = get_yara_files_from_repo(repo_dir)

    for filepath in yara_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            raw_blocks = re.findall(r'(?s)(rule\s+\w+.*?condition\s*:\s*[^}]+})', content)

            for idx, rule_text in enumerate(raw_blocks, start=1):
                rule_name_match = re.search(r'rule\s+(\w+)', rule_text)
                rule_name = rule_name_match.group(1) if rule_name_match else None

                if rule_name != title:
                    continue

                externals = {}
                compiled = False
                attempts = 0
                max_attempts = 10

                while not compiled and attempts < max_attempts:
                    try:
                        yara.compile(source=rule_text, externals=externals)
                        compiled = True
                    except yara.SyntaxError as e:
                        error_msg = str(e)

                        match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                        if match_id:
                            var_name = match_id.group(1)

                            if var_name in YARA_MODULES:
                                rule_text = insert_import_module(rule_text, var_name)
                            else:
                                externals[var_name] = "example.txt"

                            attempts += 1
                            continue

                        break

                if compiled:
                    return rule_text  

        except Exception as e:
            continue

    return None

# def find_yara_rule_by_title(repo_dir, title, logs=None):
#     if logs is None:
#         logs = []

#     logs.append(f"Searching for YARA rule titled '{title}' in repository: {repo_dir}")
#     yara_files = get_yara_files_from_repo(repo_dir)
#     logs.append(f"Found {len(yara_files)} YARA files to scan.")

#     for filepath in yara_files:
#         logs.append(f"Reading file: {filepath}")
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read()

#             raw_blocks = re.findall(r'(?s)(rule\s+\w+.*?condition\s*:\s*[^}]+})', content)
#             logs.append(f"Found {len(raw_blocks)} raw rules in file.")

#             for idx, rule_text in enumerate(raw_blocks, start=1):
#                 rule_name_match = re.search(r'rule\s+(\w+)', rule_text)
#                 rule_name = rule_name_match.group(1) if rule_name_match else None

#                 if rule_name != title:
#                     logs.append(f"Rule #{idx} named '{rule_name}' does not match target '{title}', skipping.")
#                     continue

#                 logs.append(f"Found matching rule '{rule_name}'. Attempting to compile...")
#                 externals = {}
#                 compiled = False
#                 attempts = 0
#                 max_attempts = 10

#                 while not compiled and attempts < max_attempts:
#                     try:
#                         yara.compile(source=rule_text, externals=externals)
#                         compiled = True
#                         logs.append(f"Rule compiled successfully after {attempts} attempts.")
#                     except yara.SyntaxError as e:
#                         error_msg = str(e)
#                         logs.append(f"Compilation error: {error_msg}")

#                         match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
#                         if match_id:
#                             var_name = match_id.group(1)
#                             logs.append(f"Undefined identifier found: '{var_name}'")

#                             if var_name in YARA_MODULES:
#                                 logs.append(f"Inserting import for YARA module '{var_name}'")
#                                 rule_text = insert_import_module(rule_text, var_name)
#                             else:
#                                 logs.append(f"Adding external variable '{var_name}' with dummy value")
#                                 externals[var_name] = "example.txt"

#                             attempts += 1
#                             continue
                        
#                         logs.append("Compilation failed with unrecoverable syntax error.")
#                         break

#                 if compiled:
#                     logs.append(f"Returning compiled rule for '{rule_name}'.")
#                     return rule_text, logs

#         except Exception as e:
#             logs.append(f"Error reading/parsing file {filepath}: {e}")
#             continue

#     logs.append(f"No matching YARA rule titled '{title}' found in repository.")
#     return None, logs

###########################################################_____Sync____#####################################################################


# import re
# from flask_login import current_user
# import yara
# import os
# from ..rule import rule_core as RuleModel

# YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho"}

# def get_yara_files_from_repo(repo_dir):
#     yara_files = []
#     for root, dirs, files in os.walk(repo_dir):
#         dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
#         for file in files:
#             if file.startswith('.') or file.startswith('_'):
#                 continue
#             if file.endswith(('.yar', '.yara', '.rule')):
#                 yara_files.append(os.path.join(root, file))
#     return yara_files

# def insert_import_module(rule_text, module_name):
#     lines = rule_text.strip().splitlines()
#     if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
#         return f'import "{module_name}"\n' + rule_text
#     return rule_text

# def extract_meta_from_rule(rule_text):
#     meta = {}
#     meta_block = re.search(r'meta\s*:\s*(.*?)\n\s*\w+\s*:', rule_text, re.DOTALL)
#     if meta_block:
#         entries = re.findall(r'(\w+)\s*=\s*"(.*?)"', meta_block.group(1))
#         for key, val in entries:
#             meta[key] = val
#     return meta

# def parse_yara_rules_from_repo(repo_dir, license_from_github, repo_url):

#     imported = 0
#     skipped = 0
#     bad_rules_count = 0
#     bad_rules = []

#     yara_files = get_yara_files_from_repo(repo_dir)

#     for filepath in yara_files:
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read()

#             raw_blocks = re.findall(r'(?s)(rule\s+\w+.*?condition\s*:\s*[^}]+})', content)

#             rule_blocks = []
#             for block in raw_blocks:
#                 first_lines = block.strip().splitlines()
#                 for line in first_lines:
#                     if "rule" in line:
#                         if line.strip().startswith("//"):
#                             print("Skipped commented-out rule.")
#                             break
#                         rule_blocks.append(block)
#                         break


#             for current_rule_text in rule_blocks:
#                 externals = {}
#                 compiled = False
#                 attempts = 0
#                 max_attempts = 10

#                 while not compiled and attempts < max_attempts:
#                     try:
#                         yara.compile(source=current_rule_text, externals=externals)
#                         compiled = True
#                     except yara.SyntaxError as e:
#                         error_msg = str(e)

#                         match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
#                         if match_id:
#                             var_name = match_id.group(1)
#                             if var_name in YARA_MODULES:
#                                 current_rule_text = insert_import_module(current_rule_text, var_name)
#                             else:
#                                 externals[var_name] = "example.txt"
#                             attempts += 1
#                             continue

#                         match_not_structure = re.search(r'"(\w+)" is not a structure', error_msg)
#                         if match_not_structure:
#                             bad_rules.append({
#                                 "file": filepath,
#                                 "error": error_msg,
#                                 "content": current_rule_text
#                             })
#                             bad_rules_count += 1
#                             break

#                         print(f"✗ Syntax error: {error_msg}")
#                         bad_rules.append({
#                             "file": filepath,
#                             "error": error_msg,
#                             "content": current_rule_text
#                         })
#                         bad_rules_count += 1
#                         break

#                 if compiled:
#                     try:
#                         meta = extract_meta_from_rule(current_rule_text)
#                         rule_name_match = re.search(r'rule\s+(\w+)', current_rule_text)
#                         rule_name = rule_name_match.group(1) if rule_name_match else "unknown_rule"

#                         rule_dict = {
#                             "format": "yara",
#                             "title": rule_name,
#                             "license": meta.get("license", license_from_github),
#                             "description": meta.get("description", "No description provided"),
#                             "source": repo_url,
#                             "version": meta.get("version", "1.0"),
#                             "author": meta.get("author", "Unknown"),
#                             "to_string": current_rule_text
#                         }

#                         result = {"valid": True, "rule": rule_dict}
#                         success = RuleModel.add_rule_core(result["rule"], current_user)

#                         if success:
#                             imported += 1
#                         else:
#                             skipped += 1
#                     except Exception as e:
#                         error_msg = f"Unexpected parsing error: {e}"
#                         bad_rules.append({
#                             "file": filepath,
#                             "error": error_msg,
#                             "content": current_rule_text
#                         })
#                         bad_rules_count += 1

#         except Exception as e:
#             bad_rules.append({
#                 "file": filepath,
#                 "error": str(e),
#                 "content": ""
#             })
#             bad_rules_count += 1
#     print(f"\nParsing complete. Imported: {imported}, Skipped: {skipped}, Failed: {bad_rules_count}")
#     return imported, skipped, bad_rules_count, bad_rules