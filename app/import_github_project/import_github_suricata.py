import os
import aiofiles
import asyncio
from suricataparser import parse_rules

from app.utils.utils import detect_cve
from ..rule import rule_core as RuleModel

def get_rule_files_from_repo(repo_dir) -> list:
    """Retrieve all .rule or .rules files from a local repository."""
    rule_files = []

    if not os.path.exists(repo_dir):
        return rule_files

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.rule', '.rules')):
                rule_files.append(os.path.join(root, file))

    return rule_files

async def parse_and_import_suricata_rules_async(repo_dir, license_from_github, repo_url, info, current_user):
    """Parse Suricata rules asynchronously from a repo directory and return counts of imported and skipped rules."""
    files = get_rule_files_from_repo(repo_dir)

    imported = 0
    skipped = 0

    if not files:
        return imported, skipped

    for file in files:
        try:
            async with aiofiles.open(file, 'r', encoding='utf-8') as f:
                rules_content = await f.read()

            # parse_rules est synchrone, on le lance dans un thread pour ne pas bloquer l'event loop
            rules = await asyncio.to_thread(parse_rules, rules_content)

            for rule in rules:
                r , cve = detect_cve(info.get("description", "No description provided"))
                rule_dict = {
                    "format": "suricata",
                    "title": rule.msg or file,
                    "license": license_from_github,
                    "description": info.get("description", "No description provided"),
                    "source": repo_url,
                    "version": rule.rev or "1.0",
                    "author": info.get("author", "Unknown"),
                    "to_string": rule.raw,
                    "cve_id": cve or None
                }

                # add_rule_core semble synchrone, donc pareil en thread si besoin
                success = await asyncio.to_thread(RuleModel.add_rule_core, rule_dict, current_user)
                if success:
                    imported += 1
                else:
                    skipped += 1

        except Exception as e:
            print(f"Failed to parse file {file}: {e}")

    return imported, skipped

def find_suricata_rule_by_title(repo_dir, title):
    """
    Find a Suricata rule in the given repo by its title (msg).
    Returns the raw rule string if found, otherwise None.
    """
    print(f"🔍 Searching for Suricata rule with msg: '{title}' in repo: {repo_dir}")

    if not os.path.exists(repo_dir):
        print(f"❌ Directory does not exist: {repo_dir}")
        return None

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.rule', '.rules')):
                file_path = os.path.join(root, file)
                print(f"📄 Checking file: {file_path}")

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        rules = parse_rules(content)

                        for rule in rules:
                            print(f"   → Found rule msg: {rule.msg}")
                            if rule.msg == title:
                                print(f"✅ Match found in file: {file_path}")
                                return rule.raw  # Return the raw rule string
                except Exception as e:
                    print(f"⚠️ Error reading/parsing file {file_path}: {e}")
                    continue

    print("❗ No matching Suricata rule found.")
    return None


# import os
# from suricataparser import parse_rules
# from ..rule import rule_core as RuleModel

# def get_rule_files_from_repo(repo_dir) -> list:
#     """Retrieve all .rule or .rules files from a local repository."""
#     rule_files = []

#     if not os.path.exists(repo_dir):
#         return rule_files

#     for root, dirs, files in os.walk(repo_dir):
#         dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
#         for file in files:
#             if file.startswith('.') or file.startswith('_'):
#                 continue
#             if file.endswith(('.rule', '.rules')):
#                 rule_files.append(os.path.join(root, file))

#     return rule_files



# def parse_and_import_suricata_rules(repo_dir, license_from_github, repo_url, info, current_user):
#     """Parse Suricata rules from a repo directory and return a list of rule dicts."""
#     files = get_rule_files_from_repo(repo_dir)

#     imported = 0
#     skipped = 0

#     if not files:
#         return imported, skipped

#     for file in files:
#         try:
#             with open(file, 'r', encoding='utf-8') as f:
#                 rules_content = f.read()
#                 rules = parse_rules(rules_content)
#                 for rule in rules:
#                     rule_dict = {
#                         "format": "suricata",
#                         "title": rule.msg or file,
#                         "license": license_from_github,
#                         "description": info.get("description", "No description provided"),
#                         "source": repo_url,
#                         "version": rule.rev or "1.0",
#                         "author": info.get("author", "Unknown"),
#                         "to_string": rule.raw
#                     }

#                     success = RuleModel.add_rule_core(rule_dict, current_user)
#                     if success:
#                         imported += 1
#                     else:
#                         skipped += 1

#         except Exception as e:
#             print(f"Failed to parse file {file}: {e}")

#     return imported, skipped
