import re
from flask_login import current_user
import yara
import os
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

def parse_yara_rules_from_repo(repo_dir, license_from_github, repo_url):
    print(f"🔍 Scanning repo at: {repo_dir}")
    imported = 0
    skipped = 0
    bad_rules_count = 0
    bad_rules = []

    yara_files = get_yara_files_from_repo(repo_dir)
    print(f"📂 Found {len(yara_files)} YARA file(s).")

    for filepath in yara_files:
        print(f"\n📄 Processing file: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            raw_blocks = re.findall(r'(?s)(rule\s+\w+.*?condition\s*:\s*[^}]+})', content)

            rule_blocks = []
            for block in raw_blocks:
                first_lines = block.strip().splitlines()
                for line in first_lines:
                    if "rule" in line:
                        if line.strip().startswith("//"):
                            print("🟡 Skipped commented-out rule.")
                            break
                        rule_blocks.append(block)
                        break

            print(f"🔎 Found {len(rule_blocks)} active rule(s) in file.")

            for current_rule_text in rule_blocks:
                externals = {}
                compiled = False
                attempts = 0
                max_attempts = 10

                while not compiled and attempts < max_attempts:
                    try:
                        yara.compile(source=current_rule_text, externals=externals)
                        compiled = True
                    except yara.SyntaxError as e:
                        error_msg = str(e)

                        match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                        if match_id:
                            var_name = match_id.group(1)
                            print(f"⚠️  Missing external variable: {var_name}")
                            if var_name in YARA_MODULES:
                                print(f"➕ Adding import for module: {var_name}")
                                current_rule_text = insert_import_module(current_rule_text, var_name)
                            else:
                                externals[var_name] = "example.txt"
                            attempts += 1
                            continue

                        match_not_structure = re.search(r'"(\w+)" is not a structure', error_msg)
                        if match_not_structure:
                            print(f"⚠️ Warning: {match_not_structure.group(1)} is not a structure")
                            bad_rules.append({
                                "file": filepath,
                                "error": error_msg,
                                "content": current_rule_text
                            })
                            bad_rules_count += 1
                            break

                        print(f"✗ Syntax error: {error_msg}")
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

                        rule_dict = {
                            "format": "yara",
                            "title": rule_name,
                            "license": meta.get("license", license_from_github),
                            "description": meta.get("description", "No description provided"),
                            "source": repo_url,
                            "version": meta.get("version", "1.0"),
                            "author": meta.get("author", "Unknown"),
                            "to_string": current_rule_text
                        }

                        result = {"valid": True, "rule": rule_dict}
                        success = RuleModel.add_rule_core(result["rule"], current_user)

                        if success:
                            imported += 1
                        else:
                            skipped += 1

                        print(f"✅ Parsed and imported rule: {rule_name}")
                    except Exception as e:
                        error_msg = f"Unexpected parsing error: {e}"
                        print(f"❌ {error_msg}")
                        bad_rules.append({
                            "file": filepath,
                            "error": error_msg,
                            "content": current_rule_text
                        })
                        bad_rules_count += 1

        except Exception as e:
            print(f"❌ Error reading file {filepath}: {e}")
            bad_rules.append({
                "file": filepath,
                "error": str(e),
                "content": ""
            })
            bad_rules_count += 1

    print(f"\n✅ Parsing complete. Imported: {imported}, Skipped: {skipped}, Failed: {bad_rules_count}")
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