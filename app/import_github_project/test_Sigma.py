
import os

import yaml
import json
from jsonschema import validate, ValidationError

def load_json_schema(schema_file):
    try:
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        return schema
    except Exception as e:
        print(f"Error loading JSON schema: {e}")
        return None

def get_rule_files_from_repo(repo_dir):
    """Retrieve all .yml or .yaml files from a local repository."""
    print(f"Retrieving rule files from repository: {repo_dir}")
    rule_files = []

    if not os.path.exists(repo_dir):
        print(f"Error: The directory {repo_dir} does not exist.")
        return rule_files

    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                rule_files.append(os.path.join(root, file))

    print(f"Files found: {len(rule_files)} .yml or .yaml files.")
    return rule_files

def load_rule_files(repo_dir, license_from_github, repo_url):
    """Load and parse rule files from the given repository directory."""
    print("Loading rule files...")

    files = get_rule_files_from_repo(repo_dir)
    all_rules = []
    bad_rules = []
    sigma_schema = load_json_schema("app/import_github_project/sigma_format.json")
    if files:
        for file in files:
            print(f"Processing file: {file}")
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    rule_json_string = json.dumps(rule, indent=2 , default=str)
                    rule_json_object = json.loads(rule_json_string)               
                    if rule:
                        try:
                            validate(instance=rule_json_object, schema=sigma_schema)
                            print("Valid Sigma rule.")
                            all_rules.append(rule)
                        except ValidationError as e:
                            print(f"Not a valid Sigma rule: {e.message}")
                            bad_rule_content = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
                            bad_rules.append({
                                "file": file,
                                "error": e.message,
                                "content": bad_rule_content
                            })
                    else:
                        print(f"The file {file} does not contain any rules.")
            except Exception as e:
                print(f"Error reading the file {file}: {e}")
                bad_rules.append({
                    "file": file,
                    "error": str(e),
                    "content": None
                })  
    else:
        print("No rule files found to process.")

    rule_dict_list = []
    for rule in all_rules:
        rule_dict = {
            "format": "Sigma",  
            "title": rule.get("title", "Untitled"), 
            "license": rule.get("license", license_from_github), 
            "description": rule.get("description", "No description provided"),
            "source": repo_url,
            "version": rule.get("version", "1.0"), 
            "author": rule.get("author", "Unknown"),  
            # "to_string": json.dumps(rule, indent=2, default=str) json format
            "to_string": yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
        }
        rule_dict_list.append(rule_dict)

    print(f"{len(all_rules)} valid rules loaded.")
    print(f"{len(bad_rules)} invalid or non-Sigma rules found.")
    return rule_dict_list, bad_rules , len(bad_rules)
