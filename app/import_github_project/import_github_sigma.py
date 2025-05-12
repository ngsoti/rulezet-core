
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
        return None

def get_rule_files_from_repo(repo_dir):
    """Retrieve all .yml or .yaml files from a local repository."""
    rule_files = []

    if not os.path.exists(repo_dir):
        return rule_files

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.yml', '.yaml')):
                rule_files.append(os.path.join(root, file))

    return rule_files




def load_rule_files(repo_dir, license_from_github, repo_url):
    """Load and parse rule files from the given repository directory."""
    files = get_rule_files_from_repo(repo_dir)
    all_rules = []
    bad_rules = []
    sigma_schema = load_json_schema("app/import_github_project/sigma_format.json")
    if files:
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    rule_json_string = json.dumps(rule, indent=2 , default=str)
                    rule_json_object = json.loads(rule_json_string)               
                    if rule:
                        try:
                            validate(instance=rule_json_object, schema=sigma_schema)
                            all_rules.append(rule)
                        except ValidationError as e:
                            bad_rule_content = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
                            bad_rules.append({
                                "file": file,
                                "error": e.message,
                                "content": bad_rule_content
                            })
            except Exception as e:
                bad_rules.append({
                    "file": file,
                    "error": str(e),
                    "content": None
                })  

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
    return rule_dict_list, bad_rules , len(bad_rules)
