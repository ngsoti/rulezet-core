# suricata-parser
# pip install idstools
# Validate with suricata -T subprocess,
import json
import os
from suricataparser import parse_rule
from suricataparser import parse_rules
import subprocess

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



def parse_suricata_rules_from_file(repo_dir, license_from_github, repo_url, info) -> list:
    """Parse Suricata rules from a repo directory and return a list of rule dicts."""
    files = get_rule_files_from_repo(repo_dir) 
    rule_dict_list = []

    if not files:
        return rule_dict_list

    for file in files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                rules_content = f.read()
                rules = parse_rules(rules_content)  
                for rule in rules:
                    rule_dict = {
                        "format": "Suricata",  
                        "title": rule.msg or file  ,  # msg = title of the rule
                        "license": license_from_github, 
                        "description": info.get("description", "No description provided"),
                        "source": repo_url,
                        "version": rule.rev or "1.0",  
                        "author": info.get("author", "Unknown"),  
                        "to_string": rule.raw
                    }
                    rule_dict_list.append(rule_dict)
        except Exception as e:
            print(f"Failed to parse file {file}: {e}")

    return rule_dict_list




###########################################################--------don't-work-----------####################################
def test_suricata_rule(rule_file) -> bool:
    """test if the rule is"""
    command = [
        'suricata', '-T', 
        '--rule-files', rule_file  
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 0:
        print("La règle est valide et bien interprétée.")
        return True
    else:
        print("Erreur dans la règle :", result.stderr.decode())
        return False

