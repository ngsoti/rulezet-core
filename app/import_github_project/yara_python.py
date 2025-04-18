import plyara
import plyara.utils
import os
import re

def sanitize_rule_name(name):
    # Nettoie le nom : remplace caractères non valides par _
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if re.match(r'^\d', sanitized):
        sanitized = "rule_" + sanitized
    return sanitized

def extract_yara_rules(yara_file):
    if not os.path.exists(yara_file):
        print(f"The YARA file '{yara_file}' does not exist.")
        return

    with open(yara_file, 'r') as file:
        yara_content = file.read()

    # Ce pattern capture : nom, tags éventuels, bloc complet
    rule_block_pattern = re.compile(
        r'rule\s+(\w[\w\d_.-]*)\s*(?::\s*[\w\s_-]+)?\s*({(?:[^{}]*|{[^}]*})*})', re.DOTALL
    )

    corrected_blocks = []
    name_mapping = {}

    for match in rule_block_pattern.finditer(yara_content):
        original_name = match.group(1)
        body = match.group(2)

        # Corrige le nom si invalide
        new_name = original_name
        if not plyara.utils.is_valid_rule_name(original_name):
            new_name = sanitize_rule_name(original_name)
            name_mapping[original_name] = new_name

        # Reconstruit la règle SANS les tags
        rule_block = f"rule {new_name} {body}"
        corrected_blocks.append(rule_block)

    if name_mapping:
        print("Corrected rule names (tags removed too):")
        for old, new in name_mapping.items():
            print(f" - {old} -> {new}")
        print()

    # Assemble le contenu corrigé
    filtered_content = "\n\n".join(corrected_blocks)

    parser = plyara.Plyara()
    parsed_rules = parser.parse_string(filtered_content)

    for rule_info in parsed_rules:
        print(f"\nRule Name: {rule_info.get('rule_name')}")
        print(f"Metadata: {rule_info.get('metadata') or 'None'}")
        print(f"Strings: {rule_info.get('strings') or 'None'}")
        print(f"Condition: {rule_info.get('condition_terms') or 'None'}")
