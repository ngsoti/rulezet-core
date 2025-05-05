

import os
import re
import yara

from app.import_github_project.untils_import import clean_rule_filename_Yara, clone_or_access_repo


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


def read_and_parse_all_yara_rules_from_folder_test(license_from_github, repo_url):
    """
    Read all .yar files in the folder, validate and extract metadata into JSON format.
    """
    folder_path="app/rule/output_rules/Yara"
    rules_json = []
    bad_rules = []
    if not os.path.isdir(folder_path):
        raise FileNotFoundError(f"[ERROR] Folder '{folder_path}' does not exist.")

    print(f"[INFO] Scanning folder: {folder_path}")

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        print(file_path)
        if os.path.isfile(file_path) and filename.lower().endswith(".yar"):
            print(f"[INFO] Processing file: {filename}")
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
                raw_content = file.read()

            try:
                yara.compile(source=raw_content)
                print(f"[VALID] YARA syntax OK: {filename}")
                is_valid = True
            except yara.SyntaxError as e:
                print(f"[YARA Error] {filename}: {e}")

                bad_rules.append({
                                "file": filename,
                                "error": str(e),
                                "content": raw_content
                            })
                is_valid = False

            if not is_valid:
                continue 

            title = extract_first_match(raw_content, ["title", "Title"]) or clean_rule_filename_Yara(filename)
            description = extract_first_match(raw_content, ["description", "Description"])
            license = extract_first_match(raw_content, ["license", "License"]) or license_from_github
            author = extract_first_match(raw_content, ["author", "Author"])
            version = extract_first_match(raw_content, ["version", "Version"])
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

            print(f"[INFO] Rule added: {title}")
            rules_json.append(rule_dict)

    print(f"[SUMMARY] Total valid rules parsed: {len(rules_json)}")
    return rules_json , bad_rules , len(bad_rules)




# exctract part
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
