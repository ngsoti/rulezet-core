#########################################################################################################################
import os
import re
import yara

from app.import_github_project.untils_import import build_externals_dict, clean_rule_filename_Yara, clone_or_access_repo


def get_yara_files_from_repo(repo_dir):
    """Retrieve all .yar, .rule and .yara files from a local repository, excluding hidden or system files/folders."""
    yara_files = []
    for root, dirs, files in os.walk(repo_dir):
        # Ignore dirs starting with . or _
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]

        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.yar', '.yara', '.rule')):
                yara_files.append(os.path.join(root, file))
    return yara_files



def count_braces_outside_strings(line):
    # Variable to track if we're inside single or double quotes
    in_single_quote = False
    in_double_quote = False
    escaped = False  
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
    without any modification. Each rule is saved in a file named after the rule's title.
    If there are any imports or private rules in the YARA file, they will be included before each rule.
    """
    repo_dir , existe = clone_or_access_repo(repo_url)
    yara_files = get_yara_files_from_repo(repo_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    for yara_file in yara_files:
        
        with open(yara_file, 'r', encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        inside_rule = False
        brace_count = 0
        rule_index = 0
        imports = []
        private_rules = []

        is_private = False
        temp_rule_lines = []

        for line in lines:
            stripped = line.strip()

            # Capture imports
            if re.match(r'^\s*import\s+', stripped):
                if stripped not in imports:
                    imports.append(stripped)
                continue

            # Detect start of a rule (public or private)
            if not inside_rule and re.match(r'^\s*(private\s+)?rule\b', stripped):
                inside_rule = True
                brace_count = 0
                temp_rule_lines = [line]
                if stripped.startswith("private"):
                    is_private = True
                else:
                    is_private = False
                brace_count += count_braces_outside_strings(line)
                continue

            # Inside a rule
            if inside_rule:
                temp_rule_lines.append(line)
                brace_count += count_braces_outside_strings(line)

                if brace_count == 0:
                    full_rule = ''.join(temp_rule_lines)
                    if is_private:
                        private_rules.append(full_rule.strip())
                    else:
                        # Extract rule title
                        title_match = re.search(r'\brule\s*:?\s*([^\s{(]+)', full_rule)
                        if title_match:
                            rule_title_final = title_match.group(1).strip()
                        else:
                            rule_title_final = f"Untitled_{rule_index}"

                        # Compose final rule with imports and private rules
                        final_rule_parts = []
                        if imports:
                            final_rule_parts.append('\n'.join(imports))
                        if private_rules:
                            final_rule_parts.append('\n\n'.join(private_rules))
                        final_rule_parts.append(full_rule.strip())

                        final_rule = '\n\n'.join(final_rule_parts)

                        file_name = f"{rule_title_final}.yar"
                        file_path = os.path.join(output_dir, file_name)

                        with open(file_path, 'w', encoding="utf-8") as output_file:
                            output_file.write(final_rule)

                        rule_index += 1

                    inside_rule = False
                    temp_rule_lines = []

    return repo_dir




def read_and_parse_all_yara_rules_from_folder_test(license_from_github, repo_url, external_vars):
    """
    Read all .yar files in the folder, validate and extract metadata into JSON format. 
    """

    folder_path = "app/rule/output_rules/Yara"
    rules_json = []
    bad_rules = []
    
    if not os.path.isdir(folder_path):
        raise FileNotFoundError(f"[ERROR] Folder '{folder_path}' does not exist.")

    

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and filename.lower().endswith(('.yar', '.yara', '.rule')):
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
                raw_content = file.read()

            is_valid = False
            external_vars_temp = external_vars.copy()
            externals = build_externals_dict(external_vars_temp)

            while True:
                try:
                    yara.compile(source=raw_content, externals=externals)
                    is_valid = True
                    break
                except yara.SyntaxError as e:
                    error_msg = str(e)
                    match = re.search(r'undefined identifier "(.*?)"', error_msg)
                    if match:
                        missing_var = match.group(1)
                        if missing_var in externals:
                            bad_rules.append({
                                "file": filename,
                                "error": error_msg,
                                "content": raw_content
                            })
                            break
                        external_vars_temp.append({"type": "string", "name": missing_var})
                        externals = build_externals_dict(external_vars_temp)
                    else:
                        bad_rules.append({
                            "file": filename,
                            "error": error_msg,
                            "content": raw_content
                        })
                        break

            if not is_valid:
                continue

            title = extract_first_match(raw_content, ["title", "Title"]) or clean_rule_filename_Yara(filename)
            description = extract_first_match(raw_content, ["description", "Description"])
            license = extract_first_match(raw_content, ["license", "License"]) or license_from_github
            author = extract_first_match(raw_content, ["author", "Author"])
            version = extract_first_match(raw_content, ["version", "Version"])
            source_url = repo_url

            rule_dict = {
                "format": "yara",
                "title": title,
                "license": license,
                "description": description,
                "source": source_url,
                "version": version or "1.0",
                "author": author or "Unknown",
                "to_string": raw_content
            }

            rules_json.append(rule_dict)

    return rules_json, bad_rules, len(bad_rules)





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

#########################################
# def save_yara_rules_as_is(repo_url, output_dir="app/rule/output_rules/Yara"):
#     """
#     Retrieve all YARA rules from a Git repository and save each rule exactly as it is
#     without any modification. Each rule is saved in a file named after the rule's title.
#     If there are any imports or private rules in the YARA file, they will be included before each rule.
#     """
#     repo_dir = clone_or_access_repo(repo_url)
#     yara_files = get_yara_files_from_repo(repo_dir)
#     os.makedirs(output_dir, exist_ok=True)

#     for yara_file in yara_files:

#         with open(yara_file, 'r', encoding="utf-8", errors="ignore") as file:
#             lines = file.readlines()

#         inside_rule = False
#         brace_count = 0
#         rule_index = 0
#         imports = []
#         private_rules = []

#         is_private = False
#         temp_rule_lines = []
#         in_multiline_comment = False 

#         for line in lines:
#             stripped = line.strip()


#             if not inside_rule:
#                 if in_multiline_comment:
#                     if '*/' in line:
#                         in_multiline_comment = False
#                     continue  
#                 if '/*' in line:
#                     start_comment = line.find('/*')
#                     end_comment = line.find('*/', start_comment + 2)
#                     if end_comment == -1:
#                         in_multiline_comment = True
#                         continue  
#                     else:
#                         line = line[:start_comment] + line[end_comment + 2:]
#                         stripped = line.strip()
#                         if not stripped:
#                             continue

#             # Capture imports
#             if not inside_rule and re.match(r'^\s*import\s+', stripped):
#                 if stripped not in imports:
#                     imports.append(stripped)
#                 continue

#             # Detect start of a rule (public or private)
#             if not inside_rule and re.match(r'^\s*(private\s+)?rule\b', stripped):
#                 inside_rule = True
#                 brace_count = 0
#                 temp_rule_lines = [line]
#                 if stripped.startswith("private"):
#                     is_private = True
#                 else:
#                     is_private = False
#                 brace_count += count_braces_outside_strings(line)
#                 continue

#             # Inside a rule
#             if inside_rule:
#                 temp_rule_lines.append(line)
#                 brace_count += count_braces_outside_strings(line)

#                 if brace_count == 0:
#                     full_rule = ''.join(temp_rule_lines)
#                     if is_private:
#                         private_rules.append(full_rule.strip())
#                     else:
#                         # Extract rule title
#                         title_match = re.search(r'\brule\s*:?\s*([^\s{(]+)', full_rule)
#                         if title_match:
#                             rule_title_final = title_match.group(1).strip()
#                         else:
#                             rule_title_final = f"Untitled_{rule_index}"

#                         # Compose final rule with imports and private rules
#                         final_rule_parts = []
#                         if imports:
#                             final_rule_parts.append('\n'.join(imports))
#                         if private_rules:
#                             final_rule_parts.append('\n\n'.join(private_rules))
#                         final_rule_parts.append(full_rule.strip())

#                         final_rule = '\n\n'.join(final_rule_parts)

#                         file_name = f"{rule_title_final}.yar"
#                         file_path = os.path.join(output_dir, file_name)

#                         with open(file_path, 'w', encoding="utf-8") as output_file:
#                             output_file.write(final_rule)

#                         rule_index += 1

#                     inside_rule = False
#                     temp_rule_lines = []

#     return repo_dir


# def save_yara_rules_as_is(repo_url, output_dir="app/rule/output_rules/Yara"):
#     """
#     Retrieve all YARA rules from a Git repository and save each rule exactly as it is
#     without any modification. Each rule is saved in a file named after the rule's title.
#     If there are any imports in the YARA file, they will be included before the rule itself.
#     """
    
#     # Clone or access the given repository
#     repo_dir = clone_or_access_repo(repo_url)
    
#     # Get the list of YARA files from the repository
#     yara_files = get_yara_files_from_repo(repo_dir)

#     # Ensure the output directory exists
#     os.makedirs(output_dir, exist_ok=True)

#     # Process each YARA file
#     for yara_file in yara_files:
#         with open(yara_file, 'r', encoding="utf-8", errors="ignore") as file:
#             lines = file.readlines()

#         inside_rule = False
#         brace_count = 0
#         current_rule_lines = []
#         rule_index = 0
#         imports = []

#         # Read each line of the YARA file
#         for line in lines:
#             stripped = line.strip()

#             # Detect imports in the file and store them
#             if re.match(r'^\s*import\s+', stripped):
#                 imports.append(stripped)
#                 continue  

#             # Check if the line starts a new rule
#             if not inside_rule and re.match(r'^\s*rule\b', stripped):

#                 inside_rule = True
#                 brace_count = 0
#                 current_rule_lines = [line]

#                 # Count braces on the first line outside of quotes
#                 brace_count += count_braces_outside_strings(line)

#             # Process lines inside the rule
#             elif inside_rule:
#                 current_rule_lines.append(line)
#                 brace_count += count_braces_outside_strings(line)

#                 # If brace count reaches zero, the rule is complete
#                 if brace_count == 0:
#                     # Join all lines of the rule
#                     raw_rule = ''.join(current_rule_lines)

#                     # Extract the rule title, supporting both "rule" and "rule:"
#                     title_match = re.search(r'\brule\s*:?\s*([^\s{(]+)', raw_rule)
#                     if title_match:
#                         rule_title_final = title_match.group(1).strip()
#                     else:
#                         rule_title_final = f"Untitled_{rule_index}"

#                     # Prepare the final rule with imports included at the top if any
#                     final_rule = '\n'.join(imports) + '\n' + raw_rule.strip()

#                     # Generate a safe file name using the rule title
#                     file_name = f"{rule_title_final}.yar"
#                     file_path = os.path.join(output_dir, file_name)

#                     # Write the rule (including imports) to a new file
#                     with open(file_path, 'w', encoding="utf-8") as output_file:
#                         output_file.write(final_rule)

#                     rule_index += 1
#                     inside_rule = False
#                     current_rule_lines = []


#     return repo_dir