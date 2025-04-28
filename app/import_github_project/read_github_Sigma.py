import os
import yaml

def get_sigma_files_from_repo(repo_dir):
    """Retrieve all .yml files from a local repository."""
    sigma_files = []
    
    # Check if the directory exists
    if not os.path.exists(repo_dir):
        print(f"Error: The directory {repo_dir} does not exist.")
        return sigma_files
    
    # Traverse all files in the directory
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                sigma_files.append(os.path.join(root, file))
    
    print(f"Files found: {len(sigma_files)} .yml or .yaml files.")
    return sigma_files

def load_sigma_rules(files):
    """Load and parse Sigma rule files."""
    all_rules = []

    if files:
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    sigma_rule = yaml.safe_load(f)
                    
                    # If the file contains a rule, add it to the list
                    if sigma_rule:
                        all_rules.append(sigma_rule)
                    else:
                        print(f"The file {file} does not contain any rules.")
            except Exception as e:
                print(f"Error reading the file {file}: {e}")
    else:
        print("No files found to process.")
    
    print(f"{len(all_rules)} rules loaded.")
    return all_rules


def read_and_parse_all_sigma_rules_from_folder(repo_dir,url_github):
    """Reads and parses all Sigma rules from the given folder, returning a dictionary for each rule."""
    
    files = get_sigma_files_from_repo(repo_dir)
    all_rules = load_sigma_rules(files)
    
    rule_dict_list = []

    # Iterate through all the parsed Sigma rules
    for rule in all_rules:
        # Extract information for the rule dictionary
        rule_dict = {
            "format": "Sigma",  # Assuming the format is Sigma
            "title": rule.get("title", "Untitled"),  # Default to "Untitled" if not present
            "license": rule.get("license", "Unknown"),  # Default to "Unknown" if not present
            "description": rule.get("description", "No description provided"),
            "source": url_github ,# rule.get("source", "No source available"),
            "version": rule.get("version", "1.0"),  # Default to version "1.0"
            "author": rule.get("author", "Unknown"),  # Default to "Unknown" if not present
            "to_string": yaml.dump(rule)  # Convert the full rule to a string representation
        }
        rule_dict_list.append(rule_dict)

    return rule_dict_list
