# Install zeekscript with: pip install zeekscript
import os
import re



def load_zeek_scripts(files):
    """Load and parse Zeek script files."""
    all_scripts = []
    
    if files:
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    if content.strip():  
                        script_data = {
                            "filename": os.path.basename(file),
                            "path": file,
                            "content": content
                        }
                        all_scripts.append(script_data)
            except Exception as e:
                print(f"Error reading the file {file}: {e}")
    
    return all_scripts



def get_zeek_files_from_repo(repo_dir):
    """Retrieve all .zeek files from a local repository."""
    zeek_files = []

    # Check if the directory exists
    if not os.path.exists(repo_dir):
        return zeek_files

    # Traverse all files in the directory
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith('.zeek'):
                zeek_files.append(os.path.join(root, file))
    return zeek_files

def read_and_parse_all_zeek_scripts_from_folder(repo_dir, url_github, license_from_github):
    """
    Reads and parses all Zeek script files in the given folder using regex,
    returning a list of dictionaries with metadata and parsed content.
    """
    files = get_zeek_files_from_repo(repo_dir)
    parsed_zeek_rules = []
    
    # Regex patterns to extract specific elements from Zeek scripts
    title_pattern = re.compile(r'#\s*File:\s*(.*)', re.IGNORECASE)
    description_pattern = re.compile(r'#\s*Description:\s*(.*)', re.IGNORECASE)
    author_pattern = re.compile(r'#\s*Author:\s*(.*)', re.IGNORECASE)
    version_pattern = re.compile(r'#\s*Version:\s*(.*)', re.IGNORECASE)
    
    for file in files:
        try:
            # Read the file content
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract metadata using regex
            title = re.search(title_pattern, content)
            description = re.search(description_pattern, content)
            author = re.search(author_pattern, content)
            version = re.search(version_pattern, content)
            print("oui")
            # Remove the ".zeek" from the title if it ends with that
            if title:
                title_text = title.group(1)
            else:
                title_text = os.path.basename(file)
                
            if title_text.endswith('.zeek'):
                    title_text = title_text[:-5]  # Remove the last 5 characters (i.e., ".zeek")\
            elif title_text.endswith('.bro'):
                    title_text = title_text[:-4]  # Remove the last 4 characters (i.e., ".bro")\

            # Prepare the parsed data
            rule_dict = {
                "format": "zeek",
                "title": title_text,
                "license": license_from_github,
                "description": description.group(1) if description else "No description provided",
                "source": url_github,
                "version": version.group(1) if version else "1.0",
                "author": author.group(1) if author else "Unknown",
                "to_string": content  
            }

            # Append to results
            parsed_zeek_rules.append(rule_dict)

        except Exception as e:
            print(f"Error parsing the file {file}: {e}")

    return parsed_zeek_rules
