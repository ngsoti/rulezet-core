import os
import asyncio
import aiofiles
import yaml
import json
from jsonschema import validate, ValidationError

from app.utils.utils import detect_cve
from ..rule import rule_core as RuleModel



#################################################################__Version__async__#################################################################### 

MAX_CONCURRENT_FILES = 100  # Limit the number of files processed concurrently to avoid resource exhaustion

def load_json_schema_sync(schema_file):
    with open(schema_file, 'r', encoding='utf-8') as f:
        return json.load(f)



async def get_rule_files_from_repo(repo_dir):
    """
    Recursively scan the given repository directory to find all YAML rule files.
    Ignore hidden files and directories starting with '.' or '_'.
    Return a list of full file paths to .yml and .yaml files.
    """
    rule_files = []
    if not os.path.exists(repo_dir):
        return rule_files
    for root, dirs, files in os.walk(repo_dir):
        # Exclude hidden or underscore-prefixed directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            # Skip hidden or underscore-prefixed files
            if file.startswith('.') or file.startswith('_'):
                continue
            # Only consider YAML files
            if file.endswith(('.yml', '.yaml')):
                rule_files.append(os.path.join(root, file))
    return rule_files

async def _process_single_file(file, sigma_schema, semaphore):
    """
    Process a single YAML rule file asynchronously under a semaphore limit.
    Load the YAML content, parse it, and validate against the Sigma JSON schema.
    Returns a dict with 'valid': True and the rule data if validation passes.
    If validation fails, returns 'valid': False with error info and the raw content.
    Handles file reading/parsing errors gracefully.
    """
    async with semaphore:
        try:
            async with aiofiles.open(file, 'r', encoding='utf-8') as f:
                content = await f.read()
                rule = yaml.safe_load(content)
                


                rule_json_string = json.dumps(rule, indent=2, default=str)
                rule_json_object = json.loads(rule_json_string)


                if rule:
                    try:
                        validate(instance=rule_json_object, schema=sigma_schema)
                        return {'valid': True, 'rule': rule , 'rule_content':content}
                    except ValidationError as e:
                        bad_rule_content = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
                        return {
                            'valid': False,
                            'file': file,
                            'error': e.message,
                            'content': bad_rule_content
                        }
        except Exception as e:
            return {
                'valid': False,
                'file': file,
                'error': str(e),
                'content': None
            }

async def load_rule_files(repo_dir, license_from_github, repo_url, user):
    """
    Main async function to load all rule files from a repo directory,
    validate them against the Sigma schema, and create rules in the database.

    - Scans the repo directory for YAML files.
    - Loads the Sigma schema.
    - Uses a semaphore to limit concurrent file processing.
    - Validates each file's content.
    - Adds valid rules to the database via RuleModel.add_rule_core.
    - Collects invalid rules with errors for later processing.

    Returns:
    - List of invalid/bad rules with details.
    - Number of bad rules.
    - Number of successfully imported rules.
    - Number of skipped rules (duplicates or failed insert).
    """
    files = await get_rule_files_from_repo(repo_dir)
    sigma_schema =  load_json_schema_sync("app/import_github_project/sigma_format.json")

    if not sigma_schema:
        # If schema cannot be loaded, return empty results
        return [], 0, 0, 0  # bad_rules, nb_bad, imported, skipped

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILES)
    # Create tasks for all files to process them concurrently with limit
    tasks = [_process_single_file(file, sigma_schema, semaphore) for file in files]
    results = await asyncio.gather(*tasks)

    # Filter out bad (invalid) rules
    bad_rules = [res for res in results if not res.get('valid')]
    nb_bad_rules = len(bad_rules)

    imported = 0
    skipped = 0

    # For each valid rule, prepare a dict and insert into the database
    for res in results:
        if res.get('valid'):
            rule = res['rule']
            r , cve = detect_cve(rule.get("description", "No description provided"),)
            rule_dict = {
                "format": "sigma",
                "title": rule.get("title", "Untitled"),
                "license": rule.get("license", license_from_github),
                "description": rule.get("description", "No description provided"),
                "source": repo_url,
                "version": rule.get("version", "1.0"),
                "author": rule.get("author", "Unknown"),
                # Convert back to YAML string for storage
                "to_string": res['rule_content'], #yaml.safe_dump(rule, sort_keys=False), #, allow_unicode=True
                "cve_id": cve
            }
            # Attempt to add the rule to DB; update counters accordingly
            success = RuleModel.add_rule_core(rule_dict, user)
            if success:
                imported += 1
            else:
                skipped += 1

    # Return info about invalid rules and import stats
    return bad_rules, nb_bad_rules, imported, skipped





def find_sigma_rule_by_title(repo_dir, title):
    """
    Find a Sigma rule in the given repo by its title.
    Returns the raw YAML string of the rule if found, otherwise None.
    """

    print(f"🔍 Searching for Sigma rule titled: '{title}' in repo: {repo_dir}")

    if not os.path.exists(repo_dir):
        print(f"❌ Directory does not exist: {repo_dir}")
        return None

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
        for file in files:
            if file.startswith('.') or file.startswith('_'):
                continue
            if file.endswith(('.yml', '.yaml')):
                file_path = os.path.join(root, file)
                print(f"📄 Checking file: {file_path}")

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        parsed = yaml.safe_load(content)

                        if isinstance(parsed, dict):
                            rule_title = parsed.get('title')
                            print(f"   → Found rule title: {rule_title}")
                            if rule_title == title:
                                print(f"✅ Match found in file: {file_path}")
                                return content  # Return raw YAML string
                        else:
                            print(f"⚠️ Skipped non-dict YAML content in {file_path}")
                except Exception as e:
                    print(f"⚠️ Error reading/parsing file {file_path}: {e}")
                    continue

    print("❗ No matching Sigma rule found.")
    return None




#################################################################__Version__sync__#################################################################### 
# import os

# import yaml
# import json
# from jsonschema import validate, ValidationError

# def load_json_schema(schema_file):
#     try:
#         with open(schema_file, 'r', encoding='utf-8') as f:
#             schema = json.load(f)
#         return schema
#     except Exception as e:
#         return None

# def get_rule_files_from_repo(repo_dir):
#     """Retrieve all .yml or .yaml files from a local repository."""
#     rule_files = []

#     if not os.path.exists(repo_dir):
#         return rule_files

#     for root, dirs, files in os.walk(repo_dir):
#         dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
#         for file in files:
#             if file.startswith('.') or file.startswith('_'):
#                 continue
#             if file.endswith(('.yml', '.yaml')):
#                 rule_files.append(os.path.join(root, file))

#     return rule_files




# def load_rule_files(repo_dir, license_from_github, repo_url):
#     """Load and parse rule files from the given repository directory."""
#     files = get_rule_files_from_repo(repo_dir)
#     all_rules = []
#     bad_rules = []
#     sigma_schema = load_json_schema("app/import_github_project/sigma_format.json")
#     if files:
#         for file in files:
#             try:
#                 with open(file, 'r', encoding='utf-8') as f:
#                     rule = yaml.safe_load(f)
#                     rule_json_string = json.dumps(rule, indent=2 , default=str)
#                     rule_json_object = json.loads(rule_json_string)               
#                     if rule:
#                         try:
#                             validate(instance=rule_json_object, schema=sigma_schema)
#                             all_rules.append(rule)
#                         except ValidationError as e:
#                             bad_rule_content = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
#                             bad_rules.append({
#                                 "file": file,
#                                 "error": e.message,
#                                 "content": bad_rule_content
#                             })
#             except Exception as e:
#                 bad_rules.append({
#                     "file": file,
#                     "error": str(e),
#                     "content": None
#                 })  

#     rule_dict_list = []
#     for rule in all_rules:
#         rule_dict = {
#             "format": "sigma",  
#             "title": rule.get("title", "Untitled"), 
#             "license": rule.get("license", license_from_github), 
#             "description": rule.get("description", "No description provided"),
#             "source": repo_url,
#             "version": rule.get("version", "1.0"), 
#             "author": rule.get("author", "Unknown"),  
#             # "to_string": json.dumps(rule, indent=2, default=str) json format
#             "to_string": yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
#         }
#         rule_dict_list.append(rule_dict)
#     return rule_dict_list, bad_rules , len(bad_rules)
