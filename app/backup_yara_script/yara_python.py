from git import Repo
import plyara
import plyara.utils
import os
import re

def clone_or_access_repo_v1(repo_url):
    base_dir = "Rules_Github"
    os.makedirs(base_dir, exist_ok=True)

    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    repo_dir = os.path.join(base_dir, repo_name)

    if not os.path.exists(repo_dir):
        Repo.clone_from(repo_url, repo_dir)
    else:
        pass

    return repo_dir, repo_dir


def get_yara_files_from_repo(repo_dir):
    yara_files = []
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.lower().endswith(('.yar', '.yara')):
                yara_files.append(os.path.join(root, file))
    return yara_files


def remove_comments(yara_content):
    yara_content = re.sub(r'//.*', '', yara_content)  
    yara_content = re.sub(r'/\*.*?\*/', '', yara_content, flags=re.DOTALL) 
    return yara_content



def sanitize_rule_name(name):
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if re.match(r'^\d', sanitized):
        sanitized = "rule_" + sanitized
    return sanitized



def extract_yara_rules(yara_file, source_url="Unknown"):
    if not os.path.exists(yara_file):
        return []

    with open(yara_file, 'r') as file:
        yara_content = file.read()

    rule_block_pattern = re.compile(
        r'rule\s+(\w[\w\d_.-]*)\s*(?::\s*[\w\s_-]+)?\s*({(?:[^{}]*|{[^}]*})*})', re.DOTALL
    )

    corrected_blocks = []

    for match in rule_block_pattern.finditer(yara_content):
        original_name = match.group(1)
        body = match.group(2)
        new_name = original_name
        if not plyara.utils.is_valid_rule_name(original_name):
            new_name = sanitize_rule_name(original_name)
        rule_block = f"rule {new_name} {body}"
        corrected_blocks.append(rule_block)

    filtered_content = "\n\n".join(corrected_blocks)
    parser = plyara.Plyara()
    parsed_rules = parser.parse_string(filtered_content)


    rules_info = []

    with open(yara_file, 'r') as file:
        original_lines = file.readlines()

    for rule_info in parsed_rules:
        title = rule_info['rule_name']
        license = 'Unknown'
        description = 'No description'
        author = 'Unknown'

        for item in rule_info.get('metadata', []):
            if 'description' in item:
                description = item['description']
            elif 'Description' in item:
                description = item['Description']
            if 'author' in item:
                author = item['author']
            elif 'Author' in item:
                author = item['Author']
            if 'license' in item:
                license = item['license']
            elif 'License' in item:
                license = item['License']

        start = rule_info.get('start_line', 1) - 1
        stop = rule_info.get('stop_line', start + 1)
        rule_lines = original_lines[start:stop]
        raw_content = ''.join(rule_lines)

        rule_dict = {
            "format": "YARA",
            "title": title,
            "license": license,
            "description": description,
            "source": source_url,
            "version": "1.0",
            "author": author,
            "to_string": raw_content
        }

        # rules_info.append(rule_dict)


    
        RuleModel.add_rule_core(rule_dict)


    return rules_info
from ..rule import rule_core as RuleModel


















# <div class="card p-4 shadow-sm bg-light mb-3">
#         <h5><label for="url" class="form-label">URL for a Github project to add (YARA)</label></h5>
#         <form method="POST" action="{{ url_for('rule.test_zeek_rules_parse') }}" class="d-flex">
#           <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#           <div class="mb-3 flex-grow-1 me-2">
#             <input type="text" name="url" class="form-control" id="url" placeholder="https://github.com/your_username/name_project.git" required>
#           </div>
#           <div class="d-flex align-items-center" style="height: 100%;">
#             <button type="submit" class="btn btn-primary" style="max-width: fit-content; height: 100%;">
#               <i class="fas fa-paper-plane"></i> Send
#             </button>
#           </div>
#         </form>        
#       </div>



#       <div class="card p-4 shadow-sm bg-light mb-3">
#         <h5><label for="url" class="form-label">URL for a Github project to add  (SIGMA)</label></h5>
#         <form method="POST" action="{{ url_for('rule.test_sigma_rules_parse') }}" class="d-flex">
#           <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#           <div class="mb-3 flex-grow-1 me-2">
#             <input type="text" name="url" class="form-control" id="url" placeholder="https://github.com/your_username/name_project.git" required>
#           </div>
#           <div class="d-flex align-items-center" style="height: 100%;">
#             <button type="submit" class="btn btn-primary" style="max-width: fit-content; height: 100%;">
#               <i class="fas fa-paper-plane"></i> Send
#             </button>
#           </div>
#         </form>        
#       </div> 