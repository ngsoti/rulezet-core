import os
from typing import Dict, Any, List
import re
import yara

from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve, update_or_clone_repo
from ...rule import rule_core as RuleModel

#################
#   YARA class  #
#################


#
#   Implement the yara section with check all the abstract method.
#

#-----------------------------------------------#
#   Other method to help (add import ....)      #
#-----------------------------------------------#

def insert_import_module(rule_text, module_name):
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text

class YaraRule(RuleType):
    @property
    def format(self) -> str:
        return "yara"

    YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho"}

    

    #---------------------#
    #   Abstract section  #
    #---------------------#
    
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """Try to compile the YARA rule, auto-adding imports if necessary."""
        externals = {}
        attempts = 0
        max_attempts = 10
        current_rule_text = content

        while attempts < max_attempts:
            try:
                yara.compile(source=current_rule_text, externals=externals)
                return ValidationResult(ok=True , errors="" ,normalized_content=current_rule_text)
            except yara.SyntaxError as e:
                error_msg = str(e)

                match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                if match_id:
                    var_name = match_id.group(1)
                    if var_name in self.YARA_MODULES:
                        current_rule_text = insert_import_module(current_rule_text, var_name)
                    else:
                        externals[var_name] = "example.txt"
                    attempts += 1
                    continue

                return ValidationResult(ok=False, errors=[error_msg],  normalized_content=current_rule_text)

        return ValidationResult(ok=False, errors=["Max validation attempts exceeded"] , normalized_content=current_rule_text)

    

    def parse_metadata(self, content: str , info: Dict , validation_result: str) -> Dict[str, Any]:
        """Extract metadata and normalize it into a rule dict."""
        # --- Extract meta block ---
        try:

            meta = {}
            meta_block = re.search(r'meta\s*:\s*(.*?)\n\s*\w+\s*:', content, re.DOTALL)
            if meta_block:
                entries = re.findall(r'(\w+)\s*=\s*"(.*?)"', meta_block.group(1))
                for key, val in entries:
                    meta[key] = val

            # --- Extract rule name ---
            rule_name_match = re.search(r'rule\s+(\w+)', content)
            rule_name = rule_name_match.group(1) if rule_name_match else "unknown_rule"

            # --- Detect CVE in description ---
            _, cve = detect_cve(meta.get("description", "No description provided"))

            # --- Build normalized dict ---
            rule_dict = {
                "format": "yara",
                "title": rule_name,
                "license": meta.get("license") or info["license"] or "unknown",
                "description": meta.get("description") or info["description"] or  "No description provided",
                "source": info["repo_url"] or meta.get("source") ,
                "version": meta.get("version", "1.0"),
                "original_uuid": meta.get("id") or  "Unknown",
                "author": meta.get("author") or info["author"] or "Unknown",
                "to_string": validation_result.normalized_content,
                "cve_id": cve
            }
            return rule_dict
        except Exception as e:
            return {
                "format": "yara",
                "title": "Invalid Rule",
                 "license":  info["license"] or "unknown",
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info["repo_url"],
                "original_uuid":  "Unknown",
                "author": info["author"] or "Unknown",
                "cve_id": None,
                "to_string": content,
            }

    def get_rule_files(self, repo_dir: str) -> List[str]:
        """Retrieve all YARA rule files from a repository."""
        yara_files = []
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue
                if file.endswith(('.yar', '.yara', '.rule')):
                    yara_files.append(os.path.join(root, file))
        return yara_files

    
    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract YARA rules from a file.

        Features:
        - Ignores rules that are inside comments (// or /* */).
        - Correctly handles strings so that '}', //, or /* */ inside quotes
          are treated as part of the string, not as rule terminators or comments.
        - Tracks braces to determine rule boundaries.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Parsing state variables
            brace_level = 0                  # Track nesting of { }
            inside_string = False            # Whether we are inside a "..." or '...'
            string_char = None               # Which quote character started the string
            inside_line_comment = False      # Whether we are inside a // comment
            inside_block_comment = False     # Whether we are inside a /* */ comment
            current_rule = []                # Buffer for the current rule
            in_rule = False                  # Whether we are currently parsing a rule
            escaped = False                  # Handle escape sequences like \" or \'

            i = 0
            while i < len(content):
                
                char = content[i]
                nxt = content[i + 1] if i + 1 < len(content) else ""

                # --- Handle string content ---
                if inside_string:
                    current_rule.append(char)

                    if not escaped and char == string_char:  # End of string
                        inside_string = False
                        string_char = None
                    elif char == "\\" and not escaped:       # Escape character
                        escaped = True
                    else:
                        escaped = False

                    i += 1
                    continue

                # --- Handle comments (only when not inside a string) ---
                if not inside_line_comment and not inside_block_comment:
                    if char == "/" and nxt == "/":  # Start of line comment
                        inside_line_comment = True
                        i += 2
                        continue
                    if char == "/" and nxt == "*":  # Start of block comment
                        inside_block_comment = True
                        i += 2
                        continue

                if inside_line_comment:
                    if char == "\n":               # End of line comment
                        inside_line_comment = False
                    i += 1
                    continue

                if inside_block_comment:
                    if char == "*" and nxt == "/": # End of block comment
                        inside_block_comment = False
                        i += 2
                        continue
                    i += 1
                    continue

                # --- If not inside string or comment ---
                if char in ('"', "'"):             # Start of a string
                    inside_string = True
                    string_char = char
                    escaped = False
                    current_rule.append(char)
                    i += 1
                    continue

                # Detect the beginning of a rule
                if not in_rule and content.startswith("rule", i):
                    in_rule = True
                    current_rule = []

                # Count braces only outside strings and comments
                if char == "{":
                    brace_level += 1
                elif char == "}":
                    brace_level -= 1

                # If we are inside a rule, accumulate its content
                if in_rule:
                    current_rule.append(char)
                    if brace_level == 0 and char == "}":  # Rule is complete
                        rule_text = "".join(current_rule).strip()
                        if rule_text:
                            rules.append(rule_text)
                        in_rule = False
                        current_rule = []

                i += 1

        except Exception as e:
            print(f"[extract_rules_from_file] Error parsing {filepath}: {e}")

        return rules
    
    def find_rule_in_repo(self, repo_url: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a YARA rule inside a locally cloned GitHub repo.
        Repo is stored at: Rules_Github/<owner>/<repo>
        If it already exists → run git pull to update it.
        """
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        local_repo_path = update_or_clone_repo(repo_url)
        if not local_repo_path:
            return "Could not clone or update repo.", False

        yara_files = self.get_rule_files(local_repo_path)

        for filepath in yara_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                match = re.search(r'rule\s+(\w+)', r)
                if match and match.group(1) == rule.title:
                    return r, True

        return f"Rule '{rule.title}' not found inside local repo.", False



  