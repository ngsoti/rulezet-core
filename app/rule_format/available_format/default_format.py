import os
from typing import Any, Dict

from git import List
from sympy import re

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve
from ...rule import rule_core as RuleModel

####################
#   Default class  #
####################


#
#   Implement the default section with check all the abstract method.
#


class Defaulrule(RuleType):
    @property
    def format(self) -> str:
        return "default"    # to do 

   

    def get_class(self) -> str:
        return "DefaultRule"    # to do

    #---------------------#
    #   Abstract section  #
    #---------------------#
    
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """Try to compile the Default rule, auto-adding imports if necessary."""
    
        try:
            # compile, execute, validator , etc...  To do 
            return ValidationResult(ok=True , errors="" , normalized_content=content)
        except SyntaxError as e:
                error_msg = str(e)
                return ValidationResult(ok=False, errors=[error_msg],  normalized_content=content)


    

    def parse_metadata(self, content: str , info: Dict , validation_result: str) -> Dict[str, Any]:
        """Extract metadata and normalize it into a rule dict."""
        # --- Extract meta block ---

        # info :
        #       repo_url
        #       author
        #       license


        try:

            meta = {}

            # Simple extraction logic (to be replaced with actual parsing)


            #  Detect CVE from description
            _, cve = detect_cve(meta.get("description", "No description provided"))

            rule_dict = {
                "format": "default",
                "title": meta.get("title") or "Untitled Rule",
                "license": meta.get("license") or info["license"] or "unknown",
                "description": meta.get("description") or info["description"] or  "No description provided",
                "source": info["repo_url"] or meta.get("source") ,
                "version": meta.get("version", "1.0"),
                "original_uuid": meta.get("id") or  "Unknown",
                "author": meta.get("author") or info["author"] or "Unknown",
                "to_string": validation_result.normalized_content,
                "cve_id": meta.get("cve_id") or cve or [],
            }
            return rule_dict
        except Exception as e:
            return {
                "format": "default",
                "title": "Invalid Rule",
                 "license":  info["license"] or "unknown",
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info["repo_url"],
                "original_uuid":  "Unknown",
                "author": info["author"] or "Unknown",
                "cve_id": [],
                "to_string": content,
            }

    def get_rule_files(self, file: str) -> bool:
        """Retrieve all defuly rule files from a repository."""
        if file.endswith(('.default')):      # to do 
            return True
        return False

    
    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """Extract Default rules from a file."""
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Simple extraction logic (to be replaced with actual parsing)
            rules.append(content)
            
        except Exception as e:
            return []

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

        yara_files = self.get_rule_files(repo_url)

        for filepath in yara_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                match = re.search(r'default', r)    # to do regex to identify rule title
                if match and match.group(1) == rule.title:
                    return r, True

        return f"Default Rule '{rule.title}' not found inside local repo.", False



  