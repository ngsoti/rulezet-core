from typing import Any, Dict, List, Optional
import os
import re
from ...rule import rule_core as RuleModel

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult

# Import Nova
from nova import NovaParser, NovaMatcher

from app.utils.utils import detect_cve


#################
#   Nova class  #
#################

class NovaRule(RuleType):
    @property
    def format(self) -> str:
        return "nova"

    def get_class(self) -> str:
        return "NovaRule"
    # ---------------------#
    #   Abstract section   #
    # ---------------------#

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Try to parse a Nova rule. If parsing fails → invalid rule.
        Also check that required sections are present:
            - meta
            - condition
            - at least one of keywords, semantics, llm
        """
        errors = []
        if "meta:" not in content:
            errors.append("Missing 'meta' section")
        if "condition:" not in content:
            errors.append("Missing 'condition' section")
        if not any(section in content for section in ["keywords:", "semantics:", "llm:"]):
            errors.append("Must specify at least one of: keywords, semantics, llm")

        if errors:
            return ValidationResult(
                ok=False,
                errors=errors,
                warnings=[],
                normalized_content=content
            )

        try:
            parser = NovaParser()
            parser.parse(content)
            return ValidationResult(
                ok=True,
                errors=[],
                warnings=[],
                normalized_content=content
            )
        except Exception as e:
            return ValidationResult(
                ok=False,
                errors=[str(e)],
                warnings=[],
                normalized_content=content
            )

    def parse_metadata(self, content: str, info: Dict , validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Extract metadata from the Nova rule.
        """
        rule_name = "unknown_rule"
        try:
            parser = NovaParser()
            rule = parser.parse(content) 
            
            meta_dict = getattr(rule, "meta", {})
            rule_name = getattr(rule, "name", "unknown_rule")
            
            if not rule_name and hasattr(rule, 'attributes') and 'rule_name' in rule.attributes:
                 rule_name = rule.attributes['rule_name']

            description = meta_dict.get("description") or info.get("description") or  "No description provided"
            _, cve = detect_cve(description)
            
            normalized_content = getattr(validation_result, 'normalized_content', content)
            
            return {
                "format": "nova",
                "title": rule_name, 
                "license": meta_dict.get("license") or info.get("license", "unknown"),
                "source": meta_dict.get("source") or info.get("repo_url"),
                "version": meta_dict.get("version", "1.0"),
                "original_uuid": meta_dict.get("uuid") or  "Unknown",
                "description": description,
                "author": meta_dict.get("author", "Unknown"),
                "to_string": normalized_content,
                "cve_id": cve
            }
        except Exception as e:
            return {
                "format": "nova",
                "title": f"{rule_name} (Metadata Error)",
                "license":  info.get("license", "unknown"),
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid":  "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "to_string": content,
            }
        

    def get_rule_files(self, file: str) -> bool:
        """
        Retrieve all Nova rule files (.nov) from a repository.
        """
        if file.endswith(".nov"):
            return True
        return False

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract rules from a Nova rule file.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Naive split: every "rule <name>" starts a new rule
            split_rules = re.split(r'(?=rule\s+\w+)', content, flags=re.IGNORECASE)
            for r in split_rules:
                r = r.strip()
                if r:
                    rules.append(r)
        except Exception as e:
            return []

        return rules

    def get_rule_files_update(self, repo_dir: str) -> List[str]:
        """
        Retrieve all Nova rule files (.nov) from a repository.
        """
        nova_files = []
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.endswith(".nov"):
                    nova_files.append(os.path.join(root, file))
        return nova_files
    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
            """
            Search for a Nova rule inside a locally cloned repository using the rule's title (name).
            """
            rule = RuleModel.get_rule(rule_id)
            if rule is None:
                return f"No rule found with ID {rule_id} in the database.", False

            target_rule_name = rule.title 

            if not target_rule_name:
                return f"Rule {rule_id} has no title in DB.", False

            nova_files = self.get_rule_files_update(repo_dir)

            for filepath in nova_files:
                rules = self.extract_rules_from_file(filepath)
                for r in rules:
                    match = re.search(r'rule\s+(\w+)', r, re.IGNORECASE)
                    
                    if match:
                        found_rule_name = match.group(1)

                        if found_rule_name == target_rule_name:
                            return r, True

            return f"Nova Rule '{target_rule_name}' not found inside local repo.", False