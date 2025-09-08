import os
from typing import List, Dict, Any, Optional
from suricataparser import parse_rules

from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve


class SuricataRule(RuleType):
    """
    Concrete implementation of RuleType for Suricata rules.
    """

    @property
    def format(self) -> str:
        return "suricata"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a Suricata rule using suricataparser.
        Returns a ValidationResult with errors if the rule is invalid.
        """
        try:
            rules = parse_rules(content)
            if not rules:
                return ValidationResult(ok=False, errors=["No valid Suricata rules found."], normalized_content=content)

            # If suricataparser successfully parsed it, we consider it valid
            return ValidationResult(
                ok=True,
                normalized_content="\n".join([rule.raw for rule in rules])
            )
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

    def parse_metadata(self, content: str, info: Dict,  **kwargs) -> Dict[str, Any]:
        """
        Extract metadata from a Suricata rule.
        """
        try:
            rules = parse_rules(content)
            _ , cve = detect_cve(info.get("description", "No description provided"))
            if not rules:
                return {
                    "format": "suricata",
                    "title": "Invalid Rule",
                    "license": kwargs.get("default_license") or info["license_from_github"],
                    "description": "Failed to parse Suricata rule.",
                    "version": "N/A",
                    "author": kwargs.get("author", "Unknown"),
                    "cve_id": cve or None,
                    "source": info["html_url"],
                    "to_string": content,
                }

            rule = rules[0]  # take first parsed rule
            _, cve = detect_cve(rule.msg or "")

            return {
                "format": "suricata",
                "title": rule.msg or "Untitled",
                "license": kwargs.get("default_license") or info["license_from_github"],
                "description": kwargs.get("description", "No description provided"),
                "version": rule.rev or "1.0",
                "author": kwargs.get("author", "Unknown"),
                "cve_id": cve,
                "source": info["html_url"],
                "to_string": rule.raw,
            }
        except Exception as e:
            return {
                "format": "suricata",
                "title": "Invalid Rule",
                "license": kwargs.get("default_license") or info["license_from_github"],
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "author": kwargs.get("author", "Unknown"),
                "cve_id": None,
                "to_string": content,
            }

    def get_rule_files(self, repo_dir: str) -> List[str]:
        """
        Retrieve all Suricata rule files (.rule / .rules) from a local repository.
        Hidden and underscore-prefixed files or directories are ignored.
        """
        rule_files = []
        if not os.path.exists(repo_dir):
            return rule_files

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue
                if file.endswith(('.rule', '.rules')):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract raw Suricata rules from a file.
        Each rule is returned as a string.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                parsed_rules = parse_rules(content)

                for rule in parsed_rules:
                    rules.append(rule.raw)
        except Exception:
            return []
        return rules
