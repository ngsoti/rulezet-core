import os
from typing import List, Dict, Any
from suricataparser import parse_rules
from suricataparser import parse_rule
from ...rule import rule_core as RuleModel
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

    def parse_metadata(self, content: str, info: Dict,  validation_result: str) -> Dict[str, Any]:
        """
        Extract metadata from a Suricata rule.
        """
        try:
            rule = parse_rule(content)
            _, cve = detect_cve(rule.msg or "")

            return {
                "format": "suricata",
                "title": rule.msg or "Untitled",
                "license":  info["license"] or "unknown",
                "description": info["description"] or  "No description provided",
                "version": rule.rev or "1.0",
                "author": info["author"] or "Unknown",
                "cve_id": cve,
                "original_uuid": rule.sid or  "Unknown",
                "source": info["repo_url"],
                "to_string": rule.raw,
            }
        except Exception as e:
            return {
                "format": "suricata",
                "title": "Invalid Rule",
                "license":  info["license"] or "unknown",
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "original_uuid":  "Unknown",
                "author": info["author"] or "Unknown",
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

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a Suricata rule inside a locally cloned GitHub repo.
        """
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        rule_files = self.get_rule_files(repo_dir)

        for filepath in rule_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                try:
                    parsed_rules = parse_rules(r)
                    for parsed_rule in parsed_rules:
                        if str(parsed_rule.sid) == str(rule.original_uuid):
                            return r, True
                except Exception:
                    continue

        return f"Rule with SID '{rule.original_uuid}' not found inside repo.", False
