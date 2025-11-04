import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from ...rule import rule_core as RuleModel
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve


class WazuhRule(RuleType):
    """
    Concrete implementation of RuleType for Wazuh (XML-based) rules.
    """

    @property
    def format(self) -> str:
        return "wazuh"
    
    def get_class(self) -> str:
        return "WazuhRule"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate XML syntax of a Wazuh rule file or a single <rule>.
        """
        try:
            root = ET.fromstring(content)

            if root.tag == "rule":
                return ValidationResult(ok=True, normalized_content=content)

            rules = root.findall(".//rule")
            if not rules:
                return ValidationResult(
                    ok=False,
                    errors=["No <rule> elements found."],
                    normalized_content=content
                )

            return ValidationResult(ok=True, normalized_content=content)

        except ET.ParseError as e:
            return ValidationResult(
                ok=False,
                errors=[f"XML Parse error: {e}"],
                normalized_content=content
            )
        except Exception as e:
            return ValidationResult(
                ok=False,
                errors=[str(e)],
                normalized_content=content
            )


    def parse_metadata(self, content: str, info: Dict[str, Any], validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Extract metadata from a Wazuh rule.
        """
        try:
            root = ET.fromstring(content)

            if root.tag == "rule":
                rule = root
            else:
                rule = root.find(".//rule")

            if rule is None:
                return {
                    "format": "wazuh",
                    "title": f"Invalid Rule",
                    "description": "No <rule> element found",
                    "license": info.get("license", "unknown"),
                    "version": "N/A",
                    "author": info.get("author", "Unknown"),
                    "cve_id": None,
                    "original_uuid": "Unknown",
                    "source": info.get("repo_url", ""),
                    "to_string": validation_result.normalized_content or content,
                }

            description = rule.findtext("description")
            if not description:
                description = f"Wazuh rule {rule.get('id', 'Unknown')}"

            _, cve = detect_cve(description)

            return {
                "format": "wazuh",
                "title": description[:50],
                "description": description,
                "license": info.get("license", "unknown"),
                "version": rule.get("level", "1"),
                "author": info.get("author", "Unknown"),
                "cve_id": cve,
                "original_uuid": rule.get("id", "Unknown"),
                "source": info.get("repo_url", ""),
                "to_string": validation_result.normalized_content or content,
            }

        except Exception as e:
            return {
                "format": "wazuh",
                "title": "Invalid Rule",
                "description": f"Error parsing metadata: {e}",
                "license": info.get("license", "unknown"),
                "version": "N/A",
                "author": info.get("author", "Unknown"),
                "cve_id": None,
                "original_uuid": "Unknown",
                "source": info.get("repo_url", ""),
                "to_string": content,
            }


    def get_rule_files(self, file: str) -> bool:
        """
        Get all Wazuh XML rule files from a repo.
        """
        if file.endswith(".xml") and "rules" in file.lower():
            return True
        return False

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract <rule> elements from an XML file.
        Each rule is returned as a string (XML snippet).
        """
        rules = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for rule in root.findall(".//rule"):
                rules.append(ET.tostring(rule, encoding="unicode"))
        except Exception:
            return []
        return rules

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a Wazuh rule with given ID inside a repo.
        """
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        rule_files = self.get_rule_files(repo_dir)
        for filepath in rule_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                try:
                    element = ET.fromstring(r)
                    if element.get("id") == str(rule.original_uuid):
                        return r, True
                except Exception:
                    continue

        return f"Wazuh rule with ID '{rule.original_uuid}' not found inside repo.", False
