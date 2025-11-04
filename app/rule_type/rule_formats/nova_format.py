from typing import Any, Dict, List, Optional
import os
import re
from ...rule import rule_core as RuleModel

from dataclasses import dataclass, field
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult

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
        # Vérification des sections obligatoires
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
            rule = parser.parse(content)
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

    def parse_metadata(self, content: str, info: Dict , validation_result: str) -> Dict[str, Any]:
        """
        Extract metadata from the Nova rule.
        """
        try:
            parser = NovaParser()
            rule = parser.parse(content)

            # Basic fields
            meta = getattr(rule, "meta", {})
            rule_name = getattr(rule, "name", "unknown_rule")
            _, cve = detect_cve(meta.get("description", "No description provided"))
            return {
                "format": "nova",
                "title": rule_name,
                "license": meta.get("license") or info["license"] or "unknown",
                "source": meta.get("source") or info["repo_url"],
                "version": meta.get("version", "1.0"),
                "original_uuid": meta.get("id") or  "Unknown",
                "description": meta.get("description") or info["description"] or  "No description provided",
                "author": meta.get("author", "Unknown"),
                "to_string": validation_result.normalized_content,
                "cve_id": cve
            }
        except Exception as e:
            return {
                "format": "nova",
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
        

    def get_rule_files(self, file: str) -> bool:
        """
        Retrieve all Nova rule files (.nova) from a repository.
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
            print(f"[extract_rules_from_file] Error parsing {filepath}: {e}")

        return rules

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a Nova rule by its index (for demo purposes).
        """
        rule = RuleModel.get_rule(rule_id)
        if rule is None:
            return f"No rule found with ID {rule_id} in the database.", False
        nova_files = self.get_rule_files(repo_dir)
        count = 0
        for filepath in nova_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                if count == rule_id:
                    return r
                count += 1
        return f"Nova Rule with ID '{rule.uuid}' not found inside repo.", False