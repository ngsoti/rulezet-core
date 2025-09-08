from typing import Dict, Any, List
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
import os
import yaml
import json
from typing import List, Dict, Any, Optional
from jsonschema import validate, ValidationError

from app.utils.utils import detect_cve


##################
#   Sigma class  #
##################


#
#   Implement the sigma section with check all the abstract method.
#

#-----------------------------------------------#
#   Other method to help (add import ....)      #
#-----------------------------------------------#

class SigmaRule(RuleType):
    """
    Concrete implementation of RuleType for Sigma rules.
    """

    def __init__(self, schema_path: str = "app/import_github_project/sigma_format.json"):
        self.schema = self._load_schema(schema_path)

    @property
    def format(self) -> str:
        return "sigma"

    #---------------------#
    #   Abstract section  #
    #---------------------#

    def _load_schema(self, schema_file: str) -> Optional[Dict[str, Any]]:
        """Load the Sigma JSON schema into memory."""
        if not os.path.exists(schema_file):
            return None
        with open(schema_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a Sigma rule (YAML) against the JSON schema.
        Returns a ValidationResult with possible errors or warnings.
        """
        try:
            rule = yaml.safe_load(content)
            if not rule:
                return ValidationResult(ok=False, errors=["Empty or invalid YAML content."])

            # Normalize to JSON then reload for schema validation
            rule_json_str = json.dumps(rule, indent=2, default=str)
            rule_json_obj = json.loads(rule_json_str)

            validate(instance=rule_json_obj, schema=self.schema)

            return ValidationResult(
                ok=True,
                normalized_content=yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
            )
        except ValidationError as ve:
            return ValidationResult(ok=False, errors=[ve.message], normalized_content=content)
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

    def parse_metadata(self, content: str, info: Dict,  **kwargs) -> Dict[str, Any]:
        """
        Extract key metadata from a Sigma rule.
        """
        rule = yaml.safe_load(content) or {}
        _, cve = detect_cve(rule.get("description", ""))

        return {
            "title": rule.get("title", "Untitled"),
            "format": "Sigma",
            "license": rule.get("license") or info["license_from_github"],
            "description": rule.get("description", "No description provided"),
            "version": rule.get("version", "1.0"),
            "author": rule.get("author", "Unknown"),
            "cve_id": cve,
            "source": rule.get("source") or info["html_url"],
            "to_string": yaml.safe_dump(rule, sort_keys=False, allow_unicode=True),
        }

    def get_rule_files(self, repo_dir: str) -> List[str]:
        """
        Return all YAML rule files (.yml/.yaml) from the given directory,
        skipping hidden or underscore-prefixed files and directories.
        """
        rule_files = []
        if not os.path.exists(repo_dir):
            return rule_files
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue
                if file.endswith(('.yml', '.yaml')):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract individual rules from a YAML file.
        For Sigma, usually one rule per file, but multiple rules are supported.
        Each rule is returned as a YAML string.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                parsed = yaml.safe_load(content)

                if isinstance(parsed, dict):
                    # Single rule per file
                    rules.append(content)
                elif isinstance(parsed, list):
                    # Multiple rules in a single file
                    for rule in parsed:
                        rules.append(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True))
        except Exception:
            # If the file cannot be read or parsed, return empty list
            return []
        return rules
