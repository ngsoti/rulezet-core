from typing import Dict, Any, List, Optional
from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
import inspect
import os
import yaml
import json
from jsonschema import validate, ValidationError

from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssueSeverity
import sigma.validators.core.condition as _sigma_condition
import sigma.validators.core.logsources as _sigma_logsources
import sigma.validators.core.metadata as _sigma_metadata
import sigma.validators.core.modifiers as _sigma_modifiers
import sigma.validators.core.tags as _sigma_tags
import sigma.validators.core.values as _sigma_values

from app.core.utils.utils import detect_cve


def _collect_sigma_validators() -> list:
    """Collect all concrete SigmaRuleValidator subclasses from the core validators."""
    validators = []
    seen = set()
    for mod in [
        _sigma_condition,
        _sigma_logsources,
        _sigma_metadata,
        _sigma_modifiers,
        _sigma_tags,
        _sigma_values,
    ]:
        for _name, cls in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(cls, SigmaRuleValidator)
                and cls is not SigmaRuleValidator
                and not inspect.isabstract(cls)
                and cls not in seen
            ):
                seen.add(cls)
                validators.append(cls)
    return validators


_SIGMA_VALIDATORS = _collect_sigma_validators()


##################
#   Sigma class  #
##################

class SigmaRule(RuleType):
    """
    Concrete implementation of RuleType for Sigma rules.
    """

    def __init__(self, schema_path: str = "app/features/rule/rule_format/schema_format/sigma_format.json"):
        self.schema = self._load_schema(schema_path)

    @property
    def format(self) -> str:
        return "sigma"

    def get_class(self) -> str:
        return "SigmaRule"

    def _load_schema(self, schema_file: str) -> Optional[Dict[str, Any]]:
        """Load the Sigma JSON schema into memory."""
        if not os.path.exists(schema_file):
            return None
        with open(schema_file, "r", encoding="utf-8") as f:
            return json.load(f)

    ##############################
    #        VALIDATION          #
    ##############################
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a Sigma rule (YAML) against the JSON schema, then run full
        pySigma validation.
        Does NOT modify or re-dump YAML → preserves quotes.
        """
        try:
            rule = yaml.safe_load(content)

            if rule is None or not isinstance(rule, dict):
                return ValidationResult(
                    ok=False,
                    errors=["Empty or invalid YAML content or not a single rule object."],
                    normalized_content=content
                )

           
            rule_json_str = json.dumps(rule, indent=2, default=str)
            rule_json_obj = json.loads(rule_json_str)
            validate(instance=rule_json_obj, schema=self.schema)

        except ValidationError as ve:
            return ValidationResult(ok=False, errors=[ve.message], normalized_content=content)
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

        # pySigma parsing — any exception is a hard validation failure
        try:
            sigma_collection = SigmaCollection.from_yaml(content)
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

        # pySigma semantic validation — report high-severity issues
        try:
            validator = SigmaValidator(validators=_SIGMA_VALIDATORS)
            issues = validator.validate_rules(sigma_collection)
            high_errors = [
                str(issue)
                for issue in issues
                if issue.severity == SigmaValidationIssueSeverity.HIGH
            ]
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

        if high_errors:
            return ValidationResult(ok=False, errors=high_errors, normalized_content=content)

        return ValidationResult(
            ok=True,
            normalized_content=content
        )

    ##############################
    #       META PARSING         #
    ##############################
    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Extract key metadata from a Sigma rule.
        Never re-dumps YAML → preserves original formatting.
        """
        title = "Untitled"
        try:
            rule = yaml.safe_load(content)

            if rule is None or not isinstance(rule, dict):
                rule_id_hint = info.get("original_uuid") or "Unknown"
                title = f"Untitled Sigma Rule ID:{rule_id_hint}"
                raise ValueError("Content is empty or not valid YAML.")

            title = rule.get("title", "Untitled")
            _, cve = detect_cve(rule.get("description", ""))

            return {
                "title": title,
                "format": "sigma",
                "license": rule.get("license") or info.get("license", "Unknown"),
                "description": rule.get("description", "No description provided"),
                "version": rule.get("version", "1.0"),
                "author": rule.get("author", "Unknown"),
                "cve_id": cve,
                "original_uuid": rule.get("id", "Unknown"),
                "source": rule.get("source") or info.get("repo_url", "Unknown"),
                "to_string": content  
            }

        except Exception as e:
            return {
                "format": "sigma",
                "title": f"{title} (Metadata Error)",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "to_string": content,
            }

    ##############################
    #         FILE LISTING       #
    ##############################
    def get_rule_files(self, file: str) -> bool:
        return file.endswith(('.yml', '.yaml'))

    ##############################
    #         EXTRACTION         #
    ##############################
    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract rules from YAML file.
        Never re-dumps → returns original raw rule text.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                parsed = yaml.safe_load(content)

                if parsed is None:
                    return []

                if isinstance(parsed, dict):
                    return [content]  # keep file EXACTLY as is

                elif isinstance(parsed, list):
                    rules = []
                    for rule in parsed:
                        if isinstance(rule, dict):
                            # KEEP ORIGINAL QUOTES — DO NOT safe_dump
                            rules.append(yaml.dump(rule, sort_keys=False, allow_unicode=True))
                    return rules
        except Exception:
            return []
        return []

    ##############################
    #      SEARCH IN REPO        #
    ##############################
    def get_rule_files_update(self, repo_dir: str) -> List[str]:
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

    def find_rule_in_repo(self, repo_url: str, rule_id: int) -> tuple[str, bool]:
        """
        Return the EXACT YAML rule from the repo without modifying anything.
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        sigma_files = self.get_rule_files_update(repo_url)

        for path in sigma_files:
            rules = self.extract_rules_from_file(path)
            for raw in rules:
                try:
                    parsed = yaml.safe_load(raw)
                    if not parsed or not isinstance(parsed, dict):
                        continue

                    if parsed.get("title") == rule.title or parsed.get("id") == rule.original_uuid:
                        return raw, True  # RETURN EXACT RAW YAML
                except Exception:
                    continue

        return f"Sigma rule '{rule.title}' not found inside local repo.", False
