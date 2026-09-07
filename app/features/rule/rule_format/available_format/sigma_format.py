from typing import Dict, Any, List, Optional
from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
import os
import yaml
import json
from jsonschema import ValidationError
from jsonschema.validators import validator_for

from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core import validators as _sigma_validators

from app.core.utils.utils import detect_cve


##################
#   Sigma class  #
##################

class SigmaRule(RuleType):
    """
    Concrete implementation of RuleType for Sigma rules.
    """

    def __init__(self, schema_path: str = "app/features/rule/rule_format/schema_format/sigma_format.json"):
        self.schema = self._load_schema(schema_path)
        # Built once per instance and reused — jsonschema.validate(instance, schema)
        # recompiles the whole schema (incl. $ref resolution) on every call, which
        # dominated per-rule scoring cost (~15ms of ~20ms spent in validate()).
        self._json_validator = validator_for(self.schema)(self.schema) if self.schema else None

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
            if self._json_validator is not None:
                self._json_validator.validate(rule_json_obj)

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
            validator = SigmaValidator(validators=_sigma_validators.values())
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
    #        FORMAT DETECT       #
    ##############################
    def detect(self, content: str) -> bool:
        """
        Identify a Sigma rule by its mandatory top-level fields.
        Both `logsource` and `detection` are required by the Sigma spec and
        are absent from every other YAML-based format (ATR, Wazuh, …).
        This prevents the alphabetical-load fallback from mis-assigning
        Sigma files to ATR when both formats claim .yml/.yaml.
        """
        try:
            doc = yaml.safe_load(content)
        except Exception:
            return False
        if not isinstance(doc, dict):
            return False
        return (
            isinstance(doc.get('logsource'), dict) and
            isinstance(doc.get('detection'), dict)
        )

    ##############################
    #     DOCUMENTATION SIGNALS  #
    ##############################
    def documentation_signals(self, content: str) -> Dict[str, bool]:
        """Sigma-specific documentation checklist, straight from the spec's
        optional-but-conventional fields."""
        try:
            rule = yaml.safe_load(content)
        except Exception:
            return {}
        if not isinstance(rule, dict):
            return {}
        references = rule.get("references")
        falsepositives = rule.get("falsepositives")
        # Named "documents_*" rather than "has_*" — this reports whether the
        # rule's metadata DOCUMENTS these fields (e.g. lists known FP
        # scenarios), not whether the rule itself has false positives.
        return {
            "documents_references": isinstance(references, list) and len(references) > 0,
            "documents_falsepositives": isinstance(falsepositives, list) and len(falsepositives) > 0,
            "documents_severity_level": bool(rule.get("level")),
            "documents_taxonomy_tags": isinstance(rule.get("tags"), list) and len(rule.get("tags")) > 0,
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

        Self-filters a single-document file through detect() (same as
        atr_format.py / splunk_format.py) — this method can be called
        directly (e.g. find_rule_in_repo scanning every .yml in a repo)
        without going through the candidate/detect() disambiguation that
        main_format.py and session_class.py apply first, so an ATR/Splunk
        file sitting next to real Sigma rules must not be misreported as
        a Sigma one.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                parsed = yaml.safe_load(content)

                if parsed is None:
                    return []

                if isinstance(parsed, dict):
                    return [content] if self.detect(content) else []  # keep file EXACTLY as is

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
        for root, dirs, files in os.walk(repo_dir, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')
                       and not os.path.islink(os.path.join(root, d))]
            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue
                filepath = os.path.join(root, file)
                # Reject symlinks — open() would otherwise follow one straight
                # to its target and leak arbitrary filesystem content as a "rule".
                if os.path.islink(filepath):
                    continue
                if file.endswith(('.yml', '.yaml')):
                    rule_files.append(filepath)
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
