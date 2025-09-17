import os
import glob
from typing import Any, Dict, List
from flask_login import current_user
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult

from detection_rules.rule import TOMLRule
import tomlkit

class ElasticDetectionRule(RuleType):
    @property
    def format(self) -> str:
        return "elastic"

    def normalize_multiline_strings(self, data: dict) -> dict:
        """
        Recursively convert multiline strings in dict/lists to single-line strings.
        """
        for k, v in data.items():
            if isinstance(v, dict):
                self.normalize_multiline_strings(v)
            elif isinstance(v, list):
                data[k] = [self.normalize_multiline_strings(x) if isinstance(x, dict) else (str(x).replace("\n", " ") if isinstance(x, str) else x) for x in v]
            elif isinstance(v, str):
                data[k] = v.replace("\n", " ")
        return data

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate an Elastic detection rule using detection_rules.
        """
        try:
            data = tomlkit.loads(content)
            data = self.normalize_multiline_strings(data)
            # Utilisation de TOMLRule pour valider la structure
            rule = TOMLRule(data, path="<inline>")
            return ValidationResult(
                ok=True,
                normalized_content=content
            )
        except Exception as e:
            return ValidationResult(
                ok=False,
                errors=[str(e)],
                normalized_content=content
            )

    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Extract metadata from an Elastic detection rule (.toml format).
        Uses tomlkit for better multiline/string handling.
        """
        try:
            toml_content = validation_result.normalized_content or content
            data = tomlkit.loads(toml_content)
            data = self.normalize_multiline_strings(data)

            rule_section = data.get("rule", {})
            metadata_section = data.get("metadata", {})

            print("[DEBUG] Loaded TOML data:", data)
            print("[DEBUG] rule_section:", rule_section)
            print("[DEBUG] metadata_section:", metadata_section)

            title = rule_section.get("name") or metadata_section.get("name") or info.get("title") or f"Elastic Rule ({info.get('file_name', '')})"
            description = rule_section.get("description") or metadata_section.get("description") or info.get("description") or "No description provided"
            original_uuid = rule_section.get("rule_id") or metadata_section.get("rule_id") or info.get("rule_id") or "Unknown"
            version = metadata_section.get("version") or data.get("version") or "1.0"
            license_val = rule_section.get("license") or info.get("license", "Elastic License v2")
            author_val = rule_section.get("author") or [info.get("author", getattr(current_user, "first_name", "Unknown"))]

            return {
                "title": title,
                "format": "elastic",
                "license": license_val,
                "description": description,
                "version": version,
                "author": author_val,
                "cve_id": None,
                "original_uuid": original_uuid,
                "source": info.get("repo_url", "Unknown"),
                "to_string": toml_content,
            }

        except Exception as e:
            print(f"[ERROR] Exception in parse_metadata: {e}")
            return {
                "format": "elastic",
                "title": "Invalid Rule",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": None,
                "to_string": content,
            }

    def get_rule_files(self, repo_dir: str) -> List[str]:
        files = glob.glob(os.path.join(repo_dir, "rules", "**", "*.toml"), recursive=True)
        return [f for f in files if not os.path.basename(f).startswith(".")]

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return [content]

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        rule_files = self.get_rule_files(repo_dir)
        for filepath in rule_files:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            try:
                data = tomlkit.loads(content)
                rule_section = data.get("rule", {})
                if str(rule_section.get("rule_id")) == str(rule_id):
                    return content, True
            except Exception:
                continue
        return f"Elastic Detection Rule with ID '{rule_id}' not found inside repo.", False
