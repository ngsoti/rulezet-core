import os
import re
from typing import List, Dict, Any
from suricataparser import parse_rules, parse_rule
from ...rule import rule_core as RuleModel
from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve


class SuricataRule(RuleType):
    """
    Concrete implementation of RuleType for Suricata rules.
    """

    @property
    def format(self) -> str:
        return "suricata"
    
    def get_class(self) -> str:
        return "SuricataRule"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate Suricata rules.
        """
        try:
            rules = parse_rules(content)
            if not rules:
                return ValidationResult(ok=False, errors=["No valid Suricata rules found."], normalized_content=content)

            return ValidationResult(
                ok=True,
                normalized_content="\n".join([rule.raw for rule in rules])
            )
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Extract metadata from a Suricata rule string.
        """

        msg_match = re.search(r'msg\s*:\s*"(.*?)"', content)
        sid_match = re.search(r'sid\s*:\s*(\d+)', content)
        rev_match = re.search(r'rev\s*:\s*(\d+)', content)
        
        fallback_title = msg_match.group(1).strip() if msg_match else "Untitled Suricata Rule"
        fallback_sid = sid_match.group(1) if sid_match else "Unknown"
        fallback_rev = rev_match.group(1) if rev_match else "1"

        try:
            clean_content = content
            for line in content.splitlines():
                if line.strip() and not line.strip().startswith('#'):
                    clean_content = line
                    break

            rule = parse_rule(clean_content)
            parsed_title = rule.msg or fallback_title
            
            _, cve = detect_cve(parsed_title)

            return {
                "format": "suricata",
                "title": parsed_title,
                "license": info.get("license", "unknown"),
                "description": info.get("description", "No description provided"),
                "version": str(rule.rev) if rule.rev else fallback_rev,
                "author": info.get("author", "Unknown"),
                "cve_id": cve,
                "original_uuid": str(rule.sid) if rule.sid else fallback_sid,
                "source": info.get("repo_url", "Unknown"),
                "to_string": content,
            }
        except Exception as e:
            _, cve = detect_cve(fallback_title)
            return {
                "format": "suricata",
                "title": f"{fallback_title} (Partial Parse)",
                "license": info.get("license", "unknown"),
                "description": f"Metadata parsing issue: {str(e)}",
                "version": fallback_rev,
                "original_uuid": fallback_sid,
                "author": info.get("author", "Unknown"),
                "cve_id": cve,
                "to_string": content,
            }

    def get_rule_files(self, file: str) -> bool:
        return file.endswith(('.rule', '.rules'))

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract raw Suricata rules from a file, skipping empty lines.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                # parse_rules gère nativement les fichiers avec plusieurs règles
                parsed_rules = parse_rules(content)
                for rule in parsed_rules:
                    if rule.raw:
                        rules.append(rule.raw.strip())
        except Exception as e:
            return []
        return rules

    def get_rule_files_update(self, repo_dir: str) -> List[str]:
        rule_files = []
        if not os.path.exists(repo_dir):
            return rule_files

        for root, dirs, files in os.walk(repo_dir):
            # Ignorer les dossiers cachés
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if not file.startswith('.') and not file.startswith('_'):
                    if self.get_rule_files(file):
                        rule_files.append(os.path.join(root, file))
        return rule_files

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a Suricata rule by its original SID inside the repo.
        """
        rule_db = RuleModel.get_rule(rule_id)
        if not rule_db:
            return "No rule found in the database.", False

        rule_files = self.get_rule_files_update(repo_dir)

        for filepath in rule_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    parsed_rules = parse_rules(content)
                    for parsed_rule in parsed_rules:
                        # Comparaison des SIDs
                        if str(parsed_rule.sid) == str(rule_db.original_uuid):
                            return parsed_rule.raw, True
            except Exception:
                continue

        return f"Suricata rule with SID '{rule_db.original_uuid}' not found.", False