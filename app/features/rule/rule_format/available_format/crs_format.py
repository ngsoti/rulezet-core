import glob
import os
import re
from typing import Any, Dict, List

from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from flask_login import current_user


import msc_pyparser


def normalize_crs_rule(content: str) -> str:
    """
    Supprime les backslashes de fin de ligne pour normaliser les CRS rules.
    """
    return re.sub(r'\\\s*\n', ' ', content)


# ref A5: 'ctl:ruleEngine=Off' disables the engine entirely for the matching
# request, and 'skipAfter'/'SecMarker' can jump over other rules placed in
# between — both give a rule the same engine-wide suppression power as
# Suricata's pass/bypass (ref A3).
def detect_suppression_risk(content: str) -> dict:
    """
    Detect CRS/ModSecurity directives that can silence the engine
    (ctl:ruleEngine=Off) or redirect control flow across other rules
    (SecMarker / skipAfter), independent of whether the rule is otherwise
    syntactically valid.

    Returns {'flagged': bool, 'reasons': list[str]}.
    """
    reasons = []
    try:
        mparser = msc_pyparser.MSCParser()
        mparser.parser.parse(normalize_crs_rule(content), debug=False)
    except Exception:
        return {'flagged': False, 'reasons': []}

    for line in mparser.configlines:
        if line.get('type') == 'SecMarker':
            reasons.append(
                "Declares a 'SecMarker' — a named target that another rule's "
                "'skipAfter' can jump to, potentially skipping over rules "
                "placed in between, including rules from other authors."
            )
        for action in (line.get('actions') or []):
            act_name = (action.get('act_name') or '').lower()
            if act_name == 'ctl' \
                    and (action.get('act_arg') or '').lower() == 'ruleengine' \
                    and (action.get('act_arg_val') or '').lower() == 'off':
                reasons.append(
                    "Uses 'ctl:ruleEngine=Off', which disables the ModSecurity "
                    "engine entirely for the matching request, silencing every "
                    "other rule."
                )
            if act_name == 'skipafter':
                reasons.append(
                    "Uses 'skipAfter', which skips every rule up to the named "
                    "'SecMarker', potentially bypassing rules from other authors "
                    "placed in between."
                )

    seen = set()
    deduped_reasons = [r for r in reasons if not (r in seen or seen.add(r))]
    return {'flagged': bool(deduped_reasons), 'reasons': deduped_reasons}


class CRSRule(RuleType):
    @property
    def format(self) -> str:
        return "crs"
    
    def get_class(self) -> str:
        return "CRSRule"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a CRS rule with msc_pyparser (syntax only).
        Returns a ValidationResult with possible errors or warnings.
        """
        mparser = msc_pyparser.MSCParser()
        normalized_content = normalize_crs_rule(content)
        try:
            mparser.parser.parse(normalized_content, debug=False)
            risk = detect_suppression_risk(content)
            return ValidationResult(
                ok=True,
                warnings=risk['reasons'],
                normalized_content=normalized_content
            )
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e.args[0])], normalized_content=normalized_content)

    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Parse the single CRS rule
        """


        # title = "unknown"
        
        # filepath = info.get("github_path") or info.get("filepath") 
        # if filepath:
        #     if info.get("filepath"):
        #         title = os.path.splitext(os.path.basename(filepath))[0].split("/")[-1]
        #     else:
        #         title = os.path.splitext(os.path.basename(filepath))[0]

        rule_id = None
    
        id_match = re.search(r'id:(\d+)', content)
        base_id = id_match.group(1) if id_match else "Unknown"

        try:
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(validation_result.normalized_content, debug=False)

            rule_id = None
            for rule in mparser.configlines:
                if rule["type"] == "SecRule":
                    for action in rule["actions"]:
                        if action["act_name"] == "id":
                            rule_id = action["act_arg"]
                            break

            if rule_id is None:
                rule_id = base_id
        
            author = info.get("author", "Unknown")
            if hasattr(current_user, 'first_name'):
                author = info.get("author", current_user.first_name)

            return {
                "title": f"CRS Rule {rule_id}" if rule_id != "Unknown" else "CRS Rule",
                "format": "crs",
                "license": info.get("license", "Unknown"),
                "description": info.get("description", "No description provided"),
                "version": "1.0",
                "author": author,
                "cve_id": '[]',
                "original_uuid": rule_id or "Unknown",
                "source": info.get("repo_url", "Unknown"),
                "to_string": validation_result.normalized_content,
            }
        except Exception as e:
            return {
                "format": "crs",
                "title": f"CRS Rule {base_id} (Metadata Error)",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": base_id,
                "author": info.get("author", "Unknown"),
                "cve_id": '[]',
                "to_string": content,
            }

    def get_rule_files(self, file: str) -> bool:
        if file.endswith('.conf'):
            return True
        return False    

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        rules = [r.strip() for r in content.split("SecRule") if r.strip()]
        rules = [f"SecRule {r}" for r in rules]
        return rules

    def get_rule_files_update(self, repo_dir: str) -> List[str]:
        files = []
        for ext in ["*.conf"]:
            files.extend(glob.glob(os.path.join(repo_dir, "**", ext), recursive=True))
        files = [f for f in files if not os.path.basename(f).startswith(".")]
        return files
    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a CRS rule inside a locally cloned repository.
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        rule_files = self.get_rule_files_update(repo_dir)

        for filepath in rule_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                normalized_rule = normalize_crs_rule(r)
                try:
                    mparser = msc_pyparser.MSCParser()
                    mparser.parser.parse(normalized_rule, debug=False)

                    parsed_id = None
                    for rule_line in mparser.configlines:
                        if rule_line["type"] == "SecRule":
                            for action in rule_line["actions"]:
                                if action["act_name"] == "id":
                                    parsed_id = action["act_arg"]
                                    break

                    if str(parsed_id) == str(rule.original_uuid):
                        return normalized_rule, True

                except Exception:
                    continue

        return f"CRS Rule with ID '{rule.original_uuid}' not found inside repo.", False
