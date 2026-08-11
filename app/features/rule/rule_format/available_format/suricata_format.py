import os
import re
from typing import List, Dict, Any
from suricataparser import parse_rules, parse_rule

from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.core.utils.utils import detect_cve

# ref A3: 'pass' silences the engine for matching traffic without referencing
# the rule it overrides, and 'bypass' stops further inspection for the flow —
# both give a rule engine-wide suppression power over other sources' rules.
_HASH_TRANSFORM_KEYWORDS = ('to_sha256', 'to_md5', 'to_sha1')


def detect_suppression_risk(content: str) -> dict:
    """
    Detect Suricata constructs that can silence detection for other rules'
    traffic, independent of whether the rule is otherwise syntactically valid.

    A plain 'pass' action or 'bypass' keyword is flagged but not rejected —
    it has legitimate uses. Combined with a hash transform (to_sha256/to_md5/
    to_sha1) on a 'pass'/'drop' rule or one using 'bypass', it can be used to
    silently suppress detection for one specific hashed value and is rejected.

    Returns {'flagged': bool, 'rejected': bool, 'reasons': list[str]}.
    """
    reasons = []
    rejected = False
    try:
        rules = parse_rules(content)
    except Exception:
        return {'flagged': False, 'rejected': False, 'reasons': []}

    for rule in rules:
        action = (rule.action or '').lower()
        option_names = {opt.name.lower() for opt in rule.options}
        has_bypass = 'bypass' in option_names
        hash_keywords = option_names & set(_HASH_TRANSFORM_KEYWORDS)

        if action == 'pass':
            reasons.append(
                "Uses the 'pass' action, which silences detection for matching "
                "traffic without referencing the rule(s) it overrides."
            )
        if has_bypass:
            reasons.append(
                "Uses the 'bypass' keyword, which stops further inspection for "
                "the matching flow."
            )

        if hash_keywords and (action in ('pass', 'drop') or has_bypass):
            rejected = True
            reasons.append(
                f"Combines a hash transform ({', '.join(sorted(hash_keywords))}) with a "
                f"'{action}'{' + bypass' if has_bypass else ''} rule — this pattern can "
                "silently suppress detection for one specific hashed value and is rejected."
            )

    # de-duplicate while preserving order (multiple rules in the same
    # submission can trigger the same reason)
    seen = set()
    deduped_reasons = [r for r in reasons if not (r in seen or seen.add(r))]

    return {'flagged': bool(deduped_reasons), 'rejected': rejected, 'reasons': deduped_reasons}


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

            risk = detect_suppression_risk(content)
            if risk['rejected']:
                return ValidationResult(ok=False, errors=risk['reasons'], normalized_content=content)

            return ValidationResult(
                ok=True,
                warnings=risk['reasons'] if risk['flagged'] else [],
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
        rule_db = get_rule(rule_id)
        if not rule_db:
            return "No rule found in the database.", False

        rule_files = self.get_rule_files_update(repo_dir)

        for filepath in rule_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    parsed_rules = parse_rules(content)
                    for parsed_rule in parsed_rules:
                        if str(parsed_rule.sid) == str(rule_db.original_uuid):
                            return parsed_rule.raw, True
            except Exception:
                continue

        return f"Suricata rule with SID '{rule_db.original_uuid}' not found.", False