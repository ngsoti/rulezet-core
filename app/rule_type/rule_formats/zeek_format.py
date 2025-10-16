import subprocess
import os
import re
import uuid
from typing import Any, Dict, List
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from ...rule import rule_core as RuleModel

class ZeekRule(RuleType):
    """
    Concrete implementation of RuleType for Zeek rules.
    """

    @property
    def format(self) -> str:
        return "zeek"
    
    def get_class(self) -> str:
        return "ZeekRule"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Check the syntax of a Zeek rule by calling `zeek-script parse --quiet`.
        """
        try:
            # Run the Zeek parser CLI
            process = subprocess.run(
                ["zeek-script", "parse", "--quiet", "-"],
                input=content.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if process.returncode == 0:
                return ValidationResult(ok=True, normalized_content=content)
            else:
                return ValidationResult(
                    ok=False,
                    errors=[process.stderr.decode("utf-8").strip() or "Syntax error"],
                    normalized_content=content,
                )
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=content)

    def parse_metadata(self, content: str, info: Dict, validation_result: str) -> Dict[str, Any]:
        """
        Parse a Zeek rule and extract metadata.
        The title is based on the function/event/hook name.
        """
        try:
            # Regex to find function/event/hook
            pattern = re.compile(r"\b(event|function|hook)\s+([a-zA-Z0-9_]+)\s*\(")
            match = pattern.search(content)
            if not match:
                title = f"ZeekRule-{uuid.uuid4()}"
            else:
                _, rule_name = match.groups()
                title = rule_name

            return {
                "format": "zeek",
                "title": title,
                "license": info.get("license", "unknown"),
                "description": info.get("description", "No description provided"),
                "version": info.get("version", "1.0"),
                "original_uuid": None,
                "author": info.get("author", "Unknown"),
                "cve_id": info.get("cve_id", None),
                "source": info.get("repo_url", ""),
                "to_string": content.strip(),
            }

        except Exception as e:
            return {
                "format": "zeek",
                "title": f"ZeekRule-{uuid.uuid4()}",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing rule: {e}",
                "version": "N/A",
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": None,
                "source": info.get("repo_url", ""),
                "to_string": content,
            }

    def get_rule_files(self, repo_dir: str) -> List[str]:
        """
        Retrieve all .zeek files in a local repository.
        """
        rule_files = []
        if not os.path.exists(repo_dir):
            return rule_files

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.endswith(".zeek") and not (file.startswith('.') or file.startswith('_')) or file.endswith(".bro") and not (file.startswith('.')):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract all rules (function/event/hook blocks) from a Zeek file.
        """
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            pattern = re.compile(r"\b(event|function|hook)\s+([a-zA-Z0-9_]+)\s*\(")
            pos = 0
            while True:
                match = pattern.search(content, pos)
                if not match:
                    break

                start_index = match.start()
                brace_count = 0
                inside = False
                end_index = None

                for i in range(start_index, len(content)):
                    if content[i] == "{":
                        brace_count += 1
                        inside = True
                    elif content[i] == "}":
                        brace_count -= 1
                        if inside and brace_count == 0:
                            end_index = i + 1
                            break

                if end_index:
                    rule_code = content[start_index:end_index]
                    rules.append(rule_code.strip())
                    pos = end_index
                else:
                    break

        except Exception:
            return []
        return rules

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a rule in a local repository by its ID (generated UUID).
        """
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False
        rule_files = self.get_rule_files(repo_dir)
        for filepath in rule_files:
            rules = self.extract_rules_from_file(filepath)
            for r in rules:
                if str(rule_id) in r:
                    return r , True
        return f"Zeek Rule with ID '{rule.uuid}' not found inside repo.", False