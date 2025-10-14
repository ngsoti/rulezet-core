import os
import re
import subprocess
from typing import Any, Dict, List
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve

# https://github.com/nmap/nmap.git

class NseRule(RuleType):
    """
    Implementation of RuleType for Nmap NSE scripts.
    """

    @property
    def format(self) -> str:
        return "nse"

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate the NSE rule using luac -p to check syntax.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # write content to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".nse", delete=False) as tmp:
            tmp.write(content.encode("utf-8"))
            tmp.flush()
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["luac", "-p", tmp_path],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                errors.append(result.stderr.strip())
                return ValidationResult(ok=False, errors=errors)

        except FileNotFoundError:
            # luac not installed
            warnings.append("luac not found, syntax not fully validated.")

        finally:
            os.unlink(tmp_path)

        # minimal heuristic: check for action function
        if "function action" not in content:
            warnings.append("Missing action() function in NSE script.")

        return ValidationResult(ok=(len(errors) == 0), errors=errors, warnings=warnings, normalized_content=content)


    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult ) -> Dict[str, Any]:
        """
        Extract metadata from an NSE rule.
        """
        try:
            meta: Dict[str, Any] = {}

            # description = [[ ... ]]
            m = re.search(r'description\s*=\s*\[\[([\s\S]*?)\]\]', content)
            if m:
                meta["description"] = m.group(1).strip()
                _, cve = detect_cve(meta["description"]or "")

            # author / license / version
            for key in ("author", "license", "version"):
                m = re.search(rf'{key}\s*=\s*["\'](.+?)["\']', content)
                if m:
                    meta[key] = m.group(1).strip()

            # categories = {"a","b"}
            m = re.search(r'categories\s*=\s*\{([^\}]*)\}', content)
            if m:
                items = re.findall(r'["\'](.*?)["\']', m.group(1))
                meta["categories"] = items

            # detect rule type
            if re.search(r'\bportrule\b', content):
                meta["rule_type"] = "portrule"
            elif re.search(r'\bhostrule\b', content):
                meta["rule_type"] = "hostrule"
            elif re.search(r'\bprerule\b|\bpostrule\b', content):
                meta["rule_type"] = "prerule/postrule"
            else:
                meta["rule_type"] = "unknown"

            filepath = info.get("filepath")
            if filepath:
                title = os.path.splitext(os.path.basename(filepath))[0]
            else:
                title = "unknown_rule"

           
            return {
                "format": "nse",
                "title": title,
                "license": meta.get("license") or info.get("license") or "unknown",
                "source": info.get("repo_url"),
                "version": meta.get("version", "1.0"),
                "original_uuid": info.get("uuid", "Unknown"),
                "description": meta.get("description") or info.get("description") or "No description provided",
                "author": meta.get("author", "Unknown"),
                "categories": meta.get("categories", []),
                "rule_type": meta.get("rule_type", "unknown"),
                "to_string": validation_result.normalized_content or content,
                "cve_id": None,  # NSE scripts rarely contain explicit CVEs
            }

        except Exception as e:
            return {
                "format": "nse",
                "title": "Invalid Rule",
                "license": info.get("license") or "unknown",
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url"),
                "original_uuid": "Unknown",
                "author": info.get("author") or "Unknown",
                "categories": [],
                "rule_type": "unknown",
                "cve_id": None,
                "to_string": content,
            }



    def get_rule_files(self, repo_dir: str) -> List[str]:
        """
        Return all .nse files inside a repo directory.
        """
        nse_files: List[str] = []
        for root, _, files in os.walk(repo_dir):
            for f in files:
                if f.endswith(".nse"):
                    nse_files.append(os.path.join(root, f))
        return nse_files

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Each NSE file usually contains exactly one script (rule).
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return [f.read()]
        except Exception as e:
            return []

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> str:
        """
        Very simple implementation:
        Return the N-th NSE file found in the repo.
        """
        files = self.get_rule_files(repo_dir)
        if 0 <= rule_id < len(files):
            with open(files[rule_id], "r", encoding="utf-8") as f:
                return f.read()
        raise IndexError("Rule id not found in repository.")