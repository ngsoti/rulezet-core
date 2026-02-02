import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List
from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.utils.utils import detect_cve
from ...rule import rule_core as RuleModel
import base64

class NseRule(RuleType):
    """
    NSE Rule implementation with 5 mandatory methods and robust title extraction.
    """

    @property
    def format(self) -> str:
        return "nse"
    
    def get_class(self) -> str:
        return "NseRule"

    # 1. VALIDATE
    def validate(self, content: str, **kwargs) -> ValidationResult:
        errors = []
        warnings = []
        
        with tempfile.NamedTemporaryFile(suffix=".nse", delete=False) as tmp:
            tmp.write(content.encode("utf-8"))
            tmp_path = tmp.name

        try:
            result = subprocess.run(["luac", "-p", tmp_path], capture_output=True, text=True)
            if result.returncode != 0:
                errors.append(result.stderr.strip())
        except FileNotFoundError:
            warnings.append("luac not found")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        if "function action" not in content:
            warnings.append("Missing action() function")

        return ValidationResult(ok=(len(errors) == 0), errors=errors, warnings=warnings, normalized_content=content)


    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        title = "unknown"
        
        filepath = info.get("github_path") or info.get("filepath") 
        if filepath:
            if info.get("filepath"):
                title = os.path.splitext(os.path.basename(filepath))[0].split("/")[-1]
            else:
                title = os.path.splitext(os.path.basename(filepath))[0]
        
        if title == "unknown":
            comment_match = re.search(r'^--\s*([\w\-]+)\.nse', content, re.MULTILINE)
            if comment_match:
                title = comment_match.group(1)
        
        if title == "unknown":
            id_match = re.search(r'id\s*=\s*["\']([^"\']+)["\']', content)
            if id_match:
                title = id_match.group(1)

        try:
            meta = {}
            # Description extraction
            desc_m = re.search(r'description\s*=\s*\[\[([\s\S]*?)\]\]', content)
            meta["description"] = desc_m.group(1).strip() if desc_m else "No description"
            
            _, cve = detect_cve(meta["description"])

            # Fields extraction
            for key in ("author", "license", "version"):
                m = re.search(rf'{key}\s*=\s*["\'](.+?)["\']', content)
                meta[key] = m.group(1).strip() if m else "Unknown"

            # Categories
            cat_m = re.search(r'categories\s*=\s*\{([^\}]*)\}', content)
            meta["categories"] = re.findall(r'["\'](.*?)["\']', cat_m.group(1)) if cat_m else []

            # Rule Type
            if "portrule" in content: meta["rule_type"] = "portrule"
            elif "hostrule" in content: meta["rule_type"] = "hostrule"
            else: meta["rule_type"] = "unknown"
            
            return {
                "format": "nse",
                "title": title,
                "license": meta["license"],
                "source": info.get("repo_url", "Unknown"),
                "version": meta["version"] or "1.0",
                "original_uuid": "N/A",
                "description": meta["description"],
                "author": meta["author"],
                "categories": meta["categories"],
                "rule_type": meta["rule_type"],
                "to_string": content,
                "cve_id": cve, 
            }
        except Exception as e:
            return {"format": "nse", "title": f"error_{title}", "description": str(e), "to_string": str(content)}

    def get_rule_files(self, file: str) -> bool:
        return file.endswith(".nse")

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return [f.read()]
        except:
            return []


    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        rule_name = RuleModel.get_rule(rule_id)
        for root, _, files in os.walk(repo_dir):
            for f in files:
                if f.endswith(".nse"):
                    file_name_without_ext = f[:-4] 
                    
                    if file_name_without_ext == rule_name:
                        try:
                            file_path = os.path.join(root, f)
                            with open(file_path, "r", encoding="utf-8") as f_content:
                                return f_content.read(), True
                        except Exception:
                            pass
                            
        return "Rule not found", False