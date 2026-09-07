import json
import os
import re
from typing import Any, Dict, List, Optional

import yaml

from app.core.utils.utils import detect_cve
from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult

######################
#   Splunk class     #
######################

# Splunk Security Content ("ESCU") detections — one YAML file per detection,
# the SPL query itself sitting unstructured in the `search` field. Modeled
# on splunk/security_content's exported schema (EventBasedDetection), but
# hand-rolled rather than a full jsonschema import: that schema's
# analytic_story/asset_type/atomic_guid enums are dynamic catalogs specific
# to Splunk's own content repo (which stories/asset types exist), not part
# of the generic SPL-detection format — enforcing them here would reject
# any legitimately-formed community detection that isn't in Splunk's own
# corpus. Only the short, spec-fixed enums (status/type/security_domain/
# category) and the required identity/logic fields are hard errors;
# everything else (how_to_implement, known_false_positives, analytic_story,
# the type->finding matrix, mitre_attack_id shape) is a warning — same
# calibration as atr_format.py's "additive" fields.

_SPLUNK_STATUSES = frozenset({"production", "experimental", "deprecated"})
_SPLUNK_TYPES = frozenset({"TTP", "Anomaly", "Correlation", "Hunting"})
_SPLUNK_SECURITY_DOMAINS = frozenset({"access", "audit", "endpoint", "identity", "network", "threat"})
_SPLUNK_CATEGORIES = frozenset({"application", "cloud", "endpoint", "network", "web", "deprecated"})

_MITRE_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')


def _score_to_severity(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 80:
        return "critical"
    if value >= 50:
        return "high"
    if value >= 20:
        return "medium"
    return "low"


def _severity_from_findings(doc: Dict[str, Any]) -> str:
    """Splunk has no single 'severity' field — risk score lives inside the
    `finding` (TTP/Correlation) or `intermediate_findings` (Anomaly) block,
    0-100. Bucket it into the same low/medium/high/critical scale the other
    formats use so it displays consistently across formats."""
    finding = doc.get("finding")
    if isinstance(finding, dict):
        entity = finding.get("entity")
        if isinstance(entity, dict) and "score" in entity:
            return _score_to_severity(entity["score"])

    intermediate = doc.get("intermediate_findings")
    if isinstance(intermediate, dict):
        entities = intermediate.get("entities")
        if isinstance(entities, list):
            scores = []
            for e in entities:
                if isinstance(e, dict) and "score" in e:
                    try:
                        scores.append(float(e["score"]))
                    except (TypeError, ValueError):
                        continue
            if scores:
                return _score_to_severity(max(scores))

    return "unknown"


class SplunkRule(RuleType):
    """
    Concrete implementation of RuleType for Splunk Security Content ("ESCU")
    detections — YAML files with a raw SPL query in `search`.

    Upstream: https://github.com/splunk/security_content
    """

    @property
    def format(self) -> str:
        return "splunk"

    def get_class(self) -> str:
        return "SplunkRule"

    ##############################
    #        FORMAT DETECT       #
    ##############################
    def detect(self, content: str) -> bool:
        """
        Identify a Splunk detection by the trio of fields that are required
        together only in this format — `search` + `how_to_implement` +
        `known_false_positives` — and absent from Sigma (`logsource`/
        `detection`) and ATR (`agent_source`, `detection.conditions`), the
        other formats that also claim .yml/.yaml.
        """
        try:
            doc = yaml.safe_load(content)
        except Exception:
            return False
        if not isinstance(doc, dict):
            return False
        return (
            isinstance(doc.get('search'), str) and
            isinstance(doc.get('how_to_implement'), str) and
            isinstance(doc.get('known_false_positives'), str)
        )

    ##############################
    #         VALIDATION         #
    ##############################
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a Splunk detection. Two layers:

          1. Syntactic — the content parses as a single YAML mapping.
          2. Semantic — required identity/logic fields are present and the
             short, spec-fixed enums (status, type, security_domain,
             category) hold a valid value. Everything Splunk's own dynamic
             content catalog governs (analytic_story, asset_type,
             mitre_attack_id shape, the type->finding matrix) is a warning,
             not a hard failure — see the module docstring.

        Does not re-dump YAML — returns the original content verbatim in
        `normalized_content` so quoting/ordering/comments are preserved.
        """
        try:
            doc = yaml.safe_load(content)
        except Exception as exc:
            return ValidationResult(ok=False, errors=[f"YAML parse error: {exc}"], normalized_content=content)

        if doc is None or not isinstance(doc, dict):
            return ValidationResult(
                ok=False,
                errors=["Empty or invalid YAML content or not a single rule object."],
                normalized_content=content,
            )

        errors: List[str] = []
        warnings: List[str] = []

        name = doc.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append("Missing or empty required field: name")

        rule_id = doc.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append("Missing or empty required field: id")

        description = doc.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append("Missing or empty required field: description")

        search = doc.get("search")
        if not isinstance(search, str) or not search.strip():
            errors.append("Missing or empty required field: search")
        elif search != search.strip():
            warnings.append("The 'search' field has leading/trailing whitespace.")

        status = doc.get("status")
        if status not in _SPLUNK_STATUSES:
            errors.append(f"status '{status}' is not one of: {sorted(_SPLUNK_STATUSES)}")

        detection_type = doc.get("type")
        if detection_type not in _SPLUNK_TYPES:
            errors.append(f"type '{detection_type}' is not one of: {sorted(_SPLUNK_TYPES)}")

        security_domain = doc.get("security_domain")
        if security_domain not in _SPLUNK_SECURITY_DOMAINS:
            errors.append(f"security_domain '{security_domain}' is not one of: {sorted(_SPLUNK_SECURITY_DOMAINS)}")

        category = doc.get("category")
        if category not in _SPLUNK_CATEGORIES:
            errors.append(f"category '{category}' is not one of: {sorted(_SPLUNK_CATEGORIES)}")

        mitre_ids = doc.get("mitre_attack_id")
        if mitre_ids is None:
            warnings.append("Missing mitre_attack_id — ATT&CK mapping is expected for this format.")
        elif not isinstance(mitre_ids, list) or not all(isinstance(t, str) for t in mitre_ids):
            errors.append("mitre_attack_id must be a list of strings.")
        else:
            for tid in mitre_ids:
                if not _MITRE_ID_RE.match(tid):
                    warnings.append(f"mitre_attack_id '{tid}' doesn't look like an ATT&CK technique ID (e.g. T1059.001).")

        analytic_story = doc.get("analytic_story")
        if not isinstance(analytic_story, list) or not analytic_story:
            warnings.append("Missing or empty analytic_story — used upstream to group detections into a campaign/use case.")

        has_finding = isinstance(doc.get("finding"), dict)
        has_intermediate = isinstance(doc.get("intermediate_findings"), dict)
        if detection_type in ("TTP", "Correlation") and not has_finding:
            warnings.append(f"type '{detection_type}' normally requires a 'finding' block (risk/notable metadata).")
        elif detection_type == "Anomaly" and not has_intermediate:
            warnings.append("type 'Anomaly' normally requires an 'intermediate_findings' block (risk metadata).")
        elif detection_type == "Hunting" and (has_finding or has_intermediate):
            warnings.append("type 'Hunting' normally has neither 'finding' nor 'intermediate_findings'.")

        for field_name in ("how_to_implement", "known_false_positives"):
            value = doc.get(field_name)
            if not isinstance(value, str) or not value.strip():
                warnings.append(f"Missing recommended field: {field_name}")

        ok = len(errors) == 0
        return ValidationResult(ok=ok, errors=errors, warnings=warnings, normalized_content=content)

    ##############################
    #       META PARSING         #
    ##############################
    def parse_metadata(self, content: str, info: Optional[Dict[str, Any]] = None,
                        validation_result: Optional[ValidationResult] = None, **kwargs) -> Dict[str, Any]:
        """
        Extract rulezet-canonical metadata from a Splunk detection.
        Never re-dumps YAML → preserves original formatting.
        """
        info = info or {}
        title_fallback = "Untitled Splunk Detection"
        try:
            doc = yaml.safe_load(content)
            if doc is None or not isinstance(doc, dict):
                rule_id_hint = info.get("original_uuid") or "Unknown"
                raise ValueError(f"Empty or non-mapping YAML; id hint: {rule_id_hint}")

            title = doc.get("name") or title_fallback
            description = doc.get("description", "No description provided")

            explicit_cves = doc.get("cve")
            if isinstance(explicit_cves, list) and explicit_cves:
                cve_ids = json.dumps(sorted({str(c).strip().upper() for c in explicit_cves if c}))
            else:
                _, cve_ids = detect_cve(description if isinstance(description, str) else "")

            # Flatten Splunk's structured taxonomy into rulezet's flat tag
            # list — same convention as atr_format.py's tags flattening.
            tags_list: List[str] = []
            for tid in doc.get("mitre_attack_id") or []:
                if isinstance(tid, str):
                    tags_list.append(tid)
            for story in doc.get("analytic_story") or []:
                if isinstance(story, str):
                    tags_list.append(f"analytic_story:{story}")
            if doc.get("asset_type"):
                tags_list.append(f"asset_type:{doc['asset_type']}")
            if doc.get("security_domain"):
                tags_list.append(f"security_domain:{doc['security_domain']}")
            if doc.get("category"):
                tags_list.append(f"category:{doc['category']}")

            return {
                "title": title,
                "format": "splunk",
                "license": doc.get("license") or info.get("license", "Unknown"),
                "description": description,
                "version": str(doc.get("version", "1")),
                "author": doc.get("author") or info.get("author", "Unknown"),
                "cve_id": cve_ids,
                "original_uuid": doc.get("id") or "Unknown",
                "source": info.get("repo_url", "Unknown"),
                "severity": _severity_from_findings(doc),
                "tags": tags_list,
                "to_string": content,
            }

        except Exception as exc:
            return {
                "format": "splunk",
                "title": f"{title_fallback} (Metadata Error)",
                "license": info.get("license", "Unknown"),
                "description": f"Error parsing metadata: {exc}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "severity": "unknown",
                "tags": [],
                "to_string": content,
            }

    ##############################
    #     DOCUMENTATION SIGNALS  #
    ##############################
    def documentation_signals(self, content: str) -> Dict[str, bool]:
        """Splunk-specific documentation checklist, straight from the
        format's optional-but-conventional fields."""
        try:
            doc = yaml.safe_load(content)
        except Exception:
            return {}
        if not isinstance(doc, dict):
            return {}
        references = doc.get("references")
        return {
            "documents_references": isinstance(references, list) and len(references) > 0,
            "documents_false_positives": bool((doc.get("known_false_positives") or "").strip()) if isinstance(doc.get("known_false_positives"), str) else False,
            "documents_implementation": bool((doc.get("how_to_implement") or "").strip()) if isinstance(doc.get("how_to_implement"), str) else False,
            "documents_attack_mapping": isinstance(doc.get("mitre_attack_id"), list) and len(doc.get("mitre_attack_id")) > 0,
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
        Extract Splunk detections from a YAML file. Security Content ships
        one detection per file, but multi-document and list-of-rules YAML
        are handled defensively too (same three shapes as atr_format.py).
        Never re-dumps a single-document file → returns the original raw
        text (quoting/ordering preserved).

        Self-filters a single-document file through detect() (same as
        atr_format.py) — this method can be called directly (e.g.
        find_rule_in_repo scanning every .yml in a repo) without going
        through the candidate/detect() disambiguation that main_format.py
        and session_class.py apply first, so a Sigma/ATR file sitting next
        to real Splunk detections must not be misreported as a Splunk one.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return []

        try:
            parsed = list(yaml.safe_load_all(content))
        except Exception:
            return []

        if not parsed:
            return []

        # Single-document file with a single rule mapping — return raw text.
        if len(parsed) == 1 and isinstance(parsed[0], dict):
            return [content] if self.detect(content) else []

        # Single-document file holding a list of rules — dump each.
        if len(parsed) == 1 and isinstance(parsed[0], list):
            return [
                yaml.dump(rule, sort_keys=False, allow_unicode=True)
                for rule in parsed[0]
                if isinstance(rule, dict)
            ]

        # Multi-document file — each top-level doc that is a mapping is a rule.
        return [
            yaml.dump(doc, sort_keys=False, allow_unicode=True)
            for doc in parsed
            if isinstance(doc, dict)
        ]

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
                if os.path.islink(filepath):
                    continue
                if file.endswith(('.yml', '.yaml')):
                    rule_files.append(filepath)
        return rule_files

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Return the EXACT YAML rule from the repo without modifying anything.
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        splunk_files = self.get_rule_files_update(repo_dir)

        for path in splunk_files:
            rules = self.extract_rules_from_file(path)
            for raw in rules:
                try:
                    parsed = yaml.safe_load(raw)
                    if not parsed or not isinstance(parsed, dict):
                        continue

                    if parsed.get("name") == rule.title or parsed.get("id") == rule.original_uuid:
                        return raw, True
                except Exception:
                    continue

        return f"Splunk detection '{rule.title}' not found inside local repo.", False
