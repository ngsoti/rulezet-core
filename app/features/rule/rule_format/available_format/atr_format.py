from __future__ import annotations
import json
import os
import re
from typing import Any, Dict, List, Optional

import yaml

from app.core.utils.utils import detect_cve
from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import (
    RuleType,
    ValidationResult,
)


####################
#   ATR class      #
####################

# Canonical ATR rule-ID shape (e.g. ATR-2026-00440)
_ATR_ID_RE = re.compile(r"^ATR-\d{4}-\d{5}$")

# The ten valid ATR taxonomy categories. Anything outside this set is a
# semantic validation failure even if the YAML parses fine.
_ATR_CATEGORIES = frozenset(
    {
        "prompt-injection",
        "tool-poisoning",
        "skill-compromise",
        "agent-manipulation",
        "context-exfiltration",
        "data-poisoning",
        "excessive-autonomy",
        "model-abuse",
        "model-security",
        "privilege-escalation",
    }
)

# Valid ATR severities. Same shape as Sigma's severity enum.
_ATR_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

# Valid agent_source.type values per ATR's evolving schema (additive).
_ATR_AGENT_SOURCE_TYPES = frozenset({"llm_io", "tool_call", "skill_manifest", "agent_loop"})


class ATRRule(RuleType):
    """
    Concrete implementation of RuleType for Agent Threat Rules (ATR).

    ATR is an MIT-licensed YAML-based detection-rule standard for AI agent
    threats. Each rule has a stable identifier in the form ATR-YYYY-NNNNN
    (e.g. ATR-2026-00001) and detects attacks across ten categories:
    prompt-injection, tool-poisoning, skill-compromise, agent-manipulation,
    context-exfiltration, data-poisoning, excessive-autonomy, model-abuse,
    model-security, privilege-escalation.

    Upstream: https://github.com/Agent-Threat-Rule/agent-threat-rules
    npm:      `agent-threat-rules` (MIT, currently v3.5.0 / 652 rules).
    """

    @property
    def format(self) -> str:
        return "atr"

    def get_class(self) -> str:
        return "ATRRule"

    ##############################
    #        FORMAT DETECT       #
    ##############################
    def detect(self, content: str) -> bool:
        """
        Heuristic to disambiguate an ATR rule from other YAML-based formats
        (Sigma, etc.) that share the .yaml extension.

        Triggers on any of:
          - top-level `id` field matching `ATR-YYYY-NNNNN`
          - top-level `agent_source` field (unique to ATR among YAML formats)
          - top-level `tags.category` value in the ATR taxonomy

        Not in the abstract `RuleType` contract today; safe to call directly
        on an instance when the format loader needs to disambiguate.
        """
        try:
            doc = yaml.safe_load(content)
        except Exception:
            return False
        if not isinstance(doc, dict):
            return False

        rule_id = doc.get("id")
        if isinstance(rule_id, str) and _ATR_ID_RE.match(rule_id):
            return True

        if isinstance(doc.get("agent_source"), dict):
            return True

        tags = doc.get("tags")
        if isinstance(tags, dict):
            category = tags.get("category")
            if isinstance(category, str) and category in _ATR_CATEGORIES:
                return True

        return False

    ##############################
    #         VALIDATION         #
    ##############################
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate an ATR rule. Two layers:

          1. Syntactic — the content parses as a single YAML mapping.
          2. Semantic — required fields are present and their values are
             drawn from the ATR-defined enums (severity, category,
             agent_source.type) and the canonical rule-ID pattern.

        Does not re-dump YAML — returns the original content verbatim in
        `normalized_content` so quoting and ordering are preserved.
        """
        try:
            doc = yaml.safe_load(content)
        except Exception as exc:  # YAMLError or anything else
            return ValidationResult(ok=False, errors=[f"YAML parse error: {exc}"], normalized_content=content)

        if doc is None or not isinstance(doc, dict):
            return ValidationResult(
                ok=False,
                errors=["Empty or invalid YAML content or not a single rule object."],
                normalized_content=content,
            )

        errors: List[str] = []
        warnings: List[str] = []

        # Required scalar fields.
        rule_id = doc.get("id")
        if not isinstance(rule_id, str):
            errors.append("Missing or non-string required field: id")
        elif not _ATR_ID_RE.match(rule_id):
            errors.append(
                f"Rule id '{rule_id}' does not match the canonical ATR pattern ATR-YYYY-NNNNN"
            )

        title = doc.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append("Missing or empty required field: title")

        severity = doc.get("severity")
        if severity is None:
            errors.append("Missing required field: severity")
        elif severity not in _ATR_SEVERITIES:
            errors.append(
                f"Severity '{severity}' is not one of: {sorted(_ATR_SEVERITIES)}"
            )

        # Required tags.category.
        tags = doc.get("tags")
        if not isinstance(tags, dict):
            errors.append("Missing or non-mapping required field: tags")
        else:
            category = tags.get("category")
            if category is None:
                errors.append("Missing required field: tags.category")
            elif category not in _ATR_CATEGORIES:
                errors.append(
                    f"Category '{category}' is not in the ATR taxonomy. Valid: {sorted(_ATR_CATEGORIES)}"
                )

        # Required agent_source.type.
        agent_source = doc.get("agent_source")
        if not isinstance(agent_source, dict):
            errors.append("Missing or non-mapping required field: agent_source")
        else:
            atype = agent_source.get("type")
            if atype is None:
                errors.append("Missing required field: agent_source.type")
            elif atype not in _ATR_AGENT_SOURCE_TYPES:
                # Additive schema — log as warning rather than hard fail.
                warnings.append(
                    f"agent_source.type '{atype}' is not in the currently-known set "
                    f"{sorted(_ATR_AGENT_SOURCE_TYPES)} — accepting but flagging."
                )

        # Detection block. ATR uses either an array (`conditions: [...]`)
        # with `condition: any|all`, or a named-map for older rules.
        detection = doc.get("detection")
        if not isinstance(detection, dict):
            errors.append("Missing or non-mapping required field: detection")
        else:
            conditions = detection.get("conditions")
            if conditions is None:
                errors.append("Missing required field: detection.conditions")
            elif isinstance(conditions, list):
                if len(conditions) == 0:
                    errors.append("detection.conditions must be a non-empty array")
                else:
                    for idx, cond in enumerate(conditions):
                        if not isinstance(cond, dict):
                            errors.append(f"detection.conditions[{idx}] must be a mapping")
                            continue
                        for required in ("field", "operator", "value"):
                            if required not in cond:
                                errors.append(
                                    f"detection.conditions[{idx}] missing required key '{required}'"
                                )
                expr = detection.get("condition")
                if expr is not None and expr not in {"any", "all", "or", "and"}:
                    errors.append(
                        f"detection.condition '{expr}' must be one of: any | all | or | and"
                    )
            elif not isinstance(conditions, dict):
                errors.append("detection.conditions must be either an array or a mapping")

        ok = len(errors) == 0
        return ValidationResult(ok=ok, errors=errors, warnings=warnings, normalized_content=content)

    ##############################
    #        META PARSING        #
    ##############################
    def parse_metadata(
        self,
        content: str,
        info: Optional[Dict[str, Any]] = None,
        validation_result: Optional[ValidationResult] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Extract rulezet-canonical metadata from an ATR rule.

        Preserves the original ATR rule id (ATR-YYYY-NNNNN) in
        `original_uuid` so the mapping back to the upstream corpus stays
        stable across rulezet's own UUID assignment.
        """
        info = info or {}
        title_fallback = "Untitled ATR Rule"
        try:
            doc = yaml.safe_load(content)
            if doc is None or not isinstance(doc, dict):
                rule_id_hint = info.get("original_uuid") or "Unknown"
                raise ValueError(f"Empty or non-mapping YAML; id hint: {rule_id_hint}")

            rule_id = doc.get("id", "Unknown")
            title = doc.get("title", title_fallback)
            description = doc.get("description", "No description provided")
            severity = doc.get("severity", "unknown")
            author = doc.get("author") or info.get("author", "ATR Community")

            # ATR rules carry `references.cve` as a list. Prefer the
            # explicit list when present; otherwise fall back to scanning
            # the description with rulezet's `detect_cve` utility.
            # Output shape matches the Sigma format adapter: a JSON-encoded
            # string of identifiers, so downstream consumers don't have to
            # branch on format.
            references = doc.get("references") or {}
            explicit_cves = references.get("cve") if isinstance(references, dict) else None
            if isinstance(explicit_cves, list) and explicit_cves:
                normalized = sorted({str(c).strip().upper() for c in explicit_cves if c})
                cve_ids = json.dumps(normalized)
            else:
                _, cve_ids = detect_cve(description if isinstance(description, str) else "")

            # Tags: rulezet expects a flat list of strings. Flatten the ATR
            # tags mapping (category, subcategory, confidence, etc.) into
            # `key:value` strings so consumers can filter on any of them.
            tags_list: List[str] = []
            tags_dict = doc.get("tags") or {}
            if isinstance(tags_dict, dict):
                for k, v in tags_dict.items():
                    if isinstance(v, str):
                        tags_list.append(f"{k}:{v}")
                    elif isinstance(v, (list, tuple)):
                        for item in v:
                            tags_list.append(f"{k}:{item}")

            return {
                "title": title,
                "format": "atr",
                "license": doc.get("license") or info.get("license", "MIT"),
                "description": description,
                "version": str(doc.get("rule_version", doc.get("version", "1"))),
                "author": author,
                "cve_id": cve_ids,
                "original_uuid": rule_id,
                "source": info.get("repo_url", "https://github.com/Agent-Threat-Rule/agent-threat-rules"),
                "severity": severity,
                "tags": tags_list,
                "to_string": content,
            }

        except Exception as exc:
            return {
                "format": "atr",
                "title": f"{title_fallback} (Metadata Error)",
                "license": info.get("license", "MIT"),
                "description": f"Error parsing metadata: {exc}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "ATR Community"),
                "cve_id": [],
                "severity": "unknown",
                "tags": [],
                "to_string": content,
            }

    ##############################
    #         FILE LISTING       #
    ##############################
    def get_rule_files(self, file: str) -> bool:
        """Return True if the file looks like a candidate ATR rule file by extension."""
        return file.endswith((".yml", ".yaml"))

    ##############################
    #         EXTRACTION         #
    ##############################
    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract individual ATR rules from a YAML file.

        ATR ships one rule per file in the canonical repo layout, but the
        format permits multi-document YAML and list-of-rules YAML. This
        method handles all three (single dict, list of dicts, multi-doc).
        Original content is preserved verbatim where the file holds a
        single rule (no re-dump), to keep quoting / ordering intact.
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

        # No documents.
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
    def _walk_yaml_files(self, repo_dir: str) -> List[str]:
        """Walk repo_dir for candidate ATR YAML files (mirrors sigma_format)."""
        rule_files: List[str] = []
        if not os.path.exists(repo_dir):
            return rule_files
        for root, dirs, files in os.walk(repo_dir, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith(".") and not d.startswith("_")
                       and not os.path.islink(os.path.join(root, d))]
            for fname in files:
                if fname.startswith(".") or fname.startswith("_"):
                    continue
                filepath = os.path.join(root, fname)
                # Reject symlinks — open() would otherwise follow one straight
                # to its target and leak arbitrary filesystem content as a "rule".
                if os.path.islink(filepath):
                    continue
                if fname.endswith((".yml", ".yaml")):
                    rule_files.append(filepath)
        return rule_files

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Locate a previously-imported ATR rule's current text in a repo
        directory by its stable original_uuid (ATR-YYYY-NNNNN).
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        target_uuid = getattr(rule, "original_uuid", None)
        target_title = getattr(rule, "title", None)

        for path in self._walk_yaml_files(repo_dir):
            for raw in self.extract_rules_from_file(path):
                try:
                    doc = yaml.safe_load(raw)
                except Exception:
                    continue
                if not isinstance(doc, dict):
                    continue
                if (target_uuid and doc.get("id") == target_uuid) or (
                    target_title and doc.get("title") == target_title
                ):
                    return raw, True

        return f"ATR rule '{target_title or target_uuid}' not found inside local repo.", False
