import os
import re
from typing import Any, Dict, List, Optional

from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.core.utils.utils import detect_cve


###############################################################################
#   KQL class                                                                #
#                                                                             #
#   KQL (Kusto Query Language) detection/hunting rules are stored as plain   #
#   .kql files — one query per file, the same convention used by the public  #
#   Azure-Sentinel / Sentinel-Queries GitHub repos. There is no wrapper      #
#   schema (unlike Sigma/ATR's YAML) and, in practice, most public KQL rule  #
#   repos (e.g. reprise99/Sentinel-Queries, 460+ files) don't use a          #
#   structured header at all — just a plain-English `//` comment describing #
#   the query. Metadata is read from an optional leading `// Key: Value`    #
#   header when present, falls back to the first free-form comment          #
#   paragraph for the description, and to the filename for the title.       #
###############################################################################


# Optional `// Key: Value` header lines at the top of the file. Only keys in
# _KNOWN_HEADER_KEYS are treated as metadata — this keeps an ordinary
# sentence that happens to contain a colon (e.g. "Note: this needs the AMA
# connector") from being misread as a key/value pair.
_HEADER_LINE_RE = re.compile(r'^//\s*([A-Za-z][\w \-]*?)\s*:\s*(.+)$')
_KNOWN_HEADER_KEYS = {
    'title', 'name',
    'description', 'desc', 'summary',
    'author', 'authors', 'created_by',
    'license',
    'severity',
    'tags', 'tag',
    'mitre', 'mitre_att&ck', 'attack', 'techniques',
    'version',
    'id', 'uuid', 'rule_id',
    'source', 'reference', 'references', 'ref',
}

# Kusto control/management commands (`.show`, `.create table`, `.drop`, ...)
# are cluster administration, not a detection query, and must be rejected.
_MGMT_COMMAND_RE = re.compile(r'^\s*\.\w+')

_BRACKET_PAIRS = {'(': ')', '[': ']', '{': '}'}
_BRACKET_CLOSERS = {v: k for k, v in _BRACKET_PAIRS.items()}


def _strip_comments(content: str) -> str:
    """Return the content with `//` comments removed — both whole-comment
    lines and trailing inline comments (`SecurityEvent // main table`).

    A `//` found inside a quoted string (e.g. `has "https://evil.com"`) is
    left untouched — only a `//` outside of any string starts a comment.
    Without this string-awareness, a trailing comment containing an
    apostrophe (very common in plain-English notes, e.g. "// don't count
    unknowns") would open a string that's never closed and validate() would
    wrongly reject the query as having an unterminated string literal.
    """
    out_lines: List[str] = []
    for line in content.splitlines():
        result: List[str] = []
        in_string = False
        string_char = ""
        escaped = False
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if in_string:
                result.append(ch)
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == string_char:
                    in_string = False
                i += 1
                continue
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
                result.append(ch)
                i += 1
                continue
            if ch == '/' and i + 1 < n and line[i + 1] == '/':
                break
            result.append(ch)
            i += 1
        cleaned = ''.join(result).rstrip()
        if cleaned.strip():
            out_lines.append(cleaned)
    return "\n".join(out_lines).strip()


def _parse_leading_comments(content: str) -> tuple[Dict[str, str], str]:
    """Parse the leading contiguous block of `//` comment lines.

    Returns (meta, freeform):
    - meta: recognized `Key: Value` pairs (key must be in
      _KNOWN_HEADER_KEYS), gathered from the whole leading comment block.
    - freeform: the first comment *paragraph* (up to the first blank line),
      with any recognized Key: Value lines excluded — this is what most
      public KQL rule repos actually put at the top of a file instead of a
      structured header, and is used as the description fallback.
    """
    meta: Dict[str, str] = {}
    freeform_parts: List[str] = []
    in_first_paragraph = True
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            in_first_paragraph = False
            continue
        if not stripped.startswith('//'):
            break
        match = _HEADER_LINE_RE.match(stripped)
        key = match.group(1).strip().lower().replace(' ', '_') if match else None
        if match and key in _KNOWN_HEADER_KEYS:
            meta[key] = match.group(2).strip()
        elif in_first_paragraph:
            text = stripped[2:].strip()
            if text:
                freeform_parts.append(text)
    return meta, " ".join(freeform_parts)


def _title_from_filename(filepath: Optional[str]) -> Optional[str]:
    if not filepath:
        return None
    name = os.path.splitext(os.path.basename(filepath))[0]
    name = re.sub(r'[-_]+', ' ', name).strip()
    return name.title() if name else None


class KQLRule(RuleType):
    """
    Concrete implementation of RuleType for KQL (Kusto Query Language) rules.
    """

    @property
    def format(self) -> str:
        return "kql"

    def get_class(self) -> str:
        return "KQLRule"

    # ---------------------#
    #   Abstract section   #
    # ---------------------#

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Heuristically validate a raw KQL query.

        There is no Python Kusto engine available to compile/execute against,
        so validation is syntactic: strips comments, rejects cluster
        management commands, and checks for balanced brackets/quotes and a
        sane first token (a query cannot open with a pipe).
        """
        if not content or not content.strip():
            return ValidationResult(ok=False, errors=["Rule content is empty."], normalized_content=content)

        body = _strip_comments(content)
        if not body:
            return ValidationResult(
                ok=False,
                errors=["No query body found (file only contains comments)."],
                normalized_content=content,
            )

        errors: List[str] = []
        warnings: List[str] = []

        if _MGMT_COMMAND_RE.match(body):
            errors.append("Query looks like a Kusto control command (starts with '.'), not a detection query.")

        if body.startswith('|'):
            errors.append("Query cannot start with a pipe '|' — expected a table name, 'let', or 'union' first.")

        # Balanced brackets, aware of (single/double) quoted strings.
        stack: List[str] = []
        in_string = False
        string_char = ""
        escaped = False
        for ch in body:
            if in_string:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == string_char:
                    in_string = False
                continue
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
                continue
            if ch in _BRACKET_PAIRS:
                stack.append(ch)
            elif ch in _BRACKET_CLOSERS:
                if not stack or stack[-1] != _BRACKET_CLOSERS[ch]:
                    errors.append(f"Unbalanced '{ch}' in query.")
                    break
                stack.pop()
        else:
            if stack:
                errors.append(f"Unclosed '{stack[-1]}' in query.")
        if in_string:
            errors.append("Unterminated string literal in query.")

        if '|' not in body and not re.search(r'\blet\b', body):
            warnings.append("Query has no pipe ('|') operators — it looks like a bare table reference.")

        ok = len(errors) == 0
        return ValidationResult(ok=ok, errors=errors, warnings=warnings, normalized_content=content)

    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """Extract metadata from an optional leading comment header, falling back to the filename/defaults."""
        info = info or {}
        # The import pipeline stores the file's path under "github_path"
        # (see session_class.py / update_class.py); "filepath" is only used
        # by direct/unit-test callers. Check both so the filename fallback
        # actually fires during a real GitHub/zip import.
        source_path = info.get("github_path") or info.get("filepath")
        fallback_title = _title_from_filename(source_path) or "Untitled KQL Query"

        try:
            meta, freeform_description = _parse_leading_comments(content)

            title = meta.get('title') or meta.get('name') or fallback_title
            description = meta.get('description') or meta.get('desc') or meta.get('summary') \
                or freeform_description or "No description provided"
            _, cve = detect_cve(description)

            tags: List[str] = []
            for key in ('tags', 'tag', 'mitre', 'mitre_att&ck', 'attack', 'techniques'):
                if meta.get(key):
                    tags.extend(t.strip() for t in meta[key].split(',') if t.strip())

            return {
                "format": "kql",
                "title": title,
                "license": meta.get("license") or info.get("license", "unknown"),
                "description": description,
                "source": meta.get("source") or info.get("repo_url", "Unknown"),
                "version": meta.get("version", "1.0"),
                "original_uuid": meta.get("id") or meta.get("uuid") or meta.get("rule_id") or "Unknown",
                "author": meta.get("author") or meta.get("authors") or meta.get("created_by") or info.get("author", "Unknown"),
                "to_string": content,
                "cve_id": cve,
                "severity": meta.get("severity", "unknown"),
                "tags": tags,
            }
        except Exception as e:
            return {
                "format": "kql",
                "title": f"{fallback_title} (Metadata Error)",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {e}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "severity": "unknown",
                "tags": [],
                "to_string": content,
            }

    def get_rule_files(self, file: str) -> bool:
        return file.endswith('.kql')

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract the KQL query from a file.

        The public KQL rule repos (Azure-Sentinel, Kusto-Query-Language) use
        one query per file, so the whole file — minus a check that it isn't
        comment-only — is the rule.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        if not _strip_comments(content):
            return []

        return [content.strip()]

    def get_rule_files_update(self, repo_dir: str) -> List[str]:
        """Retrieve all KQL rule files from a repository."""
        kql_files = []
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
                if self.get_rule_files(file):
                    kql_files.append(filepath)
        return kql_files

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a KQL rule inside a locally cloned repo, matching by the
        stable id/uuid from the header (if present) or by title otherwise.
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        kql_files = self.get_rule_files_update(repo_dir)

        for filepath in kql_files:
            for r in self.extract_rules_from_file(filepath):
                meta, _ = _parse_leading_comments(r)
                candidate_uuid = meta.get('id') or meta.get('uuid') or meta.get('rule_id')
                if candidate_uuid and rule.original_uuid and candidate_uuid == rule.original_uuid:
                    return r, True

                candidate_title = meta.get('title') or meta.get('name') or _title_from_filename(filepath)
                if candidate_title and candidate_title == rule.title:
                    return r, True

        return f"KQL rule '{rule.title}' not found inside local repo.", False
