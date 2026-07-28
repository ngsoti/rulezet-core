import re

import yaml

SUPPORTED_FORMATS = ('yara', 'sigma')


class _BlockDumper(yaml.SafeDumper):
    pass


def _str_representer(dumper, data):
    style = '|' if '\n' in data else None
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style=style)


_BlockDumper.add_representer(str, _str_representer)


def _slug(title: str) -> str:
    slug = re.sub(r'[^A-Za-z0-9]+', '', (title or '').title())
    return slug or 'Rule'


def _vql_safe(value: str) -> str:
    """Strip everything except a conservative identifier charset before a
    value derived from rule content is interpolated into literal VQL text.

    rule.to_string (and anything parsed out of it, like a Sigma
    logsource.category) is attacker-controlled — any authenticated user can
    set it to arbitrary text. Unlike _slug()/_artifact_name(), which already
    sanitize the rule title before using it as an artifact *name*, nothing
    upstream sanitizes `category` before it used to reach here, which meant a
    category value containing a backtick + `={...}` sequence (or `*/`) could
    break out of the VQL identifier / comment it's embedded in and splice
    arbitrary VQL — including exec-capable plugins — into the generated
    artifact, to be run against every endpoint the artifact is later deployed
    to. Confirmed live: a category of
    'x`={SELECT execve(argv=["id"]) FROM scope() WHERE 1} fake' produced a
    `sources[0].query` whose real VQL had the injected SELECT spliced in as
    its own dict entry.
    """
    return re.sub(r'[^A-Za-z0-9_/]+', '_', value or '') or 'unknown'


def _artifact_name(rule) -> str:
    fmt_label = 'YARA' if rule.format.lower() == 'yara' else 'Sigma'
    return f"Rulezet.Detection.{fmt_label}.{_slug(rule.title)}"


def _description(rule, base_url: str) -> str:
    tags = ', '.join(assoc.tag.name for assoc in rule.rule_tags_assocs if assoc.tag)
    lines = [
        f"{rule.format.upper()} rule from Rulezet: \"{rule.title}\"",
        f"Rule UUID: {rule.uuid}",
        f"Source: {base_url.rstrip('/')}/rule/detail_rule/{rule.uuid}",
    ]
    if rule.author:
        lines.append(f"Author: {rule.author}")
    if tags:
        lines.append(f"Tags: {tags}")
    return '\n'.join(lines) + '\n'


def _yara_artifact(rule, base_url: str) -> dict:
    return {
        'name': _artifact_name(rule),
        'description': _description(rule, base_url),
        'type': 'CLIENT',
        'parameters': [
            {
                'name': 'YaraRule',
                'description': 'YARA rule content (pre-filled from Rulezet)',
                'default': rule.to_string,
            },
            {'name': 'ScanProcesses', 'type': 'bool', 'default': 'true'},
            {'name': 'ScanDisk', 'type': 'bool', 'default': 'false'},
            {
                'name': 'TargetGlob',
                'description': (
                    "Glob of files to scan when ScanDisk is enabled. Defaults to a "
                    "Windows-wide scan — replace with e.g. '/**' for Linux/macOS targets."
                ),
                'default': 'C:/**',
            },
        ],
        'sources': [
            {
                # A SELECT can only have one FROM clause — scanning every running
                # process means driving proc_yara() once per pslist() row via
                # foreach(), not chaining two FROMs on the same SELECT.
                'name': 'ProcessScan',
                'query': (
                    'SELECT Pid, Name, Exe, Rule, Meta, Strings\n'
                    'FROM foreach(\n'
                    '  row={ SELECT Pid, Name, Exe FROM pslist() },\n'
                    '  query={\n'
                    '    SELECT Pid, Name, Exe, Rule, Meta, Strings\n'
                    '    FROM proc_yara(rules=YaraRule, pid=Pid)\n'
                    '  }\n'
                    ')\n'
                    'WHERE ScanProcesses\n'
                ),
            },
            {
                'name': 'DiskScan',
                'query': (
                    'SELECT OSPath, Rule, Meta, Strings\n'
                    'FROM yara(rules=YaraRule, files=TargetGlob)\n'
                    'WHERE ScanDisk\n'
                ),
            },
        ],
    }


# Sigma `logsource.category` values we can confidently map to a concrete
# Velociraptor ETW watch source. Anything not in this map gets an artifact
# that still compiles, but with a clearly-flagged placeholder log source
# instead of a silently-wrong one — guessing an ETW provider GUID for a
# category we haven't verified against a real Velociraptor server would be
# worse than being honest about the gap.
_SIGMA_LOG_SOURCE_VQL = {
    'process_creation': (
        '`windows/process_creation`={\n'
        '      SELECT * FROM watch_etw(guid="{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}")\n'
        '    }'
    ),
}


def _sigma_logsource_category(rule) -> str | None:
    try:
        parsed = yaml.safe_load(rule.to_string)
    except yaml.YAMLError:
        return None
    if not isinstance(parsed, dict):
        return None
    logsource = parsed.get('logsource')
    if not isinstance(logsource, dict):
        return None
    return logsource.get('category')


def _sigma_artifact(rule, base_url: str) -> dict:
    category = _sigma_logsource_category(rule)
    mapped = _SIGMA_LOG_SOURCE_VQL.get(category)

    if mapped:
        log_source_block = mapped
    else:
        # category comes straight out of the rule's own (attacker-controlled)
        # content — must not be spliced into VQL text unsanitized, only into
        # the inert `description` field below (which is yaml.dump-encoded,
        # not parsed as code). See _vql_safe()'s docstring for why.
        label = _vql_safe(category or 'unknown')
        # Placeholder — deliberately won't silently pass off an unverified
        # ETW mapping as correct. Operator must fill in the real watch_etw()
        # (or artifact-based) source for this category before deploying.
        log_source_block = (
            f'`windows/{label}`={{\n'
            f'      /* TODO: this Sigma rule\'s logsource category is "{label}" — \n'
            f'         supply the matching watch_etw()/artifact query here. */\n'
            '      SELECT * FROM watch_etw(guid="REPLACE_WITH_CORRECT_ETW_GUID")\n'
            '    }'
        )

    return {
        'name': _artifact_name(rule),
        'description': _description(rule, base_url) + (
            '' if mapped else
            f'\n⚠ Log source for Sigma category "{category or "unknown"}" is not yet mapped — '
            'edit the log_sources block in this artifact before deploying.\n'
        ),
        'type': 'CLIENT_EVENT',
        'parameters': [
            {
                'name': 'SigmaRule',
                'description': 'Sigma rule content (pre-filled from Rulezet)',
                'default': rule.to_string,
            },
        ],
        'sources': [
            {
                'query': (
                    'SELECT * FROM sigma(\n'
                    '  rules=[SigmaRule],\n'
                    '  log_sources=dict(\n'
                    f'    {log_source_block}\n'
                    '  )\n'
                    ')\n'
                ),
            },
        ],
    }


def generate_velociraptor_artifact(rule, base_url: str = 'https://rulezet.org') -> str:
    """Generate a Velociraptor Artifact YAML string for a YARA or Sigma rule."""
    fmt = (rule.format or '').lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Velociraptor export is not supported for format '{rule.format}'")

    artifact = _yara_artifact(rule, base_url) if fmt == 'yara' else _sigma_artifact(rule, base_url)
    return yaml.dump(artifact, Dumper=_BlockDumper, sort_keys=False, allow_unicode=True, default_flow_style=False)
