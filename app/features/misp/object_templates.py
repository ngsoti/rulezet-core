"""
Repo-tracked MISP object templates for Rulezet's own custom object types
(rulezet-metadata, rulezet-bundle).

These are NOT part of pymisp's bundled misp-objects data — passing them via
`misp_objects_template_custom` means MISPObject() no longer depends on the
local pymisp install having been hand-patched with these definitions, which
it previously was (a non-reproducible state: a fresh `pip install` would not
recreate it, and `add_attribute()` would then fail here with no type/category
sane defaults).
"""
import json
import os

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'object_templates')
_cache = {}


def load_object_template(name: str) -> dict:
    if name not in _cache:
        path = os.path.join(_TEMPLATES_DIR, f'{name}.json')
        with open(path, encoding='utf-8') as f:
            _cache[name] = json.load(f)
    return _cache[name]
