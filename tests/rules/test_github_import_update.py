"""
Integration tests for the GitHub import + update pipeline
(app/features/rule/rule_from_github/), exercised against the real
https://github.com/rulezet/rulezet-sample-rules.git repo.

These hit the network (a real `git clone`/`git pull` and the GitHub API), so
they're skipped automatically if github.com isn't reachable.
"""
import os
import re
import subprocess
import time
from collections import defaultdict

import pytest

from app.core.db_class.db import Rule

SAMPLE_REPO_URL = "https://github.com/rulezet/rulezet-sample-rules.git"


def login_admin(client):
    client.post("/account/login", data={
        "email": "admin@admin.admin",
        "password": "admin",
        "remember_me": False,
    }, follow_redirects=True)
    return client


def _network_reachable():
    try:
        subprocess.run(["git", "ls-remote", SAMPLE_REPO_URL],
                        capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _network_reachable(), reason="no network access to github.com")


def _poll_status(client, url, timeout=120):
    """Poll a /rule/{import,update}_loading_status/<sid> endpoint until the
    session reports complete >= total (see session_class.py / update_class.py —
    total/complete are now tracked per rule, not per file)."""
    deadline = time.time() + timeout
    status = None
    while time.time() < deadline:
        res = client.get(url)
        assert res.status_code == 200, res.get_json()
        status = res.get_json()
        if status.get("complete", 0) >= status.get("total", 1):
            return status
        time.sleep(0.5)
    raise AssertionError(f"session at {url} did not complete within {timeout}s: {status}")


def test_github_import_from_real_repo(client, app):
    """Import the real sample-rules repo end to end. Checks the rule-granularity
    progress fix directly: `total` must equal the number of rules actually found
    (not the number of files — several formats in this repo hold one rule per
    file, but the fix must hold regardless), and every rule must resolve to
    imported/skipped/bad_rules by the time the session completes."""
    login_admin(client)

    res = client.post("/rule/import_rules_from_github", json={
        "url": SAMPLE_REPO_URL,
        "license": "MIT",
    })
    assert res.status_code == 201, res.get_json()
    sid = res.get_json()["session_uuid"]

    status = _poll_status(client, f"/rule/import_loading_status/{sid}")

    assert status["total"] > 0
    assert status["imported"] + status["skipped"] + status["bad_rules"] == status["total"]
    assert status["imported"] > 0

    with app.app_context():
        # The GitHub API's `html_url` (no ".git" suffix) is what actually gets
        # stored as `source` (see yara_format.py parse_metadata: `info.get("repo_url")`,
        # sourced from github_repo_metadata()'s GitHub API response) — match loosely.
        imported_rules = Rule.query.filter(Rule.source.ilike("%rulezet-sample-rules%")).all()
        assert len(imported_rules) == status["imported"]

        # github_path must be relative to the repo root, not an absolute local
        # path tied to the clone directory (see session_class.py fix) —
        # otherwise a future update-check comparing paths against `git diff`
        # output, or a relocated/recreated clone, silently stops matching
        # existing rules.
        for r in imported_rules:
            assert r.github_path
            assert not os.path.isabs(r.github_path)


def test_github_update_detects_and_applies_content_change(client, app):
    """Full loop: import -> edit a rule's file on disk -> check_updates_by_rule
    -> verify the change is detected -> accept it -> verify it's applied to
    the rule.

    Edits are scoped to the repo's YARA rules: YaraRule.find_rule_in_repo()
    matches purely on the rule's title (regex on `rule <name>`), so editing a
    rule's body while keeping its title is a safe, format-agnostic way to
    exercise the exact same Check_for_rule_updates() path every rule format
    shares, without needing a hand-verified valid edit for all 7 formats the
    sample repo contains.

    The edit changes the `description` meta field's value, not a comment —
    the YARA parser's normalized_content (what actually gets diffed/stored,
    see Check_for_rule_updates()) strips comments entirely, so a comment-only
    edit would be detected as "changed" but vanish before it could be
    verified as applied.
    """
    login_admin(client)

    res = client.post("/rule/import_rules_from_github", json={
        "url": SAMPLE_REPO_URL,
        "license": "MIT",
    })
    assert res.status_code == 201, res.get_json()
    import_sid = res.get_json()["session_uuid"]
    _poll_status(client, f"/rule/import_loading_status/{import_sid}")

    with app.app_context():
        yara_rules = Rule.query.filter(
            Rule.source.ilike("%rulezet-sample-rules%"), Rule.format == "yara"
        ).all()
        assert len(yara_rules) >= 1, "expected at least one imported YARA rule to test against"
        yara_rule_paths = {r.id: r.github_path for r in yara_rules}
        yara_rule_titles = {r.id: r.title for r in yara_rules}

    from app.features.rule.rule_format.utils_format.utils_import_update import clone_or_access_repo
    repo_dir, _ = clone_or_access_repo(SAMPLE_REPO_URL)

    # Several rules can share one file (e.g. YARA/CVE-2017-11882.yar holds 3
    # rules in the sample repo) — edit per rule block (matched by title, same
    # as find_rule_in_repo()'s own matching), not a single blind replace on the
    # whole file, or only the first rule in a shared file would ever change.
    rule_ids_by_path = defaultdict(list)
    for rule_id, github_path in yara_rule_paths.items():
        rule_ids_by_path[github_path].append(rule_id)

    original_contents = {}
    try:
        for github_path, rule_ids in rule_ids_by_path.items():
            filepath = os.path.join(repo_dir, github_path)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            original_contents[github_path] = content
            for rule_id in rule_ids:
                title = yara_rule_titles[rule_id]
                # Scope the edit to this rule's own chunk (split on rule
                # boundaries) so a duplicate title elsewhere in the file, or
                # an identical description string on a different rule, can't
                # get edited instead.
                chunks = re.split(r'(?=^rule\s)', content, flags=re.MULTILINE)
                title_re = re.compile(r'^rule\s+' + re.escape(title) + r'(\s|:|\{)')
                target_i = next((i for i, c in enumerate(chunks) if title_re.match(c)), None)
                assert target_i is not None, f"could not locate 'rule {title}' block in {filepath}"
                new_chunk, n = re.subn(
                    r'(description\s*=\s*")([^"]*)(")',
                    r'\1\2 modified-by-test\3',
                    chunks[target_i], count=1,
                )
                assert n == 1, f"could not locate a description field in rule {title} ({filepath})"
                chunks[target_i] = new_chunk
                content = ''.join(chunks)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

        res = client.post("/rule/check_updates_by_rule", json={
            "rules": list(yara_rule_paths.keys()),
        })
        assert res.status_code == 201, res.get_json()
        update_sid = res.get_json()["session_uuid"]
        status = _poll_status(client, f"/rule/update_loading_status/{update_sid}")

        assert status["updated"] == len(yara_rule_paths), status

        # Fetch the per-rule detail the same way the real update_loading.html
        # page does once finished (its `is_finished` watcher switches from the
        # live status() poll to this paginated endpoint — the live status()'s
        # "rules" key can already be gone by the time we poll, since a fast
        # by_rule check can finish before the very first poll response).
        res = client.get(f"/rule/update_loading_status/{update_sid}/get_rules")
        assert res.status_code == 200, res.get_json()
        rules_detail = res.get_json()["rules"]
        by_id = {int(entry["rule_id"]): entry for entry in rules_detail}
        for rule_id in yara_rule_paths:
            entry = by_id[rule_id]
            assert entry["found"] is True
            assert entry["update_available"] is True
            assert entry["rule_syntax_valid"] is True
            assert entry["history_id"] is not None

        # Accept every detected update, then verify it actually landed on the rule.
        for rule_id in yara_rule_paths:
            entry = by_id[rule_id]
            res = client.get("/rule/update_github_rule/decision_rule", query_string={
                "rule_id": entry["history_id"],
                "decision": "accepted",
                "sid": update_sid,
            })
            assert res.status_code == 200, res.get_json()

        with app.app_context():
            for rule_id in yara_rule_paths:
                refreshed = Rule.query.get(rule_id)
                assert "modified-by-test" in refreshed.to_string
    finally:
        # The local clone is now a persistent, reused cache (see
        # utils_import_update.py / session_class.py — it's no longer deleted
        # after every run), so restore it to avoid leaking test-induced drift
        # into later test runs or real usage of the same clone.
        for github_path, content in original_contents.items():
            filepath = os.path.join(repo_dir, github_path)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
