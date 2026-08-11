"""
Tests for the code-format vs. declarative-rule classification
(app/core/db_class/db.py: Rule.is_code_format()).

Internal ref A8: Zeek and NSE (Lua-based Nmap scripts) submissions are
arbitrary executable code, not declarative detection rules, and used to
be displayed in the same undifferentiated list as YARA/Sigma/Suricata/
CRS. This only classifies and labels — it does not change validation or
execution behavior for any format.
"""
from __future__ import annotations

import datetime
import uuid

from app.core.db_class.db import Rule, User
from app import db

API_KEY_USER = "user_api_key"

CODE_FORMATS = {"zeek", "nse"}
DATA_FORMATS = {"yara", "sigma", "suricata", "crs"}


def _make_rule(fmt: str, user_id: int) -> Rule:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    rule = Rule(
        uuid=str(uuid.uuid4()),
        format=fmt,
        title=f"A8 {fmt} classification rule",
        source="test",
        user_id=user_id,
        version="1.0",
        vote_up=0,
        vote_down=0,
        to_string=f"-- placeholder {fmt} content",
        is_deleted=False,
        creation_date=now,
        last_modif=now,
    )
    db.session.add(rule)
    return rule


def test_a8_code_formats_are_labelled_distinctly(client, app):
    """Zeek/NSE rules carry is_code_format=True; YARA/Sigma/Suricata/CRS rules carry False."""
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rules_by_format = {fmt: _make_rule(fmt, user.id) for fmt in CODE_FORMATS | DATA_FORMATS}
        db.session.commit()

        for fmt in CODE_FORMATS:
            assert rules_by_format[fmt].is_code_format() is True, fmt
        for fmt in DATA_FORMATS:
            assert rules_by_format[fmt].is_code_format() is False, fmt

        ids = ",".join(str(rules_by_format[fmt].id) for fmt in CODE_FORMATS | DATA_FORMATS)

    # Same check via the live /rule/data_table endpoint (what RuleList.js
    # actually renders from) rather than the model method in isolation.
    response = client.get("/rule/data_table", query_string={"ids": ids, "per_page": 100})
    assert response.status_code == 200
    items = {item["format"]: item for item in response.get_json()["items"]}

    for fmt in CODE_FORMATS:
        assert items[fmt]["is_code_format"] is True, fmt
    for fmt in DATA_FORMATS:
        assert items[fmt]["is_code_format"] is False, fmt


def test_a8_normal_formats_are_not_labelled_as_code(client, app):
    """Regression check: the detail-page rule endpoint agrees with is_code_format() for a data format."""
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = _make_rule("yara", user.id)
        db.session.commit()
        assert rule.is_code_format() is False
        rule_id = rule.id

    response = client.get("/rule/get_current_rule", query_string={"rule_id": rule_id})
    assert response.status_code == 200
    assert response.get_json()["rule"]["is_code_format"] is False
