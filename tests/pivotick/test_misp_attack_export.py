"""
Tests that ATT&CK techniques associated with a rule show up in the MISP JSON
export consumed by the PivoTick graph (bundleMispGraph.js parseMispBundle),
as proper "attack-id" MISP object attributes — same object_relation pattern
as the existing "cve-id" vulnerability attribute, not a custom top-level key.
"""
from app import db
from app.core.db_class.db import AttackTechnique, User
from app.features.attack.attack_core import add_technique_to_rule
from app.features.misp.rule.misp_object import get_rule_misp_event, create_rulezet_metadata_misp_object
from app.features.misp.bundle.misp_object import get_bundle_misp_event

API_KEY_USER = "api_key_user_rule"


def _seed_technique():
    tech = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic_keys=["execution"],
        url="https://attack.mitre.org/techniques/T1059/",
    )
    db.session.add(tech)
    db.session.commit()


def _attach_technique_to_rule_1():
    editor = User.query.filter_by(email="t@t.t").first()
    assoc, status = add_technique_to_rule(1, "T1059", user_id=editor.id)
    assert status == "created"


def _find_attack_attributes(misp_object_dict):
    return [a for a in misp_object_dict.get("Attribute", []) if a.get("object_relation") == "attack-id"]


def test_metadata_object_gets_attack_id_attribute(app):
    with app.app_context():
        _seed_technique()
        _attach_technique_to_rule_1()

        metadata_obj = create_rulezet_metadata_misp_object(1)
        attack_attrs = [a for a in metadata_obj.Attribute if a.object_relation == "attack-id"]
        assert len(attack_attrs) == 1
        attr = attack_attrs[0]
        assert attr.value == "T1059"
        # MISP attribute types are a fixed enum — no "attack" type exists, so
        # this uses the generic "text" type (not "vulnerability": a technique
        # ID isn't a CVE).
        assert attr.type == "text"
        assert attr.category == "Other"
        assert attr.disable_correlation is True


def test_metadata_object_no_attack_id_when_no_techniques(app):
    with app.app_context():
        metadata_obj = create_rulezet_metadata_misp_object(1)
        attack_attrs = [a for a in metadata_obj.Attribute if a.object_relation == "attack-id"]
        assert attack_attrs == []


def test_rule_misp_event_includes_attack_id_attribute(app):
    with app.test_request_context():
        # get_rule_misp_event() -> get_tags_for_rule() reads current_user,
        # which needs an active request context (anonymous is fine here).
        _seed_technique()
        _attach_technique_to_rule_1()

        data = get_rule_misp_event(1)
        metadata_obj = next(o for o in data["Object"] if o["name"] == "rulezet-metadata")
        attack_attrs = _find_attack_attributes(metadata_obj)
        assert len(attack_attrs) == 1
        assert attack_attrs[0]["value"] == "T1059"


def test_bundle_misp_event_includes_attack_id_attribute(app, client):
    with app.app_context():
        _seed_technique()
        _attach_technique_to_rule_1()

    client.post(
        "/api/bundle/private/create",
        json={"name": "Attack bundle", "description": "bundle for attack export test"},
        content_type="application/json",
        headers={"X-API-KEY": API_KEY_USER},
    )
    client.get(
        "/api/bundle/private/add_rule_bundle",
        query_string={"rule_id": 1, "bundle_id": 1, "description": "rule in bundle"},
        headers={"X-API-KEY": API_KEY_USER},
    )

    with app.app_context():
        data = get_bundle_misp_event(1)
        metadata_objs = [o for o in data["Object"] if o["name"] == "rulezet-metadata"]
        assert len(metadata_objs) == 1
        attack_attrs = _find_attack_attributes(metadata_objs[0])
        assert len(attack_attrs) == 1
        assert attack_attrs[0]["value"] == "T1059"
