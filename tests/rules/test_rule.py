# # ##################################################__Test__Rules__########################################################

# """
# Unified Test Cases for Rule Endpoints

# Includes tests for:
# 1. /searchPage - searching and paginating rules
# 2. /Convert_MISP - searching rules and converting them to MISP objects
# """

import json
import re

import pytest

# --------------------------
# API Endpoints
# --------------------------
SEARCH_API_ENDPOINT = "/api/rule/public/searchPage"
MISP_API_ENDPOINT = "/api/rule/public/Convert_MISP"

# --------------------------
# Helper functions
# --------------------------
def make_get(client, endpoint, params=None, headers=None):
    """Helper to perform GET request with query params."""
    return client.get(endpoint, query_string=params or {}, headers=headers or {})

# ==================================================
# /searchPage Endpoint Tests
# ==================================================
def test_search_default(client):
    response = make_get(client, SEARCH_API_ENDPOINT)
    assert response.status_code == 200
    json_data = response.get_json()
    assert "results" in json_data
    assert json_data["pagination"]["current_page"] == 1

def test_search_with_query(client):
    params = {"search": "detect"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all("detect" in rule["title"] for rule in json_data["results"] if rule["title"])

def test_search_with_author(client):
    params = {"author": "John"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all(rule["author"] == "John" for rule in json_data["results"])

# def test_search_with_rule_type(client):
#     params = {"rule_type": "sigma"}
#     response = make_get(client, SEARCH_API_ENDPOINT, params=params)
#     assert response.status_code == 200
#     json_data = response.get_json()
#     assert all(rule["format"] == "sigma" for rule in json_data["results"])

def test_search_with_invalid_rule_type(client):
    params = {"rule_type": "sigmdddda"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 400
    assert b"Format is not supported." in response.data

def test_search_with_sort_by(client):
    params = {"sort_by": "newest"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 200

def test_search_with_pagination(client):
    params = {"page": 2, "per_page": 5}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["pagination"]["current_page"] == 2
    assert len(json_data["results"]) <= 5

def test_search_invalid_sort(client):
    params = {"sort_by": "invalid_sort"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 400
    assert b"Invalid sort_by" in response.data

# ==================================================
# /Convert_MISP Endpoint Tests
# ==================================================
def test_convert_misp_default(client):
    response = make_get(client, MISP_API_ENDPOINT)
    assert response.status_code == 200
    json_data = response.get_json()
    assert "results" in json_data

def test_convert_misp_with_search(client):
    params = {"search": "mars"}
    response = make_get(client, MISP_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all("mars" in rule["title"] for rule in json_data["results"] if rule["title"])

def test_convert_misp_with_author(client):
    params = {"author": "John"}
    response = make_get(client, MISP_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all(rule["author"] == "John" for rule in json_data["results"])

# def test_convert_misp_with_rule_type(client):
#     params = {"rule_type": "sigma"}
#     response = make_get(client, MISP_API_ENDPOINT, params=params)
#     assert response.status_code == 200
#     json_data = response.get_json()
#     assert all(rule["format"] == "sigma" for rule in json_data["results"])

def test_convert_misp_with_sort(client):
    params = {"sort_by": "newest"}
    response = make_get(client, MISP_API_ENDPOINT, params=params)
    assert response.status_code == 200

def test_convert_misp_invalid_sort(client):
    params = {"sort_by": "invalid_sort"}
    response = make_get(client, MISP_API_ENDPOINT, params=params)
    assert response.status_code == 400
    assert b"Invalid sort_by" in response.data






# ###############
# #   Api key   #
# ###############

# # a new user for the tests
API_KEY_USER = "user_api_key"

# already created in init_db.py
API_KEY_ADMIN = "admin_api_key"
API_KEY_USER_RULE = "api_key_user_rule"


# # ---------- TESTS DE CRÉATION DE RÈGLE ----------

def test_create_valid_yara_rule(client):
    myRule = {
        "title": "Test YARA Rule 1",
        "description": "Basic test",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "source": "UnitTest",
        "author": "Test",
        "to_string": "rule test { condition: true }"
    }
    response = client.post("/api/rule/private/create", json=myRule, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200


def test_create_duplicate_rule(client):
    test_create_valid_yara_rule(client) 
    duplicate = {
        "title": "Test YARA Rule 1",  
        "description": "Duplicate rule",
        "version": "1.1",
        "format": "yara",
        "license": "MIT",
        "source": "UnitTest",
        "to_string": "rule test { condition: true }"
    }
    response = client.post("/api/rule/private/create", json=duplicate, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 409
    assert b"Rule already exists" in response.data


@pytest.mark.parametrize("missing_field", ["title", "version", "format", "to_string", "license"])
def test_create_missing_required_fields(client, missing_field):
    data = {
        "title": "Test",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": "rule test { condition: true }"
    }
    del data[missing_field]
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 400
    assert f"Missing or empty fields: {missing_field}" in response.get_json()["message"]


def test_create_invalid_yara_rule(client):
    data = {
        "title": "Invalid YARA Rule",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": "rule test { condition: }"  # Invalid syntax
    }
    response = client.post(
        "/api/rule/private/create",
        json=data,
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["message"].startswith("Invalid rule")
    assert "error" in json_data



def test_create_rule_invalid_cve(client):
    data = {
        "title": "Rule with Bad CVE",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": "rule test { condition: true }",
        "cve_id": "INVALID-CVE"
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 400
    assert b"Invalid CVE ID format" in response.data


def test_create_without_api_key(client):
    data = {
        "title": "No API Key",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": "rule test { condition: true }"
    }
    response = client.post("/api/rule/private/create", json=data)
    assert response.status_code == 403


def test_create_valid_sigma_rule(client):
    data = {
        "title": "Sigma Rule OK",
        "version": "1.0",
        "format": "sigma",
        "license": "GPL",
        "to_string": """
title: Successful logon
id: b4d8e3cb-ae95-4cb2-9bbf-89d8f8b2e1d7
description: Detects successful logon events
logsource:
  product: windows
  service: security
  category: logon
detection:
  selection:
    EventID: 4624
  condition: selection
level: informational
""",
        "description": "Basic Sigma rule",
        "source": "UnitTest"
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})

    assert response.status_code == 200


def test_create_invalid_sigma_rule(client):
    data = {
        "title": "Sigma Rule Invalid",
        "version": "1.0",
        "format": "sigma",
        "license": "GPL",
        "to_string": """
title: Dangling detection
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4624
  unused:
    EventID: 9999
  condition: selection
level: high
""",
        "description": "Sigma rule with a dangling (unreferenced) detection",
        "source": "UnitTest"
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["message"].startswith("Invalid rule")

# ----------------------------------------
# Tests DELETE Rule
# ----------------------------------------

def test_delete_rule_as_owner(client):

    rule = {
        "title": "YaraToDelete",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": 'rule YaraToDelete { condition: true }',
        "description": "To be deleted",
        "source": "UnitTest"
    }
    res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 200

    res = client.post("/api/rule/private/delete", json={"rule_id": "2"}, headers={"X-API-KEY": API_KEY_USER})
    print(res.data)
    assert res.status_code == 200


def test_delete_rule_not_owner(client):
    rule = {
        "title": "YaraNotYours",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": 'rule YaraNotYours { condition: true }',
        "description": "Not yours",
        "source": "UnitTest"
    }
    res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 200

    res = client.post("/api/rule/private/delete", json={"rule_id": "2"}, headers={"X-API-KEY": API_KEY_USER_RULE})
    assert res.status_code == 403
    assert "Access denied" in res.get_json()["message"]

def test_delete_rule_as_admin(client):
    rule = {
        "title": "YaraByAdmin",
        "version": "1.0",
        "format": "yara",
        "license": "MIT",
        "to_string": 'rule YaraByAdmin { condition: true }',
        "description": "Admin deletes",
        "source": "UnitTest"
    }
    res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 200

    res = client.post("/api/rule/private/delete", json={"rule_id": "2"}, headers={"X-API-KEY": API_KEY_ADMIN})
    assert res.status_code == 200
    assert res.get_json()["success"] is True

def test_delete_rule_not_found(client):
    res = client.post("/api/rule/private/delete", json={"rule_id": "999999"}, headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 404
    assert "No rule found" in res.get_json()["message"]

def test_delete_rule_missing_title(client):
    res = client.post("/api/rule/private/delete", json={}, headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 400

def test_delete_rule_missing_json(client):
    res = client.post("/api/rule/private/delete", headers={"X-API-KEY": API_KEY_USER})
    assert res.status_code == 400


# ----------------------------------------
# Tests EDIT Rule
# ----------------------------------------


# def test_edit_rule_success(client, app):
    
#     with app.app_context():

#         payload = {
#             "title": "test updated",
#             "format": "yara",
#             "version": "2",
#             "to_string": "rule test { condition: 2}",
#             "license": "MIT",
#             "description": "updated description",
#             "source": "edited source"
#         }

#         res = client.post(f"/api/rule/private/edit/1", json=payload, headers={"X-API-KEY": API_KEY_USER_RULE})
#         assert res.status_code == 200
#         assert res.get_json()["success"] is True
#         assert "updated" in res.get_json()["message"]


# def test_edit_rule_not_found(client):
#     res = client.post("/api/rule/private/edit/999999", json={}, headers={"X-API-KEY": API_KEY_USER_RULE})
#     assert res.status_code == 404
#     assert "Rule not found" in res.get_json()["message"]

# def test_edit_rule_access_denied(client , app):

#     with app.app_context():
#         res = client.post(
#             f"/api/rule/private/edit/1",
#             json={"title": "try unauthorized edit"},
#             headers={"X-API-KEY": API_KEY_USER}
#         )
#         assert res.status_code == 403
#         assert "Access denied" in res.get_json()["message"]

# def test_edit_rule_missing_fields(client , app):
#     with app.app_context():

#         res = client.post(
#             f"/api/rule/private/edit/1",
#             json={"format": "", "title": "   "},  
#             headers={"X-API-KEY": API_KEY_USER_RULE}
#         )
#         assert res.status_code == 400
#         assert "Missing or empty fields" in res.get_json()["message"]

# def test_edit_rule_duplicate_title(client , app):
#     test_create_valid_yara_rule(client)  
#     with app.app_context():
        
#         res = client.post(
#             f"/api/rule/private/edit/2",
#             json={"title": "test", "format": "sigma", "version": "1", "to_string": "title: conflict_title\nlogsource:\n  category: process_creation\ncondition: selection", "license": "MIT"},
#             headers={"X-API-KEY": API_KEY_USER}
#         )
#         assert res.status_code == 409
#         assert "Another rule with this title already exists" in res.get_json()["message"]



# def test_edit_rule_unsupported_format(client , app):
#     with app.app_context():
#         res = client.post(
#             f"/api/rule/private/edit/1",
#             json={"format": "foobar", "title": "foobar", "version": "1", "to_string": "test", "license": "MIT"},
#             headers={"X-API-KEY": API_KEY_USER_RULE}
#         )
#         assert res.status_code == 400
#         assert "Unsupported rule format" in res.get_json()["message"]


# def test_edit_rule_invalid_cve(client, app):
#     with app.app_context():
#         res = client.post(
#             f"/api/rule/private/edit/1",
#             json={
#                 "title": "edit with cve",
#                 "format": "sigma",
#                 "version": "1",
#                 "to_string": "title: test\nlogsource:\n  category: process_creation\ncondition: selection",
#                 "license": "MIT",
#                 "cve_id": "INVALID-CVE"
#             },
#             headers={"X-API-KEY": API_KEY_USER_RULE}
#         )
#         assert res.status_code == 400
#         assert "Invalid CVE ID" in res.get_json()["message"]


# ---------- ref A3: Suricata pass/bypass suppression risk ----------

def test_a3_pass_action_rule_is_created_but_flagged(client, app):
    """A plain 'pass' rule is accepted at creation but flagged as a risk on the detail page."""
    data = {
        "title": "A3 pass action rule",
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'pass tcp any any -> any any (msg:"a3 test"; sid:900301; rev:1;)',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a3_bypass_keyword_rule_is_created_but_flagged(client, app):
    """A rule using the 'bypass' keyword is accepted at creation but flagged as a risk."""
    data = {
        "title": "A3 bypass keyword rule",
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'alert tcp any any -> any any (msg:"a3 test"; bypass; sid:900302; rev:1;)',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a3_hashed_target_in_pass_rule_is_rejected_at_creation(client):
    """A hash transform combined with a 'pass' rule is rejected outright at creation time."""
    data = {
        "title": "A3 hashed pass rule",
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": (
            'pass tcp any any -> any any '
            '(msg:"a3 test"; content:"x"; to_sha256; dataset:isset,d,type string; sid:900303; rev:1;)'
        ),
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["message"] == "Invalid rule"
    assert "hash transform" in json_data["error"]


def test_a3_normal_alert_rule_is_not_flagged(client, app):
    """An ordinary Suricata alert rule is created and shows no risk flag (regression check)."""
    data = {
        "title": "A3 normal alert rule",
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'alert tcp any any -> any any (msg:"a3 test"; content:"x"; sid:900304; rev:1;)',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is False
        assert risk['reasons'] == []


def test_a3_flagged_rule_shows_risk_banner_on_detail_page(client):
    """The rule detail page embeds the computed risk flag for a flagged rule."""
    data = {
        "title": "A3 detail page banner rule",
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'pass tcp any any -> any any (msg:"a3 test"; sid:900305; rev:1;)',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    detail = client.get(f"/rule/detail_rule/{rule_id}")
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)

    match = re.search(r"window\.__rule_risk\s*=\s*(\{.*?\});", body)
    assert match is not None, "window.__rule_risk was not embedded in the detail page"
    embedded_risk = json.loads(match.group(1))
    assert embedded_risk["flagged"] is True
    assert embedded_risk["rejected"] is False


# ---------- ref A5: CRS/ModSecurity engine-wide suppression ----------

def test_a5_ctl_ruleengine_off_rule_is_created_but_flagged(client, app):
    """A rule using 'ctl:ruleEngine=Off' is accepted at creation but flagged as a risk."""
    data = {
        "title": "A5 ctl ruleEngine off rule",
        "format": "crs",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'SecRule REQUEST_URI "@rx /admin" "id:900501,phase:1,ctl:ruleEngine=Off"',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a5_secmarker_rule_is_created_but_flagged(client, app):
    """A 'SecMarker' rule is accepted at creation but flagged as a risk."""
    data = {
        "title": "A5 SecMarker rule",
        "format": "crs",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'SecMarker "A5-BEGIN-MARKER"',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a5_normal_crs_rule_is_not_flagged(client, app):
    """An ordinary CRS rule with none of these directives shows no risk flag (regression check)."""
    data = {
        "title": "A5 normal crs rule",
        "format": "crs",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'SecRule REQUEST_URI "@rx /x" "id:900502,phase:1,deny"',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is False
        assert risk['reasons'] == []


def test_a5_flagged_rule_shows_risk_banner_on_detail_page(client):
    """The rule detail page embeds the computed risk flag for a flagged CRS rule."""
    data = {
        "title": "A5 detail page banner rule",
        "format": "crs",
        "version": "1.0",
        "license": "MIT",
        "to_string": 'SecRule REQUEST_URI "@rx /admin" "id:900503,phase:1,ctl:ruleEngine=Off"',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    detail = client.get(f"/rule/detail_rule/{rule_id}")
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)

    match = re.search(r"window\.__rule_risk\s*=\s*(\{.*?\});", body)
    assert match is not None, "window.__rule_risk was not embedded in the detail page"
    embedded_risk = json.loads(match.group(1))
    assert embedded_risk["flagged"] is True
    assert embedded_risk["rejected"] is False


# ---------- ref A6: YARA 'global rule' suppression risk ----------

def test_a6_global_rule_is_created_but_flagged(client, app):
    """A YARA 'global rule' is accepted at creation but flagged as a risk on the detail page."""
    data = {
        "title": "A6 global rule",
        "format": "yara",
        "version": "1.0",
        "license": "MIT",
        "to_string": "global rule a6_global_test { condition: false }",
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a6_normal_yara_rule_is_not_flagged(client, app):
    """An ordinary YARA rule with no 'global' modifier shows no risk flag (regression check)."""
    data = {
        "title": "A6 normal yara rule",
        "format": "yara",
        "version": "1.0",
        "license": "MIT",
        "to_string": "rule a6_normal_test { condition: true }",
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is False
        assert risk['reasons'] == []


def test_a6_flagged_global_rule_shows_risk_banner_on_detail_page(client):
    """The rule detail page embeds the computed risk flag for a flagged 'global rule'."""
    data = {
        "title": "A6 detail page banner rule",
        "format": "yara",
        "version": "1.0",
        "license": "MIT",
        "to_string": "global rule a6_detail_test { condition: false }",
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    detail = client.get(f"/rule/detail_rule/{rule_id}")
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)

    match = re.search(r"window\.__rule_risk\s*=\s*(\{.*?\});", body)
    assert match is not None, "window.__rule_risk was not embedded in the detail page"
    embedded_risk = json.loads(match.group(1))
    assert embedded_risk["flagged"] is True
    assert embedded_risk["rejected"] is False


# ---------- ref A7: Wazuh overwrite="yes" ----------

def test_a7_overwrite_yes_rule_is_created_but_flagged(client, app):
    """A Wazuh rule using overwrite="yes" is accepted at creation but flagged as a risk."""
    data = {
        "title": "A7 overwrite yes rule",
        "format": "wazuh",
        "version": "1.0",
        "license": "MIT",
        "to_string": '<rule id="900701" level="5" overwrite="yes"><description>a7 test</description></rule>',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is True
        assert risk['rejected'] is False


def test_a7_normal_wazuh_rule_is_not_flagged(client, app):
    """An ordinary Wazuh rule with no overwrite attribute shows no risk flag (regression check)."""
    data = {
        "title": "A7 normal wazuh rule",
        "format": "wazuh",
        "version": "1.0",
        "license": "MIT",
        "to_string": '<rule id="900702" level="5"><description>a7 normal test</description></rule>',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    with app.app_context():
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        risk = RuleModel.get_rule_risk_flags(rule)
        assert risk['flagged'] is False
        assert risk['reasons'] == []


def test_a7_flagged_rule_shows_risk_banner_on_detail_page(client):
    """The rule detail page embeds the computed risk flag for a flagged Wazuh rule."""
    data = {
        "title": "A7 detail page banner rule",
        "format": "wazuh",
        "version": "1.0",
        "license": "MIT",
        "to_string": '<rule id="900703" level="5" overwrite="yes"><description>a7 test</description></rule>',
    }
    response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
    assert response.status_code == 200
    rule_id = response.get_json()["rule"]["id"]

    detail = client.get(f"/rule/detail_rule/{rule_id}")
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)

    match = re.search(r"window\.__rule_risk\s*=\s*(\{.*?\});", body)
    assert match is not None, "window.__rule_risk was not embedded in the detail page"
    embedded_risk = json.loads(match.group(1))
    assert embedded_risk["flagged"] is True
    assert embedded_risk["rejected"] is False



