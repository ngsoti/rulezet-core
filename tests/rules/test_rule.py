# ##################################################__Test__Rules__########################################################

"""
Unified Test Cases for Rule Endpoints

Includes tests for:
1. /searchPage - searching and paginating rules
2. /Convert_MISP - searching rules and converting them to MISP objects
"""

import pytest
from flask import url_for

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

def test_search_with_rule_type(client):
    params = {"rule_type": "sigma"}
    response = make_get(client, SEARCH_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all(rule["format"] == "sigma" for rule in json_data["results"])

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

def test_convert_misp_with_rule_type(client):
    params = {"rule_type": "sigma"}
    response = make_get(client, MISP_API_ENDPOINT, params=params)
    assert response.status_code == 200
    json_data = response.get_json()
    assert all(rule["format"] == "sigma" for rule in json_data["results"])

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

# import pytest
# from app.db_class.db import Rule, User

# # a new user for the tests
# API_KEY_USER = "user_api_key_neo"

# # already created in init_db.py
# API_KEY_ADMIN = "admin_api_key"
# API_KEY_USER_RULE = "api_key_user_rule"

# #######################
# #   Connection user   #
# #######################

# def create_user(client) -> None:
#     """Create an User test"""
#     client.post("/api/account/register",
#                 content_type='application/json',
#                 headers={"X-API-KEY": API_KEY_USER},
#                 json={
#                     "email": "test@example.com",
#                     "password": "password",
#                     "first_name": "Test",
#                     "last_name": "User"
#                 })

# def test_login_owner_rule_test(client) -> None:
#     """Connect a lambda user"""
#     response = client.post("/api/account/login",
#                             headers={"X-API-KEY": API_KEY_USER_RULE}, 
#                             json={
#                                 "email": "t@t.t",
#                                 "password": "t"
#                             })
#     assert response.status_code == 200
#     assert b"Logged in successfully" in response.data

# def test_login_admin(client) -> None:
#     """Connect admin user"""
#     response = client.post("/api/account/login",
#                             headers={"X-API-KEY": API_KEY_ADMIN}, 
#                             json={
#                                 "email": "admin@admin.admin",
#                                 "password": "admin"
#                             })
#     assert response.status_code == 200
#     assert b"Logged in successfully" in response.data

# def test_login_success(client)-> None:
#     """Connect the user who create a rule test user"""
#     create_user(client)
#     response = client.post("/api/account/login",
#                             headers={"X-API-KEY": API_KEY_USER}, 
#                             json={
#                                 "email": "test@example.com",
#                                 "password": "password",
#                                 "remember_me": True
#                             })
#     assert response.status_code == 200
#     assert b"Logged in successfully" in response.data




# # ---------- TESTS DE CRÉATION DE RÈGLE ----------

# def test_create_valid_yara_rule(client):
#     test_login_success(client)
#     myRule = {
#         "title": "Test YARA Rule 1",
#         "description": "Basic test",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "source": "UnitTest",
#         "author": "Test",
#         "to_string": "rule test { condition: true }"
#     }
#     response = client.post("/api/rule/private/create", json=myRule, headers={"X-API-KEY": API_KEY_USER})
#     assert response.status_code == 200
#     assert b"Rule added successfully" in response.data


# def test_create_duplicate_rule(client):
#     test_create_valid_yara_rule(client) 
#     duplicate = {
#         "title": "Test YARA Rule 1",  
#         "description": "Duplicate rule",
#         "version": "1.1",
#         "format": "yara",
#         "license": "MIT",
#         "source": "UnitTest",
#         "to_string": "rule test { condition: true }"
#     }
#     response = client.post("/api/rule/private/create", json=duplicate, headers={"X-API-KEY": API_KEY_USER})
#     assert response.status_code == 409
#     assert b"Rule already exists" in response.data


# @pytest.mark.parametrize("missing_field", ["title", "version", "format", "to_string", "license"])
# def test_create_missing_required_fields(client, missing_field):
#     test_login_success(client)
#     data = {
#         "title": "Test",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": "rule test { condition: true }"
#     }
#     del data[missing_field]
#     response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
#     assert response.status_code == 400
#     assert f"Missing or empty fields: {missing_field}" in response.get_json()["message"]


# def test_create_invalid_yara_rule(client):
#     test_login_success(client)
#     data = {
#         "title": "Invalid YARA Rule",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": "rule test { condition: }"  # Invalid syntax
#     }
#     response = client.post(
#         "/api/rule/private/create",
#         json=data,
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 400
#     json_data = response.get_json()
#     assert json_data["message"].startswith("Invalid rule")
#     assert "error" in json_data



# def test_create_rule_invalid_cve(client):
#     test_login_success(client)
#     data = {
#         "title": "Rule with Bad CVE",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": "rule test { condition: true }",
#         "cve_id": "INVALID-CVE"
#     }
#     response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})
#     assert response.status_code == 400
#     assert b"Invalid CVE ID format" in response.data


# def test_create_without_api_key(client):
#     data = {
#         "title": "No API Key",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": "rule test { condition: true }"
#     }
#     response = client.post("/api/rule/private/create", json=data)
#     assert response.status_code == 403


# def test_create_valid_sigma_rule(client):
#     test_login_success(client)
#     data = {
#         "title": "Sigma Rule OK",
#         "version": "1.0",
#         "format": "sigma",
#         "license": "GPL",
#         "to_string": """
# title: Successful logon
# id: b4d8e3cb-ae95-4cb2-9bbf-89d8f8b2e1d7
# description: Detects successful logon events
# logsource:
#   product: windows
#   service: security
#   category: logon
# detection:
#   selection:
#     EventID: 4624
#   condition: selection
# level: informational
# """,
#         "description": "Basic Sigma rule",
#         "source": "UnitTest"
#     }
#     response = client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})

#     assert response.status_code == 200
#     assert b"Rule added successfully" in response.data

# # ----------------------------------------
# # Tests DELETE Rule
# # ----------------------------------------

# def test_delete_rule_as_owner(client):
#     test_login_success(client)

#     rule = {
#         "title": "YaraToDelete",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": 'rule YaraToDelete { condition: true }',
#         "description": "To be deleted",
#         "source": "UnitTest"
#     }
#     res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 200

#     res = client.post("/api/rule/private/delete", json={"title": "YaraToDelete"}, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 200
#     # assert res.get_json()["success"] is True


# def test_delete_rule_not_owner(client):
#     test_login_success(client)
#     rule = {
#         "title": "YaraNotYours",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": 'rule YaraNotYours { condition: true }',
#         "description": "Not yours",
#         "source": "UnitTest"
#     }
#     res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 200

#     test_login_owner_rule_test(client)
#     res = client.post("/api/rule/private/delete", json={"title": "YaraNotYours"}, headers={"X-API-KEY": API_KEY_USER_RULE})
#     assert res.status_code == 403
#     assert "Access denied" in res.get_json()["message"]

# def test_delete_rule_as_admin(client):
#     test_login_success(client)
#     rule = {
#         "title": "YaraByAdmin",
#         "version": "1.0",
#         "format": "yara",
#         "license": "MIT",
#         "to_string": 'rule YaraByAdmin { condition: true }',
#         "description": "Admin deletes",
#         "source": "UnitTest"
#     }
#     res = client.post("/api/rule/private/create", json=rule, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 200

#     test_login_admin(client)
#     res = client.post("/api/rule/private/delete", json={"title": "YaraByAdmin"}, headers={"X-API-KEY": API_KEY_ADMIN})
#     assert res.status_code == 200
#     assert res.get_json()["success"] is True

# def test_delete_rule_not_found(client):
#     test_login_success(client)
#     res = client.post("/api/rule/private/delete", json={"title": "NonExistentRule"}, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 404
#     assert "No rule found" in res.get_json()["message"]

# def test_delete_rule_missing_title(client):
#     test_login_success(client)
#     res = client.post("/api/rule/private/delete", json={}, headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 400
#     assert "Missing or empty 'title'" in res.get_json()["message"]

# def test_delete_rule_missing_json(client):
#     test_login_success(client)
#     res = client.post("/api/rule/private/delete", headers={"X-API-KEY": API_KEY_USER})
#     assert res.status_code == 400
#     assert "Missing JSON body" in res.get_json()["message"]


# # ----------------------------------------
# # Tests EDIT Rule
# # ----------------------------------------


# def test_edit_rule_success(client, app):
#     test_login_success(client)
    
#     with app.app_context():
#         rule = Rule.query.filter_by(title="test").first()
#         assert rule is not None

#         payload = {
#             "title": "test updated",
#             "format": "yara",
#             "version": "2",
#             "to_string": "rule test { condition: 2}",
#             "license": "MIT",
#             "description": "updated description",
#             "source": "edited source"
#         }

#         res = client.post(f"/api/rule/private/edit/{rule.id}", json=payload, headers={"X-API-KEY": API_KEY_USER_RULE})
#         assert res.status_code == 200
#         assert res.get_json()["success"] is True
#         assert "updated" in res.get_json()["message"]


# def test_edit_rule_not_found(client):
#     test_login_success(client)
#     res = client.post("/api/rule/private/edit/999999", json={}, headers={"X-API-KEY": API_KEY_USER_RULE})
#     assert res.status_code == 404
#     assert "Rule not found" in res.get_json()["message"]

# def test_edit_rule_access_denied(client , app):
#     test_login_success(client)

#     with app.app_context():
#         other_user = User.query.filter_by(email="t@t.t").first()
#         rule = Rule.query.filter_by(title="test").first()
#         assert other_user and rule

#         res = client.post(
#             f"/api/rule/private/edit/{rule.id}",
#             json={"title": "try unauthorized edit"},
#             headers={"X-API-KEY": API_KEY_USER}
#         )
#         assert res.status_code == 403
#         assert "Access denied" in res.get_json()["message"]

# def test_edit_rule_missing_fields(client , app):
#     test_login_success(client)
#     with app.app_context():
#         rule = Rule.query.filter_by(title="test").first()

#         res = client.post(
#             f"/api/rule/private/edit/{rule.id}",
#             json={"format": "", "title": "   "},  
#             headers={"X-API-KEY": API_KEY_USER_RULE}
#         )
#         assert res.status_code == 400
#         assert "Missing or empty fields" in res.get_json()["message"]

# def test_edit_rule_duplicate_title(client , app):
#     test_login_success(client)
#     test_create_valid_yara_rule(client)  
#     with app.app_context():
#         rule = Rule.query.filter_by(title="Test YARA Rule 1").first()
        
#         res = client.post(
#             f"/api/rule/private/edit/{rule.id}",
#             json={"title": "test", "format": "sigma", "version": "1", "to_string": "title: conflict_title\nlogsource:\n  category: process_creation\ncondition: selection", "license": "MIT"},
#             headers={"X-API-KEY": API_KEY_USER}
#         )
#         assert res.status_code == 409
#         assert "Another rule with this title already exists" in res.get_json()["message"]



# def test_edit_rule_unsupported_format(client , app):
#     test_login_success(client)
#     with app.app_context():
#         rule = Rule.query.filter_by(title="test").first()
#         res = client.post(
#             f"/api/rule/private/edit/{rule.id}",
#             json={"format": "foobar", "title": "foobar", "version": "1", "to_string": "test", "license": "MIT"},
#             headers={"X-API-KEY": API_KEY_USER_RULE}
#         )
#         assert res.status_code == 400
#         assert "Unsupported rule format" in res.get_json()["message"]


# def test_edit_rule_invalid_cve(client, app):
#     test_login_success(client)
#     with app.app_context():
#         rule = Rule.query.filter_by(title="test").first()
#         res = client.post(
#             f"/api/rule/private/edit/{rule.id}",
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



