##################################################__Test__Bundles__########################################################

###############
#   Api key   #
###############


# a new user for the tests
API_KEY_USER = "api_key_user_rule"

# already created in init_db.py
API_KEY_ADMIN = "admin_api_key"

#######################
#   Connection user   #
#######################


# ---------- TESTS DE CRÉATION DE BUNDLE ----------

def test_create_valid_bundle(client):

    myBundle = {
        "name": "My Bundle Name",
        "description": "This is a test bundle created via API."
    }
    response = client.post(
        "/api/bundle/private/create",
        json=myBundle,
        content_type='application/json',
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["message"] == "Bundle created successfully"
    assert "bundle_id" in json_data

    myBundle2 = {
        "name": "ww",
        "description": ""
    }
    response = client.post(
        "/api/bundle/private/create",
        json=myBundle2,
        content_type='application/json',
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["message"] == "Bundle created successfully"
    assert "bundle_id" in json_data


def test_create_invalid_bundle(client):
    myBundle = {
        "name": "",
        "description": "This is a test bundle created via API."
    }
    response = client.post(
        "/api/bundle/private/create",
        json=myBundle,
        content_type='application/json',
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["message"] == "Invalid bundle"
    assert json_data["error"] == "'name' must be a non-empty string"


def test_add_rule_to_bundle_success(client):
    test_create_valid_bundle(client)

    response = client.get(
        "/api/bundle/private/add_rule_bundle",
        query_string={
            "rule_id": 1,
            "bundle_id": 1,
            "description": "Test rule in bundle"
        },
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["message"] == "Rule added!"


def test_add_rule_to_bundle_missing_params(client):
    response = client.get(
        "/api/bundle/private/add_rule_bundle",
        query_string={
            "rule_id": 1,
            "bundle_id": 1
            # manque description
        },
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Missing" in json_data["message"]


def test_add_rule_to_bundle_not_found(client):
    response = client.get(
        "/api/bundle/private/add_rule_bundle",
        query_string={
            "rule_id": 1,
            "bundle_id": 9999,  # inexistant
            "description": "Test rule in bundle"
        },
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data["success"] is False
    assert json_data["message"] == "Bundle not found"


def test_add_rule_to_bundle_permission_denied(client):
    # Création du bundle en tant qu’admin (bundle_id=1)
    response = client.post(
        "/api/bundle/private/create",
        json={"name": "Admin Bundle", "description": "Bundle créé par admin"},
        content_type='application/json',
        headers={"X-API-KEY": API_KEY_ADMIN}
    )
    assert response.status_code == 200
    admin_bundle_id = response.get_json()["bundle_id"]

    # Le user tente d’ajouter une règle dans le bundle admin → refusé
    response = client.get(
        "/api/bundle/private/add_rule_bundle",
        query_string={
            "rule_id": 1,
            "bundle_id": admin_bundle_id,
            "description": "Trying to hack"
        },
        headers={"X-API-KEY": API_KEY_USER}
    )
    assert response.status_code == 401
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "permission" in json_data["message"].lower()

