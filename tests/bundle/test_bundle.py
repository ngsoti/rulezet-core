# ##################################################__Test__Bundles__########################################################

# ###############
# #   Api key   #
# ###############


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




# # ---------- TESTS DE CRÉATION DE BUNDLE ----------

# def test_create_valid_bundle(client):
#     test_login_success(client)

#     myBundle = {
#         "name": "My Bundle Name",
#         "description": "This is a test bundle created via API."
#     }
#     response = client.post(
#         "/api/bundle/create",
#         json=myBundle,
#         content_type='application/json',
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 200
#     json_data = response.get_json()
#     assert json_data["message"] == "Bundle created successfully"
#     assert "bundle_id" in json_data

#     myBundle2 = {
#         "name": "ww",
#         "description": ""
#     }
#     response = client.post(
#         "/api/bundle/create",
#         json=myBundle2,
#         content_type='application/json',
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 200
#     json_data = response.get_json()
#     assert json_data["message"] == "Bundle created successfully"
#     assert "bundle_id" in json_data


# def test_create_invalid_bundle(client):
#     test_login_success(client)

#     myBundle = {
#         "name": "",
#         "description": "This is a test bundle created via API."
#     }
#     response = client.post(
#         "/api/bundle/create",
#         json=myBundle,
#         content_type='application/json',
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 400
#     json_data = response.get_json()
#     assert json_data["message"] == "Invalid bundle"
#     assert json_data["error"] == "Name is required"


# def test_add_rule_to_bundle_success(client):
#     test_login_success(client)
#     test_create_valid_bundle(client)
#     # On suppose que bundle_id=1 et rule_id=1 existent en base
#     response = client.get(
#         "/api/bundle/add_rule_bundle",
#         query_string={
#             "rule_id": 1,
#             "bundle_id": 1,
#             "description": "Test rule in bundle"
#         },
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 200
#     json_data = response.get_json()
#     assert json_data["success"] is True
#     assert json_data["message"] == "Rule added!"


# def test_add_rule_to_bundle_missing_params(client):
#     test_login_success(client)

#     response = client.get(
#         "/api/bundle/add_rule_bundle",
#         query_string={
#             "rule_id": 1,
#             "bundle_id": 1
#             # manque description
#         },
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 400
#     json_data = response.get_json()
#     assert json_data["success"] is False
#     assert "Missing" in json_data["message"]


# def test_add_rule_to_bundle_not_found(client):
#     test_login_success(client)

#     response = client.get(
#         "/api/bundle/add_rule_bundle",
#         query_string={
#             "rule_id": 1,
#             "bundle_id": 9999,  # inexistant
#             "description": "Test rule in bundle"
#         },
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 404
#     json_data = response.get_json()
#     assert json_data["success"] is False
#     assert json_data["message"] == "Bundle not found"


# def test_add_rule_to_bundle_permission_denied(client):
#     # Création du bundle en tant qu’admin (bundle_id=1)
#     test_login_admin(client)
#     response = client.post(
#         "/api/bundle/create",
#         json={"name": "Admin Bundle", "description": "Bundle créé par admin"},
#         content_type='application/json',
#         headers={"X-API-KEY": API_KEY_ADMIN}
#     )
#     assert response.status_code == 200
#     admin_bundle_id = response.get_json()["bundle_id"]

#     # On se connecte comme user normal
#     test_login_success(client)

#     # Le user tente d’ajouter une règle dans le bundle admin → refusé
#     response = client.get(
#         "/api/bundle/add_rule_bundle",
#         query_string={
#             "rule_id": 1,
#             "bundle_id": admin_bundle_id,
#             "description": "Trying to hack"
#         },
#         headers={"X-API-KEY": API_KEY_USER}
#     )
#     assert response.status_code == 401
#     json_data = response.get_json()
#     assert json_data["success"] is False
#     assert "permission" in json_data["message"].lower()

