# #####################
# #   register case   #
# #####################

# # API_KEY = "admin_api_key"

# def create_user(client) -> None:
#     """Create an User test"""
#     response = client.post("/api/account/register",
#         content_type='application/json',
#         json={
#             "email": "test@example.com",
#             "password": "password1@A",
#             "first_name": "Test",
#             "last_name": "User"
#         })
#     data = response.get_json()
#     assert response.status_code == 201
#     assert "X-API-KEY" in data
#     return(data["X-API-KEY"])


# def test_register_success(client):
#     # First registration
#     response = client.post("/api/account/register", json={
#         "email": "test@example.com",
#         "password": "password!!1A@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 201
#     assert b"User registered successfully" in response.data

# def test_register_and_reject_duplicate(client):
#     # First registration
#     response = client.post("/api/account/register", json={
#         "email": "test@example.com",
#         "password": "password1Q@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 201
#     assert b"User registered successfully" in response.data

#     # Second registration with same email
#     response = client.post("/api/account/register", json={
#         "email": "test@example.com",
#         "password": "password1Q@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 409
#     assert b"Email already exists" in response.data


# def test_register_with_bad_email(client):
#     response = client.post("/api/account/register", json={
#         "email": "invalideEmail",
#         "password": "password1Q@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Invalid email" in response.data

# def test_register_with_bad_password_miss_uppercase(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "password1@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must contain at least one uppercase letter." in response.data

# def test_register_with_bad_password_miss_lowercase(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "PASSWORD1@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must contain at least one lowercase letter." in response.data 

# def test_register_with_bad_password_miss_digit(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "Password@",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must contain at least one digit." in response.data    

# def test_register_with_bad_password_miss_special_char(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "Password1",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must contain at least one special character (@$!%*?&)." in response.data

# def test_register_with_bad_password_too_short(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "P1@a",
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must be between 8 and 64 characters." in response.data    
# def test_register_with_bad_password_too_long(client):
#     response = client.post("/api/account/register", json={
#         "email": "a@a.a",
#         "password": "P1@" + "a"*62,
#         "first_name": "Test",
#         "last_name": "User"
#     })
#     assert response.status_code == 400
#     assert b"Password must be between 8 and 64 characters." in response.data    
# # #####################
# # #   login case      #
# # #####################


# def test_login_success(client):
#     # First, register a user
#     api_key = create_user(client)

#     # Then test login
#     response = client.post("/api/account/login", json={
#         "email": "test@example.com",
#         "password": "password1@A",
#         "remember_me": True
#     })
#     assert response.status_code == 200
#     assert b"Logged in successfully" in response.data
#     return api_key


# def test_login_invalid_email_format(client):
#     create_user(client)
#     response = client.post("/api/account/login", json={
#         "email": "invalid-email",
#         "password": "password1@A"
#     })
#     assert response.status_code == 400
#     assert b"Invalid email" in response.data


# def test_login_missing_fields(client):
#     create_user(client)
#     response = client.post("/api/account/login", json={
#         "email": "test@example.com"
#         # password is missing
#     })
#     assert response.status_code == 400
#     assert b"Missing fields" in response.data


# def test_login_wrong_password(client):
#     create_user(client)

#     response = client.post("/api/account/login", json={
#         "email": "test@example.com",
#         "password": "wrongpass"
#     })
#     assert response.status_code == 401
#     assert b"Invalid email or password" in response.data


# def test_login_email_not_found(client):
#     response = client.post("/api/account/login", json={
#         "email": "notfound@example.com",
#         "password": "password1@A"
#     })
#     assert response.status_code == 401
#     assert b"Invalid email or password" in response.data


# def test_login_remember_me_not_bool(client):
#     response = client.post("/api/account/login", json={
#         "email": "test@example.com",
#         "password": "password1@A",
#         "remember_me": "yes"  # Invalid type
#     })
#     assert response.status_code == 400
#     assert b"remember_me must be a boolean" in response.data

# # #############
# # #   logout  #
# # #############

# def test_logout(client):
#     test_login_success(client)
#     response = client.post("/api/account/logout")
#     assert response.status_code == 200
#     assert b"You have been logged out." in response.data

# #############
# #   Edit    #
# #############

# def test_edit_user_success(client):
#     api_key = test_login_success(client)
#     response = client.post("/api/account/edit", json={
#         "email": "newemail@example.com",
#         "first_name": "NewFirst",
#         "last_name": "NewLast"
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code == 200
#     assert b"User updated successfully" in response.data


# def test_edit_user_missing_field(client):
#     api_key = test_login_success(client)
#     response = client.post("/api/account/edit", json={
#         "email": "newemail@example.com",
#         "first_name": "OnlyFirst"
#         # missing last_name
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code == 400
#     assert b"last_name is required" in response.data


# def test_edit_user_invalid_email_format(client):
#     api_key = test_login_success(client)
#     response = client.post("/api/account/edit", json={
#         "email": "invalid-email",
#         "first_name": "First",
#         "last_name": "Last"
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code == 400
#     assert b"Invalid email format" in response.data


# def test_edit_user_email_already_used(client):
#     api_key = test_login_success(client)
#     response = client.post("/api/account/edit", json={
#         "email": "t@t.t",
#         "first_name": "Test",
#         "last_name": "User"
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code == 409
#     assert b"Email already registered" in response.data


# def test_edit_user_same_email_allowed(client):
#     api_key = test_login_success(client)
#     # Reuse the same email: should be OK
#     response = client.post("/api/account/edit", json={
#         "email": "test@example.com",  # unchanged
#         "first_name": "Updated",
#         "last_name": "User"
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code == 200
#     assert b"User updated successfully" in response.data


# def test_edit_user_without_authentication(client):
#     api_key = "invalide_api_key"
#     # Not logged in
#     response = client.post("/api/account/edit", json={
#         "email": "unauth@example.com",
#         "first_name": "A",
#         "last_name": "B"
#     },headers={"X-API-KEY": api_key})
#     assert response.status_code in (401, 302)  # Depending on how login_required behaves


# # #################
# # #   redirect    #
# # #################

# # def test_favorite_page(client):
# #     create_user(client)
# #     test_login_success(client)
# #     response = client.get('/api/account/favorite')
# #     assert response.status_code == 200

# # def test_profile_page(client):
# #     create_user(client)
# #     test_login_success(client)
# #     response = client.get('/api/account/profil')
# #     assert response.status_code == 200



