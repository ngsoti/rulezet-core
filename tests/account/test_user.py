#####################
#   register case   #
#####################

from app.db_class.db import User
API_KEY = "admin_api_key"

def create_user(client) -> None:
    """Create an User test"""
    client.post("/api/account/register",
                content_type='application/json',
                headers={"X-API-KEY": API_KEY},
                json={
                    "email": "test@example.com",
                    "password": "password",
                    "first_name": "Test",
                    "last_name": "User"
                })

def test_register_and_reject_duplicate(client):
    # First registration
    response = client.post("/api/account/register", json={
        "email": "test@example.com",
        "password": "password",
        "first_name": "Test",
        "last_name": "User"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 201
    assert b"User registered successfully" in response.data

    # Second registration with same email
    response = client.post("/api/account/register", json={
        "email": "test@example.com",
        "password": "password",
        "first_name": "Test",
        "last_name": "User"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 409
    assert b"Email already exists" in response.data


def test_register_with_bad_email(client):
    response = client.post("/api/account/register", json={
        "email": "invalideEmail",
        "password": "password",
        "first_name": "Test",
        "last_name": "User"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"Invalid email" in response.data

# #####################
# #   login case      #
# #####################


def test_login_success(client):
    # First, register a user
    create_user(client)

    # Then test login
    response = client.post("/api/account/login", json={
        "email": "test@example.com",
        "password": "password",
        "remember_me": True
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 200
    assert b"Logged in successfully" in response.data


def test_login_invalid_email_format(client):
    create_user(client)
    response = client.post("/api/account/login", json={
        "email": "invalid-email",
        "password": "password"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"Invalid email" in response.data


def test_login_missing_fields(client):
    create_user(client)
    response = client.post("/api/account/login", json={
        "email": "test@example.com"
        # password is missing
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"Missing fields" in response.data


def test_login_wrong_password(client):
    create_user(client)

    response = client.post("/api/account/login", json={
        "email": "test@example.com",
        "password": "wrongpass"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_login_email_not_found(client):
    response = client.post("/api/account/login", json={
        "email": "notfound@example.com",
        "password": "password"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_login_remember_me_not_bool(client):
    response = client.post("/api/account/login", json={
        "email": "test@example.com",
        "password": "password",
        "remember_me": "yes"  # Invalid type
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"remember_me must be a boolean" in response.data

#############
#   logout  #
#############

def test_logout(client):
    create_user(client)
    test_login_success(client)
    response = client.post("/api/account/logout")
    assert response.status_code == 200
    assert b"You have been logged out." in response.data

#############
#   Edit    #
#############

def test_edit_user_success(client):
    create_user(client)
    test_login_success(client)
    response = client.post("/api/account/edit", json={
        "email": "newemail@example.com",
        "first_name": "NewFirst",
        "last_name": "NewLast"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 200
    assert b"User updated successfully" in response.data


def test_edit_user_missing_field(client):
    create_user(client)
    test_login_success(client)
    response = client.post("/api/account/edit", json={
        "email": "newemail@example.com",
        "first_name": "OnlyFirst"
        # missing last_name
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"last_name is required" in response.data


def test_edit_user_invalid_email_format(client):
    create_user(client)
    test_login_success(client)
    response = client.post("/api/account/edit", json={
        "email": "invalid-email",
        "first_name": "First",
        "last_name": "Last"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 400
    assert b"Invalid email format" in response.data


def test_edit_user_email_already_used(client):
    create_user(client)
    test_login_success(client)
    response = client.post("/api/account/edit", json={
        "email": "t@t.t",
        "first_name": "Test",
        "last_name": "User"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 409
    assert b"Email already registered" in response.data


def test_edit_user_same_email_allowed(client):
    create_user(client)
    test_login_success(client)
    # Reuse the same email: should be OK
    response = client.post("/api/account/edit", json={
        "email": "test@example.com",  # unchanged
        "first_name": "Updated",
        "last_name": "User"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code == 200
    assert b"User updated successfully" in response.data


def test_edit_user_without_authentication(client):
    create_user(client)
    # Not logged in
    response = client.post("/api/account/edit", json={
        "email": "unauth@example.com",
        "first_name": "A",
        "last_name": "B"
    },headers={"X-API-KEY": API_KEY})
    assert response.status_code in (401, 302)  # Depending on how login_required behaves


#################
#   redirect    #
#################

def test_favorite_page(client):
    create_user(client)
    test_login_success(client)
    response = client.get('/api/account/favorite')
    assert response.status_code == 200

def test_profile_page(client):
    create_user(client)
    test_login_success(client)
    response = client.get('/api/account/profil')
    assert response.status_code == 200



