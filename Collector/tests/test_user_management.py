from unittest.mock import AsyncMock, patch
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
import sqlalchemy
from sqlalchemy.orm import sessionmaker, Session
import tempfile
import os
from database import get_db
from collector import app
from user_management.models import Base, User, Role
from utils import hash_password
import utils

test_indexes = [ "test_index1", "test_index2" ]

# Mock Redis client
@pytest.fixture(autouse=True)
def mock_redis():
    with patch("storage.get_redis_pool") as MockRedis:
        mock_redis_instance = MockRedis.return_value
        mock_redis_instance.get = AsyncMock(return_value=None)
        mock_redis_instance.set = AsyncMock(return_value=True)
        mock_redis_instance.delete = AsyncMock(return_value=True)
        yield mock_redis_instance

@pytest.fixture(autouse=True, scope="session")
def mock_get_all_indexes_raw():
    with patch("utils.get_all_indexes_raw", return_value=test_indexes) as MockGetAllIndexesRaw:
        yield MockGetAllIndexesRaw

DEF_ADMIN_PASSWORD = "adminpassword"
DEF_USER_PASSWORD = "userpassword"

# Setup temp SQLite database for testing
@pytest.fixture(scope="session")
def db_engine():
    # Create a temporary file for the SQLite database
    temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    temp_db_file.close()
    DB_URL = f"sqlite:///{temp_db_file.name}"
    
    # Store the file path for cleanup
    db_file_path = temp_db_file.name
    
    # Set environment variable for database URL
    os.environ["DATABASE_URL"] = DB_URL
    
    # Create in-memory SQLite database with a persistent connection
    # SingletonThreadPool keeps the same connection alive for all checkout operations
    engine = create_engine(
        DB_URL,
        connect_args={"check_same_thread": False},
        # Using SingletonThreadPool instead of StaticPool to maintain a single connection
        poolclass=sqlalchemy.pool.SingletonThreadPool,
    )
       
    Base.metadata.create_all(engine)   
 
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        role_admin = Role(name="admin")
        role_user = Role(name="user")
        db.add(role_admin)
        db.add(role_user)
        db.commit()
        db.refresh(role_admin)
        db.refresh(role_user)
        
        # Add admin user
        admin = User(username="admin", email="admin@example.com")
        admin.hashed_password = utils.hash_password(DEF_ADMIN_PASSWORD)
        admin.roles = [role_admin]
        db.add(admin)
        
        # Add regular user
        regular = User(username="regular_user", email="user@example.com") 
        regular.hashed_password = utils.hash_password(DEF_USER_PASSWORD)
        regular.roles = [role_user]
        db.add(regular)
        
        db.commit()
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
        raise
    finally:
        db.close()

    yield engine
    
    # Dispose engine after tests
    engine.dispose()
    # Clean up the temporary database file
    try:
        os.unlink(db_file_path)
    except Exception as e:
        print(f"Error removing temporary database: {e}")


@pytest.fixture
def db(db_engine):
    # Create session for test
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


# Override the app's dependency to use our test database
@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides = {}
    # Replace the production database with our test database

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    # Create admin login token
    response = client.post("/login", json={"username": "admin", "password": DEF_ADMIN_PASSWORD})
    print("Admin login response:", response.json())
    return response.json()["access_token"]


@pytest.fixture
def regular_user_token(client):
    # Create regular user login token
    response = client.post("/login", json={"username": "regular_user", "password": DEF_USER_PASSWORD})
    return response.json()["access_token"]


@pytest.fixture
def test_user(db: Session):
    # Create a test user to delete later
    user = User(username="test_delete_user", email="test_delete@example.com")
    user.hashed_password = "hashed_password"  # In real test, use proper hashing
    role = db.query(Role).filter(Role.name == "user").first()
    user.roles = [ role ] # Assign a role to the user
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    # Cleanup in case test fails
    db_user = db.query(User).filter(User.id == user.id).first()
    if db_user:
        db.delete(db_user)
        db.commit()


# Test login functionality
def test_login_valid_credentials(client):
    response = client.post("/login", json={"username": "admin", "password": DEF_ADMIN_PASSWORD})
    assert response.status_code == 200
    assert "access_token" in response.json()
    # assert "access_token" in response.cookies


def test_login_invalid_credentials(client):
    response = client.post("/login", json={"username": "admin", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_login_missing_username(client):
    response = client.post("/login", json={"password": DEF_USER_PASSWORD})
    assert response.status_code == 400
    assert "invalid json format, missing username or password" in response.json()["detail"].lower()


def test_login_missing_password(client):
    response = client.post("/login", json={"username": "admin"})
    assert response.status_code == 400
    assert "invalid json format, missing username or password" in response.json()["detail"].lower()


def test_login_empty_username(client):
    response = client.post("/login", json={"username": "", "password": DEF_USER_PASSWORD})
    assert response.status_code == 401
    assert "invalid credentials" in response.json()["detail"].lower()


def test_login_empty_password(client):
    response = client.post("/login", json={"username": "admin", "password": ""})
    assert response.status_code == 401
    assert "invalid credentials" in response.json()["detail"].lower()

def test_logout(client):
    # Simulate a login first
    response = client.post("/login", json={"username": "admin", "password": DEF_ADMIN_PASSWORD})
    assert response.status_code == 200
    assert "access_token" in response.json()
    
    # Now test logout
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    client.cookies["access_token"] = response.json()["access_token"]
    response = client.post("/logout", headers=headers)
    assert response.status_code == 200
    assert "access_token" not in response.cookies
    assert "access_token" not in response.json()
    assert "Logout successful" in response.json()["message"]


# Test user creation (requires admin)
def test_create_user_as_admin(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser",
        "email": "new@example.com",
        "password": "newpass123",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "newuser"
    assert response.json()["email"] == "new@example.com"


# Test user creation (requires admin)
def test_create_user_with_permissions_as_admin(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get the role ID for regular user
    user_role = db.query(Role).filter(Role.name == "user").first()
    new_user = {
        "username": "newuser1",
        "email": "new1@example.com",
        "password": "newpass123",
        "role_ids": [ user_role.id ],  # Regular user role ID
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "newuser1"
    assert response.json()["email"] == "new1@example.com"
    assert len(response.json()["permissions"]) == 1
    assert response.json()["permissions"][0]["index_name"] == "test_index1"
    user = db.query(User).filter(User.username == "newuser1").first()
    assert user is not None
    assert len(user.permissions) == 1
    assert utils.user_has_index_permission_defined(user, "test_index1") is True
    assert utils.user_has_index_permission_defined(user, "test_index2") is False
    assert utils.user_has_read_access_on_index(user, "test_index1") is True
    assert utils.user_has_write_access_on_index(user, "test_index1") is False
    assert utils.user_has_delete_access_on_index(user, "test_index1") is False


def test_create_user_unauthorized(client, regular_user_token):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    new_user = {
        "username": "newuser2",
        "email": "new2@example.com",
        "password": "newpass123",
        "role_ids": [2]
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 403  # Should be forbidden for non-admin


# Test user creation (requires admin)
def test_create_user_as_admin_missing_username(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "email": "new@example.com",
        "password": "newpass123",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_small_username(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "nu",
        "email": "new@example.com",
        "password": "newpass123",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_large_username(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "n" * 100,  # Exceeding max length
        "email": "new@example.com",
        "password": "newpass123",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_invalid_username(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "new user",  # Invalid username with space
        "email": "new@example.com",
        "password": "newpass123",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_missing_password(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "new@example.com",
        "role_ids": [ 2 ]  # Regular user role ID
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_small_password(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "new@example.com",
        "role_ids": [ 2 ],  # Regular user role ID
        "password": "new"  # Too short password
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_missing_email(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "role_ids": [ 2 ],  # Regular user role ID
        "password": "newlllasdaiuhsffsadas"
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_invalid_email(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "newuser324234",  # Invalid email format
        "role_ids": [ 2 ],  # Regular user role ID
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_missing_role_ids(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "new@example.com",
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_empty_role_ids(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "new@example.com",
        "role_ids": [],  # Empty role IDs
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 422


# Test user creation (requires admin)
def test_create_user_as_admin_duplicate_username(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "regular_user",  # Duplicate username
        "email": "new@example.com",
        "role_ids": [ 1 ],
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 400


# Test user creation (requires admin)
def test_create_user_as_admin_duplicate_email(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "user@example.com",  # Duplicate email
        "role_ids": [ 1 ],
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 400


# Test user creation (requires admin)
def test_create_user_as_admin_unknown_role_id(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_user = {
        "username": "newuser324234",
        "email": "new@example.com",
        "role_ids": [ 99999 ],  # Unknown role ID
        "password": "newlllasdaiuhsffsadas" 
    }
    
    response = client.post("/admin/users", json=new_user, headers=headers)
    assert response.status_code == 400


# Test listing users
def test_list_users_as_admin(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/admin/users", headers=headers)
    
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 2  # At least admin and regular_user
    usernames = [user["username"] for user in users]
    assert "admin" in usernames
    assert "regular_user" in usernames


def test_list_users_as_regular_user(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Regular user should not be able to list all users
    response = client.get("/admin/users", headers=headers)
    
    assert response.status_code == 200
    users = response.json()
    assert len(users) == 1  # Regular user should only see their own info
    assert users[0]["username"] == "regular_user"


# Test getting a specific user
def test_get_user_by_id(client, admin_token, db):
    # Get the ID of regular_user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get(f"/admin/users/{user_id}", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["username"] == user.username
    assert response.json()["email"] == user.email


# Test getting a specific user
def test_get_user_by_id_self(client, regular_user_token, db):
    # Get the ID of regular_user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    response = client.get(f"/admin/users/{user_id}", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["username"] == user.username
    assert response.json()["email"] == user.email


# Test getting a specific user
def test_get_user_by_id_other_forbidden(client, regular_user_token, db):
    # Get the ID of regular_user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    admin_user = db.query(User).filter(User.username == "admin").first()
    
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    response = client.get(f"/admin/users/{admin_user.id}", headers=headers)
    
    assert response.status_code == 403


# Test getting a specific user
def test_get_user_me(client, regular_user_token, db):
    # Get the ID of regular_user
    user = db.query(User).filter(User.username == "regular_user").first()
    
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    response = client.get(f"/admin/users/me", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["username"] == user.username
    assert response.json()["email"] == user.email


def test_get_nonexistent_user(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/admin/users/9999", headers=headers)  # Non-existent ID
    
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]


def test_user_assign_roles_success(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get regular user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # Get a role
    role = db.query(Role).filter(Role.name == "user").first()
    role_id = role.id
    response = client.put(f"/admin/users/{user_id}/roles", json=[role_id], headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == user_id
    assert response.json()["roles"][0]["id"] == role_id
    assert response.json()["roles"][0]["name"] == role.name
    assert response.json()["roles"][0]["description"] == role.description
    assert response.json()["roles"][0]["parent_id"] == role.parent_id
    assert response.json()["roles"][0]["permissions"] == role.permissions

    response = client.get(f"/admin/users/{user_id}", headers=headers)
    assert response.status_code == 200
    ws_user = response.json()
    assert ws_user["id"] == user_id
    assert ws_user["roles"][0]["id"] == role_id
    assert ws_user["roles"][0]["name"] == role.name
    assert ws_user["roles"][0]["description"] == role.description


def test_user_assign_roles_forbiden(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get regular user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # Get a role
    role = db.query(Role).filter(Role.name == "user").first()
    role_id = role.id
    response = client.put(f"/admin/users/{user_id}/roles", json=[role_id], headers=headers)
    assert response.status_code == 403


def test_user_assign_roles_unknown_user(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # use an unknown user id
    user_id = 99999
    # Get a role
    role = db.query(Role).filter(Role.name == "user").first()
    role_id = role.id
    response = client.put(f"/admin/users/{user_id}/roles", json=[role_id], headers=headers)
    assert response.status_code == 404


def test_user_assign_roles_unknwon_role(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get regular user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # use an unknown role id
    role_id = 99999
    response = client.put(f"/admin/users/{user_id}/roles", json=[role_id], headers=headers)
    assert response.status_code == 400


def test_user_update_email_admin(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "admin").first()
    user_id = user.id
    # new email address, random
    new_email = "im_the_admin@acme.org"
    response = client.put(f"/admin/users/{user_id}", json={"email": new_email}, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == new_email
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    db.refresh(user)
    assert user.email == new_email


def test_user_update_email_regular_user_by_admin(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new email address, random
    new_email = "you_the_user@acme.org"
    response = client.put(f"/admin/users/{user_id}", json={"email": new_email}, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == new_email
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    db.refresh(user)
    assert user.email == new_email


def test_user_update_email_regular_user(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new email address, random
    new_email = "im_the_user@acme.org"
    response = client.put(f"/admin/users/{user_id}", json={"email": new_email}, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == new_email
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    db.refresh(user)
    assert user.email == new_email


def test_user_update_email_admin_by_regular_user(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "admin").first()
    user_id = user.id
    # new email address, random
    new_email = "you_the_admin@acme.org"
    response = client.put(f"/admin/users/{user_id}", json={"email": new_email}, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Only admins can update other users"


def add_random_suffix(prefix):
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def test_user_update_passwd_admin(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "admin").first()
    user_id = user.id
    # new password, random
    new_passwd = add_random_suffix("new_passwd_")
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    assert utils.verify_password(new_passwd, user.hashed_password) is True
    # Reset password to original for other tests
    user.hashed_password = hash_password(DEF_ADMIN_PASSWORD)
    db.commit()
    db.refresh(user)
    assert utils.verify_password(DEF_ADMIN_PASSWORD, user.hashed_password) is True


def test_user_update_passwd_regular_user_by_admin(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new password, random
    new_passwd = add_random_suffix("new_passwd_")
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    assert utils.verify_password(new_passwd, user.hashed_password) is True
    # Reset password to original for other tests
    user.hashed_password = hash_password(DEF_USER_PASSWORD)
    db.commit()
    db.refresh(user)
    assert utils.verify_password(DEF_USER_PASSWORD, user.hashed_password) is True


def test_user_update_passwd_regular_user(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new password, random
    new_passwd = add_random_suffix("new_passwd_")
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    assert response.json()["username"] == user.username
    assert response.json()["id"] == user_id
    # Check if the email is updated in the database
    assert utils.verify_password(new_passwd, user.hashed_password) is True
    # Reset password to original for other tests
    user.hashed_password = hash_password(DEF_USER_PASSWORD)
    db.commit()
    db.refresh(user)
    assert utils.verify_password(DEF_USER_PASSWORD, user.hashed_password) is True


def test_user_update_passwd_admin_by_regular_user(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get admin user
    user = db.query(User).filter(User.username == "admin").first()
    user_id = user.id
    # new password, random
    new_passwd = add_random_suffix("new_passwd_")
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Only admins can update other users"


def test_user_update_nothing(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get user 
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    response = client.put(f"/admin/users/{user_id}", json={}, headers=headers)
    assert response.status_code == 422


def test_user_update_password_short(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get user 
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new password, random
    new_passwd = add_random_suffix("")
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 422


def test_user_update_password_unknwon_user(client, admin_token, db):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Unknown user 
    user_id = 99999
    # new password, same
    new_passwd = DEF_USER_PASSWORD
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_user_update_password_same(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get user 
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new password, same
    new_passwd = DEF_USER_PASSWORD
    response = client.put(f"/admin/users/{user_id}", json={"password": new_passwd}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "New password must be different from the current one."


def test_user_update_invalid_email(client, regular_user_token, db):
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    # Get user 
    user = db.query(User).filter(User.username == "regular_user").first()
    user_id = user.id
    # new email, invalid
    new_email = "invalid_email"
    response = client.put(f"/admin/users/{user_id}", json={"email": new_email}, headers=headers)
    assert response.status_code == 422


####

index_permission1 = {
    "index_name": "test_index1",
    "read": True,
    "write": False,
    "delete": False
}

index_permission2 = {
    "index_name": "test_index2",
    "read": True,
    "write": False,
    "delete": False
}

index_permission3 = {
    "index_name": "test_index3",
    "read": True,
    "write": False,
    "delete": False
}

index_permission4 = {
    "index_name": "test_index4",
    "read": True,
    "write": False,
    "delete": False
}

index_permissions = {
    "permissions": [ index_permission1 ]
}

def test_update_user_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    response = client.put(f"/admin/users/{user.id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    assert len(user.permissions) == len(index_permissions["permissions"])
    assert user.permissions[0].index_name == index_permissions["permissions"][0]["index_name"]
    assert user.permissions[0].read_permission == index_permissions["permissions"][0]["read"]
    assert user.permissions[0].write_permission == index_permissions["permissions"][0]["write"]
    assert user.permissions[0].delete_permission == index_permissions["permissions"][0]["delete"]
    assert len(response.json()["permissions"]) == len(index_permissions["permissions"])
    assert response.json()["permissions"][0]["index_name"] == index_permissions["permissions"][0]["index_name"]
    assert response.json()["permissions"][0]["read"] == index_permissions["permissions"][0]["read"]
    assert response.json()["permissions"][0]["write"] == index_permissions["permissions"][0]["write"]
    assert response.json()["permissions"][0]["delete"] == index_permissions["permissions"][0]["delete"]


def test_update_user_indexes_no_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    response = client.put(f"/admin/users/{user.id}/indexes", json={}, headers=headers)
    assert response.status_code == 422
    assert "At least one index is required." in response.json()["detail"][0]["msg"]


def test_update_user_indexes_empty_indexes_list(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    response = client.put(f"/admin/users/{user.id}/indexes", json={ "permissions": []}, headers=headers)
    assert response.status_code == 422
    assert "At least one index is required." in response.json()["detail"][0]["msg"]


def test_update_user_indexes_unauthrized(client, regular_user_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    response = client.put(f"/admin/users/{user.id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 403

def test_update_user_indexes_not_found(client, admin_token):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_id = 99999
    
    response = client.put(f"/admin/users/{non_existent_id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]

def test_add_user_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    prev_count = len(user.permissions)
    
    response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    after_count = len(user.permissions)
    assert after_count == prev_count + 1
    new_permission = [permission for permission in user.permissions if permission.index_name == index_permission2["index_name"]][0]
    assert new_permission.index_name == index_permission2["index_name"]
    assert new_permission.read_permission == index_permission2["read"]
    assert new_permission.write_permission == index_permission2["write"]
    assert new_permission.delete_permission == index_permission2["delete"]
    resp_permission = [permission for permission in response.json()["permissions"] if permission["index_name"] == index_permission2["index_name"]][0]
    assert resp_permission["index_name"] == index_permission2["index_name"]
    assert resp_permission["read"] == index_permission2["read"]
    assert resp_permission["write"] == index_permission2["write"]
    assert resp_permission["delete"] == index_permission2["delete"]

def test_add_user_indexes_unkown_user(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = 99999
    
    response = client.post(f"/admin/users/{user_id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]


def test_add_user_indexes_unauthorized(client, regular_user_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 403
    assert "You do not have the necessary admin permissions." in response.json()["detail"]

def test_add_user_indexes_already_exists(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    # Add the index first time
    response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission4, headers=headers)
    assert response.status_code == 200
    
    # Try to add the same index again
    response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission4, headers=headers)
    
    assert response.status_code == 400
    assert "Index already exists in user." in response.json()["detail"]


def test_add_user_indexes_no_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    
    # Remove all indexes from the user
    user.permissions = []
    db.commit()
    db.refresh(user)
    assert len(user.permissions) == 0
    
    response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 200
    db.refresh(user)
    assert len(user.permissions) == 1
    assert user.permissions[0].index_name == index_permission2["index_name"]
    assert user.permissions[0].read_permission == index_permission2["read"]
    assert user.permissions[0].write_permission == index_permission2["write"]
    assert user.permissions[0].delete_permission == index_permission2["delete"]


def test_delete_user_index(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    prev_count = len(user.permissions)
    
    # Add index to the user if not present
    if not any(permission.index_name == index_permission4["index_name"] for permission in user.permissions):
        # Add index to the user
        response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission4, headers=headers)
        assert response.status_code == 200
        db.refresh(user)
        after_count = len(user.permissions)
        assert after_count == prev_count + 1
        assert any(permission.index_name == index_permission4["index_name"] for permission in user.permissions)
        prev_count = after_count
    
    # Delete the index from the user
    response = client.delete(f"/admin/users/{user.id}/indexes/{index_permission4["index_name"]}", headers=headers)
    assert response.status_code == 200
    
    # Check if the index is deleted
    db.refresh(user)
    assert len(user.permissions) == prev_count - 1
    assert not any(permission.index_name == index_permission4["index_name"] for permission in user.permissions)

def test_delete_user_index_unauthorized(client, admin_token, regular_user_token, db):
    # Setup
    regular_headers = {"Authorization": f"Bearer {regular_user_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()
    prev_count = len(user.permissions)
    
    if not any(permission.index_name == index_permission4["index_name"] for permission in user.permissions):
        # Add index to the user if not present
        response = client.post(f"/admin/users/{user.id}/indexes", json=index_permission4, headers=admin_headers)
        assert response.status_code == 200
        db.refresh(user)
        assert len(user.permissions) == prev_count + 1
        assert any(permission.index_name == index_permission4["index_name"] for permission in user.permissions)
        
    # Delete the index from the user with regular user token
    response = client.delete(f"/admin/users/{user.id}/indexes/{index_permission4["index_name"]}", headers=regular_headers)
    assert response.status_code == 403
    assert "You do not have the necessary admin permissions." in response.json()["detail"]


def test_delete_user_index_index_not_found(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user = db.query(User).filter(User.username == "regular_user").first()

    unknown_index_name = "unknown_index"
    
    # Delete the index from the user
    response = client.delete(f"/admin/users/{user.id}/indexes/{unknown_index_name}", headers=headers)
    assert response.status_code == 404
    assert "Index not found" in response.json()["detail"]


def test_delete_user_index_user_not_found(client, admin_token):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = 99999 
    
    # Delete the index from the user
    response = client.delete(f"/admin/users/{user_id}/indexes/any_index_name", headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]