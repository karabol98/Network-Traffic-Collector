import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from collector import app  # Import your FastAPI app
from user_management.models import Base, Role, RolePermission, User  # Import your SQLAlchemy models
from database import get_db  # Import your database setup
from user_management.schemas import RoleCreate
import utils
from unittest.mock import AsyncMock, patch
import uuid

test_indexes = [ "test_index1", "test_index2", "test_index3", "test_index4" ]

def add_random_suffix(prefix):
    return f"{prefix}{uuid.uuid4().hex[:8]}"

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
        admin.hashed_password = utils.hash_password("adminpassword")
        admin.roles = [role_admin]
        db.add(admin)
        
        # Add regular user
        regular = User(username="regular_user", email="user@example.com") 
        regular.hashed_password = utils.hash_password("userpassword")
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
    response = client.post("/login", json={"username": "admin", "password": "adminpassword"})
    print("Admin login response:", response.json())
    return response.json()["access_token"]

@pytest.fixture
def regular_user_token(client):
    # Create regular user login token
    response = client.post("/login", json={"username": "regular_user", "password": "userpassword"})
    return response.json()["access_token"]

test_role = {
    "name": "test_role",
    "description": "Test role description",
    "permissions": [
        {
            "index_name": "test_index1",
            "read": True,
            "write": False,
            "delete": False
        }
    ]
}

def test_create_role(admin_token, client):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = client.post("/admin/roles", json=test_role, headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == test_role["name"]
    assert response.json()["description"] == test_role["description"]
    assert len(response.json()["permissions"]) == len(test_role["permissions"])
    assert response.json()["permissions"][0]["index_name"] == test_role["permissions"][0]["index_name"]
    assert response.json()["permissions"][0]["read"] == test_role["permissions"][0]["read"]
    assert response.json()["permissions"][0]["write"] == test_role["permissions"][0]["write"]
    assert response.json()["permissions"][0]["delete"] == test_role["permissions"][0]["delete"]


def test_create_role_success(client, admin_token, db):
    # Setup
    role = {
        "name": "test_role1",
        "description": "Test role1 description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": True,
                "delete": False
            }
        ]
    }
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = client.post("/admin/roles", json=role, headers=headers)
    
    assert response.status_code == 200
    assert response.json()["name"] == role["name"]
    assert response.json()["description"] == role["description"]
    print(response.json())
    db_role = db.query(Role).filter(Role.name == role["name"]).first()
    assert db_role is not None
    assert len(db_role.permissions) == len(role["permissions"])
    assert db_role.permissions[0].index_name == role["permissions"][0]["index_name"]
    assert db_role.permissions[0].read_permission == role["permissions"][0]["read"]
    assert db_role.permissions[0].write_permission == role["permissions"][0]["write"]
    assert db_role.permissions[0].delete_permission == role["permissions"][0]["delete"]
    # Check if permissions are stored correctly
    db_permissions = db.query(RolePermission).filter(RolePermission.role_id == db_role.id).all()
    assert len(db_permissions) == len(role["permissions"])
    assert db_permissions[0].index_name == role["permissions"][0]["index_name"]
    assert db_permissions[0].read_permission == role["permissions"][0]["read"]
    assert db_permissions[0].write_permission == role["permissions"][0]["write"]
    assert db_permissions[0].delete_permission == role["permissions"][0]["delete"]


def test_create_role_unauthorized(client, regular_user_token):
    # Setup
    role = {
        "name": "test_role",
        "description": "Test role description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    
    response = client.post("/admin/roles", json=role, headers=headers)
    
    assert response.status_code == 403
    assert "You do not have the necessary admin permissions." in response.json()["detail"]


def test_create_role_duplicated(client, admin_token):
    # Setup
    role_name = add_random_suffix("role_")
    role = {
        "name": role_name,
        "description": "Test role1 description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Create the role first time
    response = client.post("/admin/roles", json=role, headers=headers)
    assert response.status_code == 200
    
    # Try to create the same role again
    response = client.post("/admin/roles", json=role, headers=headers)
    
    assert response.status_code == 400
    assert "Role already exists" in response.json()["detail"]


def test_create_role_invalid(client, admin_token):
    # Setup
    role = {
        "name": "test role", # Invalid name with space
        "description": "Test role description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Create the role with invalid data
    response = client.post("/admin/roles", json=role, headers=headers)
    
    assert response.status_code == 422
    assert "Name can only contain letters, numbers and underscores." in response.json()["detail"][0]["msg"]


def test_get_roles(admin_token, client):
    # Setup
    role_name = add_random_suffix("role_")
    role = {
        "name": role_name,
        "description": "Test role1 description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": True,
                "delete": False
            }
        ]
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post("/admin/roles", json=role, headers=headers)
    assert response.status_code == 200

    response = client.get("/admin/roles", headers=headers)
    assert response.status_code == 200
    roles = response.json()
    print(response.json())
    assert len(roles) > 0
    assert roles[-1]["name"] == role["name"]
    assert roles[-1]["description"] == role["description"]


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

def test_update_role_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    response = client.put(f"/admin/roles/{role.id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 200
    db.refresh(role)
    assert len(role.permissions) == len(index_permissions["permissions"])
    assert role.permissions[0].index_name == index_permissions["permissions"][0]["index_name"]
    assert role.permissions[0].read_permission == index_permissions["permissions"][0]["read"]
    assert role.permissions[0].write_permission == index_permissions["permissions"][0]["write"]
    assert role.permissions[0].delete_permission == index_permissions["permissions"][0]["delete"]
    assert len(response.json()["permissions"]) == len(index_permissions["permissions"])
    assert response.json()["permissions"][0]["index_name"] == index_permissions["permissions"][0]["index_name"]
    assert response.json()["permissions"][0]["read"] == index_permissions["permissions"][0]["read"]
    assert response.json()["permissions"][0]["write"] == index_permissions["permissions"][0]["write"]
    assert response.json()["permissions"][0]["delete"] == index_permissions["permissions"][0]["delete"]


def test_update_role_indexes_no_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    response = client.put(f"/admin/roles/{role.id}/indexes", json={}, headers=headers)
    assert response.status_code == 422
    assert "At least one index is required." in response.json()["detail"][0]["msg"]


def test_update_role_indexes_empty_indexes_list(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    response = client.put(f"/admin/roles/{role.id}/indexes", json={ "permissions": []}, headers=headers)
    assert response.status_code == 422
    assert "At least one index is required." in response.json()["detail"][0]["msg"]


def test_update_role_indexes_unauthrized(client, regular_user_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    response = client.put(f"/admin/roles/{role.id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 403

def test_update_role_indexes_not_found(client, admin_token):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_id = 99999
    
    response = client.put(f"/admin/roles/{non_existent_id}/indexes", json=index_permissions, headers=headers)
    assert response.status_code == 404
    assert "Role not found" in response.json()["detail"]

def test_add_role_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    prev_count = len(role.permissions)
    
    response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 200
    db.refresh(role)
    after_count = len(role.permissions)
    assert after_count == prev_count + 1
    new_permission = [permission for permission in role.permissions if permission.index_name == index_permission2["index_name"]][0]
    assert new_permission.index_name == index_permission2["index_name"]
    assert new_permission.read_permission == index_permission2["read"]
    assert new_permission.write_permission == index_permission2["write"]
    assert new_permission.delete_permission == index_permission2["delete"]
    resp_permission = [permission for permission in response.json()["permissions"] if permission["index_name"] == index_permission2["index_name"]][0]
    assert resp_permission["index_name"] == index_permission2["index_name"]
    assert resp_permission["read"] == index_permission2["read"]
    assert resp_permission["write"] == index_permission2["write"]
    assert resp_permission["delete"] == index_permission2["delete"]

def test_add_role_indexes_unkown_role(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role_id = 99999
    
    response = client.post(f"/admin/roles/{role_id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 404
    assert "Role not found" in response.json()["detail"]


def test_add_role_indexes_unauthorized(client, regular_user_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 403
    assert "You do not have the necessary admin permissions." in response.json()["detail"]

def test_add_role_indexes_already_exists(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    # Add the index first time
    response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission4, headers=headers)
    assert response.status_code == 200
    
    # Try to add the same index again
    response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission4, headers=headers)
    
    assert response.status_code == 400
    assert "Index already exists in role." in response.json()["detail"]


def test_add_role_indexes_no_indexes(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    
    # Remove all indexes from the role
    role.permissions = []
    db.commit()
    db.refresh(role)
    assert len(role.permissions) == 0
    
    response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission2, headers=headers)
    assert response.status_code == 200
    db.refresh(role)
    assert len(role.permissions) == 1
    assert role.permissions[0].index_name == index_permission2["index_name"]
    assert role.permissions[0].read_permission == index_permission2["read"]
    assert role.permissions[0].write_permission == index_permission2["write"]
    assert role.permissions[0].delete_permission == index_permission2["delete"]


def test_delete_role(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a new role to delete
    role = {
        "name": "role_to_delete",
        "description": "Role to be deleted",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    response = client.post("/admin/roles", json=role, headers=headers)
    assert response.status_code == 200

    # Get the created role
    role = db.query(Role).filter(Role.name == "role_to_delete").first()
    assert role is not None
    assert role.name == "role_to_delete"
    # Delete the role    
    response = client.delete(f"/admin/roles/{role.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == "role_to_delete"
    assert response.json()["description"] == "Role to be deleted"
    assert len(response.json()["permissions"]) == 1
    assert response.json()["permissions"][0]["index_name"] == "test_index1"
    assert response.json()["permissions"][0]["read"] == True
    assert response.json()["permissions"][0]["write"] == False
    assert response.json()["permissions"][0]["delete"] == False
    
    # Check if the role is actually deleted from the database
    deleted_role = db.query(Role).filter(Role.name == "role_to_delete").first()
    assert deleted_role is None


def test_delete_role_unauthorized(client, admin_token, regular_user_token, db):
    # Setup
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    user_headers = {"Authorization": f"Bearer {regular_user_token}"}
    
    # Create a new role to delete
    role = {
        "name": "role_to_delete",
        "description": "Role to be deleted",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    response = client.post("/admin/roles", json=role, headers=admin_headers)
    assert response.status_code == 200

    # Get the created role
    role = db.query(Role).filter(Role.name == "role_to_delete").first()
    assert role is not None
    assert role.name == "role_to_delete"
    
    # Try to delete the role with regular user token
    response = client.delete(f"/admin/roles/{role.id}", headers=user_headers)
    assert response.status_code == 403

    # delete the role from database
    db.delete(role)
    db.commit()
    role = db.query(Role).filter(Role.name == "role_to_delete").first()
    assert role is None


def test_delete_role_not_found(client, admin_token):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_id = 99999
    
    response = client.delete(f"/admin/roles/{non_existent_id}", headers=headers)
    assert response.status_code == 404
    assert "Role not found" in response.json()["detail"]


def test_delete_role_with_users(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Get a role with users
    role = db.query(Role).filter(Role.name == "user").first()
    assert role is not None
    assert role.name == "user"
    
    # Delete the role    
    response = client.delete(f"/admin/roles/{role.id}", headers=headers)
    assert response.status_code == 400
    assert "Cannot delete role with users." in response.json()["detail"]


def test_delete_role_with_child_roles(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a parent role
    parent_role = {
        "name": add_random_suffix("parent_role_"),
        "description": "Parent role description",
        "permissions": [
            {
                "index_name": "test_index1",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    response = client.post("/admin/roles", json=parent_role, headers=headers)
    assert response.status_code == 200

    # Get the parent role
    db_parent_role = db.query(Role).filter(Role.name == parent_role["name"]).first()
    assert db_parent_role is not None
    assert db_parent_role.name == parent_role["name"]

    # Create a child role
    child_role = {
        "name": add_random_suffix("child_role_"),
        "description": "Child role description",
        "parent_id": response.json()["id"],
        "permissions": [
            {
                "index_name": "test_index2",
                "read": True,
                "write": False,
                "delete": False
            }
        ]
    }
    response = client.post("/admin/roles", json=child_role, headers=headers)
    assert response.status_code == 200

    # Get the child role
    db_child_role = db.query(Role).filter(Role.name == child_role["name"]).first()
    assert db_child_role is not None
    assert db_child_role.name == child_role["name"]
    assert db_child_role.parent_id == db_parent_role.id
    
    # Delete the parent role    
    response = client.delete(f"/admin/roles/{db_parent_role.id}", headers=headers)
    assert response.status_code == 400
    assert "Cannot delete role with child roles." in response.json()["detail"]

    # delete the child role from database
    db.delete(db_child_role)
    # delete the parent role from database
    db.delete(db_parent_role)
    db.commit()


def test_delete_role_index(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    prev_count = len(role.permissions)
    
    # Add index to the role if not present
    if not any(permission.index_name == index_permission4["index_name"] for permission in role.permissions):
        # Add index to the role
        response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission4, headers=headers)
        assert response.status_code == 200
        db.refresh(role)
        after_count = len(role.permissions)
        assert after_count == prev_count + 1
        assert any(permission.index_name == index_permission4["index_name"] for permission in role.permissions)
        prev_count = after_count
    
    # Delete the index from the role
    response = client.delete(f"/admin/roles/{role.id}/indexes/{index_permission4["index_name"]}", headers=headers)
    assert response.status_code == 200
    
    # Check if the index is deleted
    db.refresh(role)
    assert len(role.permissions) == prev_count - 1
    assert not any(permission.index_name == index_permission4["index_name"] for permission in role.permissions)

def test_delete_role_index_unauthorized(client, admin_token, regular_user_token, db):
    # Setup
    regular_headers = {"Authorization": f"Bearer {regular_user_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()
    prev_count = len(role.permissions)
    
    if not any(permission.index_name == index_permission4["index_name"] for permission in role.permissions):
        # Add index to the role if not present
        response = client.post(f"/admin/roles/{role.id}/indexes", json=index_permission4, headers=admin_headers)
        assert response.status_code == 200
        db.refresh(role)
        assert len(role.permissions) == prev_count + 1
        assert any(permission.index_name == index_permission4["index_name"] for permission in role.permissions)
        
    # Delete the index from the role with regular user token
    response = client.delete(f"/admin/roles/{role.id}/indexes/{index_permission4["index_name"]}", headers=regular_headers)
    assert response.status_code == 403
    assert "You do not have the necessary admin permissions." in response.json()["detail"]


def test_delete_role_index_index_not_found(client, admin_token, db):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role = db.query(Role).filter(Role.name == "user").first()

    unknown_index_name = "unknown_index"
    
    # Delete the index from the role
    response = client.delete(f"/admin/roles/{role.id}/indexes/{unknown_index_name}", headers=headers)
    assert response.status_code == 404
    assert "Index not found" in response.json()["detail"]


def test_delete_role_index_role_not_found(client, admin_token):
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    role_id = 99999 
    
    # Delete the index from the role
    response = client.delete(f"/admin/roles/{role_id}/indexes/any_index_name", headers=headers)
    assert response.status_code == 404
    assert "Role not found" in response.json()["detail"]