import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
import sqlalchemy
from sqlalchemy.orm import sessionmaker, Session
from collector import app
from user_management.models import Role, User, Base
from unittest.mock import patch
from database import get_db
import os
import tempfile
import utils

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

@pytest.fixture
def test_user(db: Session):
    # Create a test user to delete later
    user = User(username="test_delete_user", email="test_delete@example.com")
    user.hashed_password = "hashed_password"  # In real test, use proper hashing
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    # Cleanup in case test fails
    db_user = db.query(User).filter(User.id == user.id).first()
    if db_user:
        db.delete(db_user)
        db.commit()

@patch("user_management.routes.delete_user_history")
def test_delete_user_success(mock_delete_history, admin_token, test_user, db: Session, client):
    """Test successful deletion of a user by admin"""
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Execute
    response = client.delete(f"/admin/users/{test_user.id}", headers=headers)
    
    # Verify
    assert response.status_code == 200
    assert response.json()["id"] == test_user.id
    assert response.json()["username"] == test_user.username
    
    # Verify user is deleted from database
    db_user = db.query(User).filter(User.id == test_user.id).first()
    assert db_user is None
    
    # Verify history deletion was called
    mock_delete_history.assert_called_once_with(test_user.id)

def test_delete_user_not_found(admin_token, client):
    """Test deleting a non-existent user"""
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_id = 99999
    
    # Execute
    response = client.delete(f"/admin/users/{non_existent_id}", headers=headers)
    
    # Verify
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]

def test_delete_self(admin_token, db: Session, client):
    """Test admin trying to delete themselves"""
    # Setup
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get admin's user ID
    admin_info = client.get("/admin/users/me", headers=headers).json()
    admin_id = admin_info["id"]
    
    # Execute
    response = client.delete(f"/admin/users/{admin_id}", headers=headers)
    
    # Verify
    assert response.status_code == 403
    assert "You cannot delete yourself" in response.json()["detail"]

def test_delete_user_unauthorized(client):
    """Test deleting a user without authentication"""
    # Execute
    response = client.delete("/admin/users/1")
    
    # Verify
    assert response.status_code == 401

def test_delete_user_forbidden(regular_user_token, test_user, client):
    """Test regular user cannot delete other users"""
    # Setup
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    
    # Execute
    response = client.delete(f"/admin/users/{test_user.id}", headers=headers)
    
    # Verify
    assert response.status_code == 403