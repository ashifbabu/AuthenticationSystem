import pytest
from datetime import date, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import uuid

# Import our application code
from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.schemas.user import Gender


# Use SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_user_registration.db"


@pytest.fixture(scope="module")
def test_db_engine():
    """Create a test database engine."""
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Clean up
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test_user_registration.db"):
        os.remove("./test_user_registration.db")


@pytest.fixture(scope="function")
def test_db(test_db_engine):
    """Create a new database session for a test."""
    # Create a sessionmaker 
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    
    # Create a new session
    db = TestSessionLocal()
    
    try:
        yield db
    finally:
        # Close the session and rollback any changes
        db.rollback()
        db.close()


@pytest.fixture(scope="function")
def client(test_db):
    """Create a FastAPI test client with a test database."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass
    
    # Override the dependency
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as c:
        yield c
    
    # Clear dependency overrides
    app.dependency_overrides.clear()


def test_register_user_success(client):
    """Test successful user registration."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),  # 25 years ago
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",  # Unique email
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 200, f"Response: {response.text}"
    data = response.json()
    
    # Verify response data
    assert data["first_name"] == user_data["first_name"]
    assert data["last_name"] == user_data["last_name"]
    assert data["email"] == user_data["email"]
    assert "id" in data
    assert data["is_active"] is True
    assert data["is_email_verified"] is False  # Email verification required


def test_register_user_password_mismatch(client):
    """Test registration with password mismatch."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.FEMALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "DifferentPassword123!"  # Different password
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("password" in error["loc"] for error in data["detail"])


def test_register_user_duplicate_email(client):
    """Test registration with an email that already exists."""
    # First registration
    email = f"test.user.{uuid.uuid4()}@example.com"
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": email,  # Use the same email for both registrations
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    # First registration should succeed
    response = client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 200, f"First registration failed: {response.text}"
    
    # Second registration with same email should fail
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 409, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert "already exists" in data["detail"]


def test_register_user_invalid_email(client):
    """Test registration with invalid email format."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": "invalid-email-format",  # Invalid email format
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("email" in error["loc"] for error in data["detail"])


def test_register_user_underage(client):
    """Test registration with a user who is too young."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 12)),  # 12 years old
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    # The API might return 422 or 400 depending on implementation
    assert response.status_code in [400, 422], f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data


def test_register_user_invalid_mobile(client):
    """Test registration with invalid mobile format."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "1234567890",  # Invalid Bangladeshi format
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("mobile" in error["loc"] for error in data["detail"])


def test_register_user_weak_password(client):
    """Test registration with a weak password."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "password",  # Weak password
        "confirm_password": "password"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    # The API might return 422 or 400 depending on implementation
    assert response.status_code in [400, 422], f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data 