import os
import pytest
from datetime import date, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.schemas.user import Gender, UserCreate
from app import crud


# Use SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

@pytest.fixture(scope="session")
def engine():
    """Create a new database engine for the tests."""
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Drop the database after tests
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture(scope="function")
def db_session(engine):
    """Create a new database session for a test."""
    # Create a sessionmaker that binds to our engine
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create a new session for the test
    db = TestingSessionLocal()
    
    try:
        yield db
    finally:
        # Close the session and rollback any changes
        db.rollback()
        db.close()


@pytest.fixture(scope="function")
def client(db_session):
    """Create a new FastAPI TestClient for testing API endpoints."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as c:
        yield c
    
    # Remove the override after the test
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create a test user in the database."""
    user_in = UserCreate(
        first_name="Test",
        last_name="User",
        date_of_birth=date.today() - timedelta(days=365 * 20),  # 20 years old
        gender=Gender.MALE,
        email="test.user@example.com",
        mobile="+8801712345678",
        password="testpassword",
        confirm_password="testpassword",
    )
    
    user = crud.user.create(db_session, obj_in=user_in)
    return user


@pytest.fixture(scope="function")
def verified_test_user(db_session, test_user):
    """Create a test user with a verified email."""
    user = crud.user.set_email_verified(db_session, user=test_user)
    return user


@pytest.fixture(scope="function")
def test_admin_user(db_session):
    """Create a test admin user in the database."""
    user_in = UserCreate(
        first_name="Admin",
        last_name="User",
        date_of_birth=date.today() - timedelta(days=365 * 30),  # 30 years old
        gender=Gender.MALE,
        email="admin.user@example.com",
        mobile="+8801712345679",
        password="testpassword",
        confirm_password="testpassword",
    )
    
    # Create user
    user = crud.user.create(db_session, obj_in=user_in)
    # Set as verified
    user = crud.user.set_email_verified(db_session, user=user)
    # Set as superuser
    user.is_superuser = True
    db_session.commit()
    return user


@pytest.fixture(scope="function")
def test_auth_headers(client, verified_test_user):
    """Get auth headers for a test user."""
    login_response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    
    tokens = login_response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture(scope="function")
def test_admin_headers(client, test_admin_user):
    """Get auth headers for a test admin user."""
    login_response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        data={"username": test_admin_user.email, "password": "testpassword"},
    )
    
    tokens = login_response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"} 