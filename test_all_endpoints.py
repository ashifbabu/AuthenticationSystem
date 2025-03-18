import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, date
from sqlalchemy import text
from unittest.mock import patch, AsyncMock

from app.main import app
from app.core.config import settings
from app.models.user import User
from app.models.token import Token, TokenType
from app.crud import user as user_crud
from app.crud import token as token_crud
from app.core.security import create_access_token, create_refresh_token
from app.schemas.user import UserCreate, Gender
from app.core.enums import OAuthProvider
from app.schemas.oauth import OAuthUserInfo
from app.db.base_class import Base
from app.db.session import engine, SessionLocal
from datetime import datetime, timedelta
from uuid import uuid4

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    
    client = TestClient(app)
    
    # Get CSRF token
    response = client.get("/api/v1/auth/csrf-token")
    csrf_token = response.json()["csrf_token"]
    
    # Set CSRF token in headers for all requests
    client.headers.update({
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/json"
    })
    
    return client

# Test data
test_user_dict = {
    "email": "test@example.com",
    "password": "Test123!@#",
    "confirm_password": "Test123!@#",
    "first_name": "Test",
    "last_name": "User",
    "mobile": "+8801234567890",
    "date_of_birth": "1990-01-01",
    "gender": "male"
}

test_user_data = UserCreate(
    email="test@example.com",
    password="Test123!@#",
    confirm_password="Test123!@#",
    first_name="Test",
    last_name="User",
    mobile="+8801234567890",
    date_of_birth=date(1990, 1, 1),
    gender=Gender.MALE
)

@pytest.fixture
def test_user(db: Session):
    # First check if user already exists
    user = user_crud.get_by_email(db, email=test_user_data.email)
    if not user:
        user = user_crud.create(db, obj_in=test_user_data)
    
    # Verify the user's email if not already verified
    if not user.is_email_verified:
        user = user_crud.set_email_verified(db, user=user)
    
    # Ensure the user is active
    if not user.is_active:
        user = user_crud.update(db, db_obj=user, obj_in={"is_active": True})
    
    return user

@pytest.fixture
def test_user_token(test_user: User, db: Session):
    """Create access and refresh tokens for test user."""
    from app.models.token import Token, TokenType
    from datetime import datetime, timedelta
    from uuid import uuid4
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=test_user.id,
        expires_delta=access_token_expires
    )
    
    # Create refresh token
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_refresh_token(
        user_id=test_user.id,
        expires_delta=refresh_token_expires
    )
    
    # Store tokens in the database
    db_access_token = Token(
        id=str(uuid4()),
        user_id=test_user.id,
        token=access_token,
        token_type=TokenType.ACCESS,
        expires_at=datetime.utcnow() + access_token_expires,
        created_at=datetime.utcnow()
    )
    db.add(db_access_token)
    
    db_refresh_token = Token(
        id=str(uuid4()),
        user_id=test_user.id,
        token=refresh_token,
        token_type=TokenType.REFRESH,
        expires_at=datetime.utcnow() + refresh_token_expires,
        created_at=datetime.utcnow()
    )
    db.add(db_refresh_token)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@pytest.fixture(autouse=True)
def cleanup_database():
    """Clean up the database before each test."""
    from app.db.base import Base
    from app.db.session import engine, SessionLocal
    from sqlalchemy import text
    
    # Drop and recreate all tables
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    # Create a new session and delete all data
    db = SessionLocal()
    try:
        # Delete all data from tables in reverse order of dependencies
        db.execute(text("DELETE FROM tokens"))
        db.execute(text("DELETE FROM oauth_accounts"))
        db.execute(text("DELETE FROM login_attempts"))
        db.execute(text("DELETE FROM users"))
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

# Health Check Tests
def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

# Registration Tests
def test_register_user(client):
    response = client.post("/api/v1/auth/register", json=test_user_dict)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == test_user_dict["email"]
    assert data["first_name"] == test_user_dict["first_name"]
    assert data["last_name"] == test_user_dict["last_name"]

def test_register_duplicate_email(client, test_user: User):
    # First ensure the test user exists
    response = client.post("/api/v1/auth/register", json=test_user_dict)
    assert response.status_code == 200
    
    # Now try to register with the same email
    duplicate_user_dict = test_user_dict.copy()
    duplicate_user_dict["email"] = test_user.email  # Use the email from the test_user fixture
    response = client.post("/api/v1/auth/register", json=duplicate_user_dict)
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]

# Email Verification Tests
def test_verify_email(client, test_user: User, db: Session):
    # Create verification token
    token_value = "test_verification_token"
    token = user_crud.create_verification_token(
        db=db,
        user_id=test_user.id,
        token=token_value,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_delta=timedelta(hours=24)
    )

    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": token_value}
    )
    assert response.status_code == 200

# Login Tests
def test_login(client, test_user: User):
    # Ensure the test user has a verified email
    db = SessionLocal()
    try:
        user = user_crud.get_by_email(db, email=test_user_dict["email"])
        if user:
            user = user_crud.update(db, db_obj=user, obj_in={"is_email_verified": True})
            db.commit()
            db.refresh(user)
    finally:
        db.close()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": test_user_dict["email"],
            "password": test_user_dict["password"]
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client):
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "wrong@example.com",
            "password": "wrongpassword"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401

# Token Refresh Tests
def test_refresh_token(client, test_user_token: dict):
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": test_user_token["refresh_token"]},
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

# Logout Tests
def test_logout(client, test_user_token: dict):
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"refresh_token": test_user_token["refresh_token"]}
    )
    assert response.status_code == 204

# Password Management Tests
def test_forgot_password(client, test_user: User):
    response = client.post(
        "/api/v1/auth/forgot-password",
        json={"email": test_user_dict["email"]}
    )
    assert response.status_code == 204

def test_reset_password(client, test_user: User, db: Session):
    # Create reset token
    token = user_crud.create_verification_token(
        db=db,
        user_id=test_user.id,
        token="reset_token",
        token_type=TokenType.PASSWORD_RESET,
        expires_delta=timedelta(hours=24)
    )

    response = client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "reset_token",
            "new_password": "NewTest123!@#"
        }
    )
    assert response.status_code == 200

def test_change_password(client, test_user_token: dict):
    response = client.put(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={
            "current_password": test_user_dict["password"],
            "new_password": "NewTest123!@#"
        }
    )
    assert response.status_code == 200

# MFA Tests
def test_enable_mfa(client, test_user_token: dict):
    response = client.post(
        "/api/v1/auth/mfa/enable",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200

def test_verify_mfa(client, test_user_token: dict):
    response = client.post(
        "/api/v1/auth/mfa/verify",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"code": "123456"}
    )
    assert response.status_code == 200

def test_disable_mfa(client, test_user_token: dict):
    response = client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"password": test_user_dict["password"]}
    )
    assert response.status_code == 200

# OAuth Tests
@pytest.mark.asyncio
async def test_oauth_login(client):
    mock_url = "https://example.com/oauth"
    mock_state = "test_state"
    with patch("app.services.oauth.generate_oauth_state", return_value=mock_state), \
         patch("app.services.oauth.get_oauth_login_url", return_value=mock_url):
        response = client.post(
            "/api/v1/auth/oauth/google/login",
            json={
                "redirect_uri": "http://localhost:8000/callback",
                "state": mock_state
            }
        )
        assert response.status_code == 302
        assert response.headers["location"] == mock_url

@pytest.mark.asyncio
async def test_oauth_callback(client):
    # Mock data
    mock_token_data = {
        "access_token": "mock_access_token",
        "token_type": "bearer",
        "expires_in": 3600,
        "expires_at": datetime.utcnow() + timedelta(seconds=3600),
        "refresh_token": "mock_refresh_token"
    }
    
    mock_user_info = OAuthUserInfo(
        provider=OAuthProvider.GOOGLE,
        provider_user_id="mock_user_id",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        picture_url="https://example.com/picture.jpg",
        gender=None,
        date_of_birth=None,
        raw_data={}
    )

    # Set up mocks
    async def mock_exchange(*args, **kwargs):
        return mock_token_data

    async def mock_get_user_info(*args, **kwargs):
        return mock_user_info

    with patch("app.services.oauth.exchange_code_for_token", new=mock_exchange), \
         patch("app.services.oauth.get_user_info", new=mock_get_user_info), \
         patch("app.crud.oauth_account.get_by_provider_and_user", return_value=None), \
         patch("app.crud.user.get_by_email", return_value=None), \
         patch("app.crud.oauth_account.create"), \
         patch("app.core.security.create_access_token", return_value="mock_access_token"), \
         patch("app.core.security.create_refresh_token", return_value="mock_refresh_token"), \
         patch("app.crud.token.create_access_token"), \
         patch("app.crud.token.create_refresh_token"):

        response = client.post(
            "/api/v1/auth/oauth/google/callback",
            json={
                "code": "mock_code",
                "state": "test_state",
                "redirect_uri": "http://localhost:8000/callback"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

# Account Status Tests
def test_check_account_status(client, test_user_token: dict):
    response = client.get(
        f"/api/v1/auth/account-status/{test_user_dict['email']}",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200

def test_unlock_account(client, test_user_token: dict):
    response = client.post(
        f"/api/v1/auth/unlock-account/{test_user_dict['email']}",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 204

# User Profile Tests
def test_read_current_user(client, test_user_token: dict):
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200

def test_update_current_user(client, test_user_token: dict):
    response = client.put(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"first_name": "Updated", "last_name": "Name"}
    )
    assert response.status_code == 200

def test_read_oauth_accounts(client, test_user_token: dict):
    response = client.get(
        "/api/v1/users/me/oauth-accounts",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200

def test_delete_oauth_account(client, test_user_token: dict):
    response = client.delete(
        f"/api/v1/users/me/oauth-accounts/{OAuthProvider.GOOGLE}",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200

def test_delete_account(client, test_user_token: dict):
    response = client.delete(
        f"/api/v1/users/me?password={test_user_dict['password']}",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 204