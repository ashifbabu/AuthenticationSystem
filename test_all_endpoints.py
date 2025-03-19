import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool
from datetime import datetime, timedelta, date
from unittest.mock import patch, AsyncMock
from uuid import uuid4
import secrets
import pyotp
import uuid
from typing import Dict, Any
from fastapi import Depends

from app.main import app
from app.core.config import settings
from app.models.user import User
from app.models.token import Token, TokenType, AccessToken
from app.models.oauth import OAuthAccount
from app.schemas.oauth import OAuthAccountCreate
from app.crud import user as user_crud
from app.crud import token as token_crud
from app.crud.oauth_account import oauth_crud
from app.core.security import create_access_token, create_refresh_token, get_password_hash
from app.schemas.user import UserCreate, Gender
from app.core.enums import OAuthProvider
from app.schemas.oauth import OAuthUserInfo
from app.db.base_class import Base
from app.db.session import SessionLocal, get_db
from app.db.init_db import init_db
from app.models.token import OAuthStateToken

@pytest.fixture(scope="session")
def db_engine():
    """Create a test database engine."""
    # Use in-memory SQLite for tests
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    return engine

@pytest.fixture(scope="function")
def db(db_engine):
    """Get a database session for testing."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    
    # Initialize database with required data
    init_db(session)
    
    yield session
    
    # Rollback the transaction
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(db):
    """Create a test client with a fresh database."""
    app.dependency_overrides[get_db] = lambda: db

    client = TestClient(app)

    # Generate a CSRF token
    csrf_token = secrets.token_urlsafe(32)

    # Set CSRF token in headers and cookies for all requests
    client.headers.update({
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/json"
    })
    client.cookies.update({
        "csrf_token": csrf_token
    })

    # Create a new client with the updated headers and cookies
    client = TestClient(app, headers=client.headers, cookies=client.cookies)

    yield client

    # Clean up
    app.dependency_overrides.clear()

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
    """Create a test user if it doesn't exist."""
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
    
    # Refresh the user object to get the latest state
    db.refresh(user)
    return user

@pytest.fixture
def test_user_token(test_user: User, db: Session):
    """Create access and refresh tokens for test user."""
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
def cleanup_database(db: Session):
    """Clean up the database before each test."""
    # Delete all data from tables in reverse order of dependencies
    db.execute(text("DELETE FROM oauth_accounts"))
    db.execute(text("DELETE FROM tokens"))
    db.execute(text("DELETE FROM users"))
    db.commit()

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
    # First register a new user with a different email
    new_user_dict = test_user_dict.copy()
    new_user_dict["email"] = "newuser@example.com"
    response = client.post("/api/v1/auth/register", json=new_user_dict)
    assert response.status_code == 200
    
    # Now try to register with the same email as test_user
    duplicate_user_dict = test_user_dict.copy()
    duplicate_user_dict["email"] = test_user.email  # Use the email from the test_user fixture
    response = client.post("/api/v1/auth/register", json=duplicate_user_dict)
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]

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
    
    # Schema validation will return 422
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("password" in str(error["loc"]) for error in data["detail"])

def test_register_user_password_mismatch(client):
    """Test registration with mismatched passwords."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "DifferentPassword123!"  # Mismatched password
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    # Schema validation will return 422
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("confirm_password" in str(error["loc"]) for error in data["detail"])

# Email Verification Tests
def test_verify_email(client, test_user: User, db: Session):
    # First, ensure the user's email is not verified
    test_user.is_email_verified = False
    db.add(test_user)
    db.commit()
    db.refresh(test_user)

    # Create verification token
    token_value = "test_verification_token"
    token = user_crud.create_verification_token(
        db=db,
        user_id=test_user.id,
        token=token_value,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_delta=timedelta(hours=24)
    )

    # Ensure the user is not verified initially
    assert not test_user.is_email_verified

    # Verify the email
    response = client.post(
        f"/api/v1/auth/verify-email?token={token_value}"
    )
    if response.status_code != 200:
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.content}")
    assert response.status_code == 200
    
    # Check that the response contains the user data
    data = response.json()
    assert data["email"] == test_user.email
    assert data["is_email_verified"] is True
    
    # Verify that the user's email is marked as verified in the database
    db.refresh(test_user)
    assert test_user.is_email_verified is True

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
        f"/api/v1/auth/forgot-password?email={test_user_dict['email']}"
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
        f"/api/v1/auth/reset-password?token=reset_token&new_password=NewTest123!@#"
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

@pytest.fixture
def test_user_with_mfa(test_user: User, db: Session):
    """Create a test user with MFA enabled."""
    # Enable MFA for the test user
    user = user_crud.enable_mfa(db, user=test_user)
    return user

def test_verify_mfa(client, test_user_token: dict, test_user_with_mfa: User):
    # Generate a valid MFA code using the user's MFA secret
    totp = pyotp.TOTP(test_user_with_mfa.mfa_secret)
    valid_code = totp.now()
    
    response = client.post(
        "/api/v1/auth/mfa/verify",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"code": valid_code}
    )
    assert response.status_code == 200

def test_disable_mfa(client, test_user_token: dict, test_user_with_mfa: User):
    response = client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        json={"password": test_user_dict["password"]}
    )
    assert response.status_code == 200

# OAuth Tests
def test_oauth_login(client: TestClient):
    """Test OAuth login endpoint."""
    response = client.get(
        "/api/v1/auth/oauth/google/login",
        params={
            "redirect_uri": "http://localhost:3000/oauth/callback"
        },
        allow_redirects=False
    )
    assert response.status_code == 307  # Temporary redirect
    assert "accounts.google.com" in response.headers["location"]

@pytest.mark.asyncio
async def test_oauth_callback_google(client, monkeypatch):
    """Test Google OAuth callback."""
    # Generate state token
    state = secrets.token_urlsafe(32)

    # Mock exchange_code_for_token
    async def mock_exchange_code_for_token(provider, code, redirect_uri):
        assert provider == OAuthProvider.GOOGLE
        assert code == "test_code"
        assert redirect_uri == "http://localhost:3000/oauth/callback"
        return {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600
        }

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.exchange_code_for_token",
        mock_exchange_code_for_token
    )

    # Mock get_user_info
    async def mock_get_user_info(provider, access_token):
        assert provider == OAuthProvider.GOOGLE
        assert access_token == "test_access_token"
        return OAuthUserInfo(
            provider=provider,
            account_id="google123",
            email="test@example.com",
            first_name="Test",
            last_name="User",
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.get_user_info",
        mock_get_user_info
    )

    # Mock token_crud.get_oauth_state_token to return a token matching the state
    def mock_get_oauth_state_token(db, token):
        if token == state:  # Only return a token if the state matches
            return OAuthStateToken(
                id=str(uuid4()),
                token_type=TokenType.OAUTH_STATE,
                token=state,  # Use the same state token
                user_id=None,
                expires_at=datetime.utcnow() + timedelta(minutes=10),
                created_at=datetime.utcnow(),
                is_revoked=False,
                provider=OAuthProvider.GOOGLE,
                redirect_uri="http://localhost:3000/oauth/callback"
            )
        return None

    monkeypatch.setattr(
        "app.crud.token.get_oauth_state_token",
        mock_get_oauth_state_token
    )

    # Mock oauth_crud.get_by_provider_and_account_id
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.get_by_provider_and_account_id",
        lambda db, provider, account_id: None
    )

    # Mock user_crud.create
    def mock_create_user(*args, **kwargs):
        return User(
            id=str(uuid4()),
            email="test@example.com",
            first_name="Test",
            last_name="User",
            is_active=True,
            is_superuser=False,
            is_email_verified=True
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.user_crud.create",
        mock_create_user
    )

    # Mock oauth_crud.create
    def mock_create_oauth_account(*args, **kwargs):
        return OAuthAccount(
            id=str(uuid4()),
            user_id=str(uuid4()),
            provider=OAuthProvider.GOOGLE,
            account_id="google123",
            account_email="test@example.com",
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=None,
            is_active=True,
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.create",
        mock_create_oauth_account
    )

    # Mock token_crud.create_refresh_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.create_refresh_token",
        lambda db, user_id, token, expires_delta: None
    )

    # Mock token_crud.revoke_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.revoke_token",
        lambda db, token: True
    )

    # Mock create_access_token and create_refresh_token
    def mock_create_access_token(*args, **kwargs):
        return "test_access_token"

    def mock_create_refresh_token(*args, **kwargs):
        return "test_refresh_token"

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_access_token",
        mock_create_access_token
    )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_refresh_token",
        mock_create_refresh_token
    )

    response = client.get(
        "/api/v1/auth/oauth/callback/google",
        params={
            "code": "test_code",
            "state": state,
            "redirect_uri": "http://localhost:3000/oauth/callback"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "test_access_token"
    assert data["refresh_token"] == "test_refresh_token"
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_oauth_callback_facebook(client, monkeypatch):
    """Test Facebook OAuth callback."""
    # Generate state token
    state = secrets.token_urlsafe(32)

    # Mock exchange_code_for_token
    async def mock_exchange_code_for_token(provider, code, redirect_uri):
        assert provider == OAuthProvider.FACEBOOK
        assert code == "test_code"
        assert redirect_uri == "http://localhost:3000/oauth/callback"
        return {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600
        }

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.exchange_code_for_token",
        mock_exchange_code_for_token
    )

    # Mock get_user_info
    async def mock_get_user_info(provider, access_token):
        assert provider == OAuthProvider.FACEBOOK
        assert access_token == "test_access_token"
        return OAuthUserInfo(
            provider=provider,
            account_id="facebook123",
            email="test@example.com",
            first_name="Test",
            last_name="User",
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.get_user_info",
        mock_get_user_info
    )

    # Mock token_crud.get_oauth_state_token to return a token matching the state
    def mock_get_oauth_state_token(db, token):
        if token == state:  # Only return a token if the state matches
            return OAuthStateToken(
                id=str(uuid4()),
                token_type=TokenType.OAUTH_STATE,
                token=state,  # Use the same state token
                user_id=None,
                expires_at=datetime.utcnow() + timedelta(minutes=10),
                created_at=datetime.utcnow(),
                is_revoked=False,
                provider=OAuthProvider.FACEBOOK,
                redirect_uri="http://localhost:3000/oauth/callback"
            )
        return None

    monkeypatch.setattr(
        "app.crud.token.get_oauth_state_token",
        mock_get_oauth_state_token
    )

    # Mock oauth_crud.get_by_provider_and_account_id
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.get_by_provider_and_account_id",
        lambda db, provider, account_id: None
    )

    # Mock user_crud.create
    def mock_create_user(*args, **kwargs):
        return User(
            id=str(uuid4()),
            email="test@example.com",
            first_name="Test",
            last_name="User",
            is_active=True,
            is_superuser=False,
            is_email_verified=True
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.user_crud.create",
        mock_create_user
    )

    # Mock oauth_crud.create
    def mock_create_oauth_account(*args, **kwargs):
        return OAuthAccount(
            id=str(uuid4()),
            user_id=str(uuid4()),
            provider=OAuthProvider.FACEBOOK,
            account_id="facebook123",
            account_email="test@example.com",
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=None,
            is_active=True,
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.create",
        mock_create_oauth_account
    )

    # Mock token_crud.create_refresh_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.create_refresh_token",
        lambda db, user_id, token, expires_delta: None
    )

    # Mock token_crud.revoke_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.revoke_token",
        lambda db, token: True
    )

    # Mock create_access_token and create_refresh_token
    def mock_create_access_token(*args, **kwargs):
        return "test_access_token"

    def mock_create_refresh_token(*args, **kwargs):
        return "test_refresh_token"

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_access_token",
        mock_create_access_token
    )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_refresh_token",
        mock_create_refresh_token
    )

    response = client.get(
        "/api/v1/auth/oauth/callback/facebook",
        params={
            "code": "test_code",
            "state": state,
            "redirect_uri": "http://localhost:3000/oauth/callback"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "test_access_token"
    assert data["refresh_token"] == "test_refresh_token"
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_oauth_callback_github(client, monkeypatch):
    """Test GitHub OAuth callback."""
    # Generate state token
    state = secrets.token_urlsafe(32)

    # Mock exchange_code_for_token
    async def mock_exchange_code_for_token(provider, code, redirect_uri):
        assert provider == OAuthProvider.GITHUB
        assert code == "test_code"
        assert redirect_uri == "http://localhost:3000/oauth/callback"
        return {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600
        }

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.exchange_code_for_token",
        mock_exchange_code_for_token
    )

    # Mock get_user_info
    async def mock_get_user_info(provider, access_token):
        assert provider == OAuthProvider.GITHUB
        assert access_token == "test_access_token"
        return OAuthUserInfo(
            provider=provider,
            account_id="github123",
            email="test@example.com",
            first_name="Test",
            last_name="User",
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.get_user_info",
        mock_get_user_info
    )

    # Mock token_crud.get_oauth_state_token to return a token matching the state
    def mock_get_oauth_state_token(db, token):
        if token == state:  # Only return a token if the state matches
            return OAuthStateToken(
                id=str(uuid4()),
                token_type=TokenType.OAUTH_STATE,
                token=state,  # Use the same state token
                user_id=None,
                expires_at=datetime.utcnow() + timedelta(minutes=10),
                created_at=datetime.utcnow(),
                is_revoked=False,
                provider=OAuthProvider.GITHUB,
                redirect_uri="http://localhost:3000/oauth/callback"
            )
        return None

    monkeypatch.setattr(
        "app.crud.token.get_oauth_state_token",
        mock_get_oauth_state_token
    )

    # Mock oauth_crud.get_by_provider_and_account_id
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.get_by_provider_and_account_id",
        lambda db, provider, account_id: None
    )

    # Mock user_crud.create
    def mock_create_user(*args, **kwargs):
        return User(
            id=str(uuid4()),
            email="test@example.com",
            first_name="Test",
            last_name="User",
            is_active=True,
            is_superuser=False,
            is_email_verified=True
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.user_crud.create",
        mock_create_user
    )

    # Mock oauth_crud.create
    def mock_create_oauth_account(*args, **kwargs):
        return OAuthAccount(
            id=str(uuid4()),
            user_id=str(uuid4()),
            provider=OAuthProvider.GITHUB,
            account_id="github123",
            account_email="test@example.com",
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=None,
            is_active=True,
            raw_data={}
        )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.oauth_crud.create",
        mock_create_oauth_account
    )

    # Mock token_crud.create_refresh_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.create_refresh_token",
        lambda db, user_id, token, expires_delta: None
    )

    # Mock token_crud.revoke_token
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.token_crud.revoke_token",
        lambda db, token: True
    )

    # Mock create_access_token and create_refresh_token
    def mock_create_access_token(*args, **kwargs):
        return "test_access_token"

    def mock_create_refresh_token(*args, **kwargs):
        return "test_refresh_token"

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_access_token",
        mock_create_access_token
    )

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.auth.create_refresh_token",
        mock_create_refresh_token
    )

    response = client.get(
        "/api/v1/auth/oauth/callback/github",
        params={
            "code": "test_code",
            "state": state,
            "redirect_uri": "http://localhost:3000/oauth/callback"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "test_access_token"
    assert data["refresh_token"] == "test_refresh_token"
    assert data["token_type"] == "bearer"

def test_oauth_account_crud(
    client: TestClient,
    test_user: User,
    test_user_token: dict
):
    """Test OAuth account CRUD operations."""
    # Create an OAuth account
    db = SessionLocal()
    try:
        # Create a new user for testing OAuth accounts
        new_user = User(
            id=str(uuid.uuid4()),
            email="oauth_test@example.com",
            hashed_password=get_password_hash("Test123!@#"),
            first_name="OAuth",
            last_name="Test",
            is_active=True,
            is_superuser=False,
            is_email_verified=True,  # Make sure the user is verified
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Create access token for the new user
        access_token = create_access_token(
            subject=new_user.id,
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Store access token in database
        db_access_token = AccessToken(
            id=str(uuid.uuid4()),
            user_id=new_user.id,
            token=access_token,
            token_type=TokenType.ACCESS,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            created_at=datetime.utcnow(),
            is_revoked=False
        )
        db.add(db_access_token)
        db.commit()

        print(f"New user ID: {new_user.id}")
        print(f"Access token: {access_token}")

        # Create OAuth account using CRUD module
        oauth_account = oauth_crud.create(
            db,
            obj_in=OAuthAccountCreate(
                user_id=new_user.id,  # Use the new user's ID
                provider=OAuthProvider.GOOGLE,
                account_id="test_provider_user_id",
                account_email="test@example.com",
                access_token="test_access_token",
                refresh_token="test_refresh_token",
                expires_at=datetime.utcnow() + timedelta(hours=1),
                is_active=True,
                raw_data={
                    "sub": "test_provider_user_id",
                    "email": "test@example.com",
                    "given_name": "Test",
                    "family_name": "User"
                }
            )
        )
        print(f"Created OAuth account: {oauth_account.id}")

        # Verify OAuth account was created
        oauth_accounts = oauth_crud.get_by_user_id(db=db, user_id=new_user.id)
        print(f"Found {len(oauth_accounts)} OAuth accounts for user")
        for account in oauth_accounts:
            print(f"  - {account.id} ({account.provider})")

        # Override the get_db dependency to use our test session
        def override_get_db():
            try:
                yield db
            finally:
                pass  # Don't close the session here

        app.dependency_overrides[get_db] = override_get_db

        # Get OAuth accounts using the new user's token
        response = client.get(
            "/api/v1/users/me/oauth-accounts",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0
        assert data[0]["provider"] == "google"
        assert data[0]["account_email"] == "test@example.com"

        # Clean up
        db.query(Token).filter(Token.user_id == new_user.id).delete()
        db.delete(oauth_account)
        db.delete(new_user)
        db.commit()

        # Remove the dependency override
        app.dependency_overrides = {}
    finally:
        db.close()

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

def test_delete_oauth_account(client, test_user, test_user_token, db):
    """Test deleting an OAuth account."""
    oauth_account = OAuthAccount(
        id=str(uuid4()),
        user_id=test_user.id,
        provider=OAuthProvider.GOOGLE,
        account_id="test_provider_user_id",
        account_email="test@example.com",
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        expires_at=datetime.utcnow() + timedelta(hours=1),
        is_active=True,
        raw_data={}
    )
    db.add(oauth_account)
    db.commit()
    db.refresh(oauth_account)

    try:
        response = client.delete(
            "/api/v1/users/me/oauth-accounts/google",
            headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "OAuth account deleted successfully"
    finally:
        # Clean up
        db.query(OAuthAccount).filter(OAuthAccount.user_id == test_user.id).delete()
        db.commit()

def test_delete_account(client, test_user_token: dict):
    """Test deleting user account."""
    response = client.delete(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"},
        params={"password": test_user_dict["password"]}  # Use the password from test_user_dict
    )
    assert response.status_code == 204

def test_oauth_google_login(client):
    """Test Google OAuth login endpoint."""
    response = client.get(
        "/api/v1/auth/oauth/google/login",
        params={
            "redirect_uri": "http://localhost:3000/oauth/callback",
            "state": "test_state"
        },
        allow_redirects=False
    )
    assert response.status_code == 307  # Temporary redirect
    assert "accounts.google.com" in response.headers["location"]

def test_oauth_facebook_login(client):
    """Test Facebook OAuth login endpoint."""
    response = client.get(
        "/api/v1/auth/oauth/facebook/login",
        params={
            "redirect_uri": "http://localhost:3000/oauth/callback",
            "state": "test_state"
        },
        allow_redirects=False
    )
    assert response.status_code == 307  # Temporary redirect
    assert "facebook.com" in response.headers["location"]

def test_oauth_github_login(client):
    """Test GitHub OAuth login endpoint."""
    response = client.get(
        "/api/v1/auth/oauth/github/login",
        params={
            "redirect_uri": "http://localhost:3000/oauth/callback",
            "state": "test_state"
        },
        allow_redirects=False
    )
    assert response.status_code == 307  # Temporary redirect
    assert "github.com" in response.headers["location"]

def test_get_oauth_accounts(client, test_user, test_user_token):
    """Test getting OAuth accounts for the current user."""
    response = client.get(
        "/api/v1/users/me/oauth-accounts",
        headers={"Authorization": f"Bearer {test_user_token['access_token']}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

@pytest.fixture
def test_oauth_state():
    """Create a test OAuth state."""
    return secrets.token_urlsafe(32)

@pytest.fixture
def test_oauth_token_data():
    """Create test OAuth token data."""
    return {
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "expires_in": 3600,
        "token_type": "bearer"
    }

@pytest.fixture
def test_oauth_user_info():
    """Create test OAuth user info."""
    return OAuthUserInfo(
        provider=OAuthProvider.GOOGLE,
        account_id="test_provider_user_id",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        raw_data={
            "sub": "test_provider_user_id",
            "email": "test@example.com",
            "given_name": "Test",
            "family_name": "User"
        }
    )

@pytest.fixture
def test_oauth_account(db: Session, test_user: User):
    """Create a test OAuth account."""
    oauth_account = OAuthAccount(
        id=str(uuid4()),
        user_id=test_user.id,
        provider=OAuthProvider.GOOGLE,
        account_id="test_provider_user_id",
        account_email="test@example.com",
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        expires_at=datetime.utcnow() + timedelta(hours=1),
        is_active=True,
        raw_data={
            "sub": "test_provider_user_id",
            "email": "test@example.com",
            "given_name": "Test",
            "family_name": "User"
        }
    )
    db.add(oauth_account)
    db.commit()
    db.refresh(oauth_account)
    return oauth_account

@pytest.fixture
def test_token(test_user: User):
    """Create a test access token."""
    return create_access_token(
        subject=test_user.id,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )