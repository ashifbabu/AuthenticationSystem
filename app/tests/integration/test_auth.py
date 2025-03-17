import json
import pytest
from fastapi import status
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4

from app.core.config import settings
from app.models.user import User
from app.models.token import Token, TokenType


@pytest.fixture
def test_auth_headers(client, verified_test_user):
    """Get auth headers for a test user."""
    login_response = client.post(
        f"/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    
    tokens = login_response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_register_user(client, db_session):
    """Test user registration endpoint."""
    # Prepare test user data
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1990-01-01",
        "gender": "male",
        "email": "john.doe@example.com",
        "mobile": "+8801700000001",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    
    # Mock email sending
    with patch("app.services.email.send_verification_email", return_value=True) as mock_send_email:
        response = client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        # Check if the email sending function was called
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["first_name"] == user_data["first_name"]
    assert data["last_name"] == user_data["last_name"]
    assert "password" not in data  # Ensure password is not in response
    assert "password_hash" not in data  # Ensure password hash is not in response
    assert data["is_email_verified"] is False  # Email should not be verified yet


def test_register_user_duplicate_email(client, test_user):
    """Test that registering with a duplicate email returns an error."""
    # Prepare test user data with the same email as an existing user
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1990-01-01",
        "gender": "male",
        "email": test_user.email,  # Use an email that already exists
        "mobile": "+8801700000001", 
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    
    response = client.post(
        "/api/v1/auth/register",
        json=user_data
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in response.json()["detail"].lower()


def test_verify_email(client, db_session, test_user):
    """Test email verification endpoint."""
    # Create a verification token for the test user
    token_value = "test-verification-token"
    
    # Create a token in the database
    db_token = Token(
        id=str(uuid4()),
        user_id=test_user.id,
        token=token_value,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        is_revoked=False,
        created_at=datetime.utcnow()
    )
    db_session.add(db_token)
    db_session.commit()
    
    # Verify the email
    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": token_value}
    )
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == test_user.email
    assert data["is_email_verified"] is True
    
    # Check that the user's email is marked as verified in the database
    db_session.refresh(test_user)
    assert test_user.is_email_verified is True


def test_verify_email_invalid_token(client):
    """Test that verifying with an invalid token returns an error."""
    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": "invalid-token"}
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired token" in response.json()["detail"].lower()


def test_login_success(client, verified_test_user):
    """Test successful login."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"}
    )
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_credentials(client, verified_test_user):
    """Test login with invalid credentials."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "wrongpassword"}
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect email or password" in response.json()["detail"].lower()


def test_login_unverified_user(client, test_user):
    """Test login with an unverified user."""
    # Ensure the user is not verified
    test_user.is_email_verified = False
    
    response = client.post(
        "/api/v1/auth/login",
        data={"username": test_user.email, "password": "testpassword"}
    )
    
    # Should authenticate but mark as inactive
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "inactive user" in response.json()["detail"].lower()


def test_refresh_token(client, verified_test_user):
    """Test refreshing the access token."""
    # First, login to get tokens
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"}
    )
    
    tokens = login_response.json()
    refresh_token = tokens["refresh_token"]
    
    # Use the refresh token to get a new access token
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert "access_token" in data
    assert data["refresh_token"] == refresh_token  # Refresh token should remain the same
    assert data["token_type"] == "bearer"


def test_logout(client, verified_test_user):
    """Test logout endpoint."""
    # First, login to get tokens
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"}
    )
    
    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    
    # Logout
    response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    # Check response status code
    assert response.status_code == status.HTTP_204_NO_CONTENT
    
    # Try to use the refresh token after logout
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    
    # Should be rejected as the token is revoked
    assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
