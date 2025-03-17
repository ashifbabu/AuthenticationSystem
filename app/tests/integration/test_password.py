import json
import pytest
from fastapi import status
from unittest.mock import patch, MagicMock

from app.models.user import User
from app.models.token import Token, TokenType
from app.core.security import verify_password
from datetime import datetime, timedelta
from uuid import uuid4
from app.core.config import settings


def test_forgot_password(client, db_session, test_user):
    """Test the forgot password endpoint."""
    # Mock the send_password_reset_email function to prevent actual email sending
    with patch('app.services.email.send_password_reset_email') as mock_send_email:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email},
        )
        
        # Should return 204 No Content
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify email was attempted to be sent
        mock_send_email.assert_called_once()
        
        # Verify token was created in the database
        token = db_session.query(Token).filter(
            Token.user_id == test_user.id,
            Token.type == TokenType.PASSWORD_RESET,
            Token.is_used == False,
        ).first()
        
        assert token is not None


def test_forgot_password_nonexistent_email(client, db_session):
    """Test the forgot password endpoint with a nonexistent email."""
    with patch('app.services.email.send_password_reset_email') as mock_send_email:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
        )
        
        # Should still return 204 for security reasons (to not leak email existence)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify email was NOT attempted to be sent
        mock_send_email.assert_not_called()


def test_reset_password_valid_token(client, db_session, test_user):
    """Test resetting password with a valid token."""
    # Create a valid password reset token
    token_value = "valid_reset_token"
    reset_token = Token(
        id=uuid4(),
        user_id=test_user.id,
        token_hash=token_value,  # In a real app, this would be hashed
        type=TokenType.PASSWORD_RESET,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db_session.add(reset_token)
    db_session.commit()
    
    # Use the token to reset the password
    new_password = "NewPassword123!"
    response = client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": token_value,
            "new_password": new_password,
        },
    )
    
    # Should return 200 and new tokens
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    
    # Verify token was marked as used
    db_session.refresh(reset_token)
    assert reset_token.is_used
    
    # Verify password was updated
    db_session.refresh(test_user)
    assert verify_password(new_password, test_user.password_hash)


def test_reset_password_invalid_token(client):
    """Test resetting password with an invalid token."""
    response = client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "invalid_token",
            "new_password": "NewPassword123!",
        },
    )
    
    # Should return 400 Bad Request
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    

def test_reset_password_invalid_password_format(client, db_session, test_user):
    """Test resetting password with an invalid password format."""
    # Create a valid password reset token
    token_value = "valid_reset_token2"
    reset_token = Token(
        id=uuid4(),
        user_id=test_user.id,
        token_hash=token_value,
        type=TokenType.PASSWORD_RESET,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db_session.add(reset_token)
    db_session.commit()
    
    # Attempt to reset with weak password
    response = client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": token_value,
            "new_password": "weak",
        },
    )
    
    # Should return 422 Unprocessable Entity (validation error)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_change_password(client, db_session, test_user, test_auth_headers):
    """Test changing password for an authenticated user."""
    current_password = "testpassword"  # From test_user fixture
    new_password = "NewPassword456!"
    
    response = client.put(
        "/api/v1/auth/change-password",
        headers=test_auth_headers,
        json={
            "current_password": current_password,
            "new_password": new_password,
        },
    )
    
    # Should return 200 and new tokens
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Verify password was updated
    db_session.refresh(test_user)
    assert verify_password(new_password, test_user.password_hash)


def test_change_password_incorrect_current(client, test_auth_headers):
    """Test changing password with incorrect current password."""
    response = client.put(
        "/api/v1/auth/change-password",
        headers=test_auth_headers,
        json={
            "current_password": "wrong_password",
            "new_password": "NewPassword789!",
        },
    )
    
    # Should return 401 Unauthorized
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_change_password(client, verified_test_user, test_auth_headers):
    """Test changing a user's password."""
    # Prepare data for password change
    password_data = {
        "current_password": "testpassword",
        "new_password": "NewPassword123!"
    }
    
    # Mock email sending
    with patch("app.services.email.send_security_notification_email") as mock_send_email:
        response = client.put(
            "/api/v1/auth/change-password",
            json=password_data,
            headers=test_auth_headers
        )
        
        # Check if the notification email was sent
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Try to login with the new password
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "NewPassword123!"}
    )
    
    assert login_response.status_code == status.HTTP_200_OK
    
    # Try to login with the old password (should fail)
    old_login_response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"}
    )
    
    assert old_login_response.status_code == status.HTTP_401_UNAUTHORIZED


def test_change_password_incorrect_current(client, verified_test_user, test_auth_headers):
    """Test that changing password fails if the current password is incorrect."""
    # Prepare data with incorrect current password
    password_data = {
        "current_password": "wrongpassword",
        "new_password": "NewPassword123!"
    }
    
    response = client.put(
        "/api/v1/auth/change-password",
        json=password_data,
        headers=test_auth_headers
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect password" in response.json()["detail"].lower()


def test_forgot_password(client, verified_test_user):
    """Test initiating the password reset process."""
    # Prepare data for password reset request
    reset_data = {
        "email": verified_test_user.email
    }
    
    # Mock email sending
    with patch("app.services.email.send_password_reset_email") as mock_send_email:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json=reset_data
        )
        
        # Check if the password reset email was sent
        assert mock_send_email.called
    
    # Check response status code
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_forgot_password_nonexistent_email(client):
    """Test that forgot password still returns success for nonexistent emails (for security)."""
    reset_data = {
        "email": "nonexistent@example.com"
    }
    
    response = client.post(
        "/api/v1/auth/forgot-password",
        json=reset_data
    )
    
    # Should still return 204 for security
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_reset_password(client, db_session, verified_test_user):
    """Test resetting a password with a valid token."""
    # Create a password reset token for the test user
    token_value = "test-reset-token"
    
    # Create a token in the database
    db_token = Token(
        id=str(uuid4()),
        user_id=verified_test_user.id,
        token=token_value,
        token_type=TokenType.PASSWORD_RESET,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        is_revoked=False,
        created_at=datetime.utcnow()
    )
    db_session.add(db_token)
    db_session.commit()
    
    # Prepare data for password reset
    reset_data = {
        "token": token_value,
        "new_password": "NewPassword123!"
    }
    
    # Mock email sending
    with patch("app.services.email.send_security_notification_email") as mock_send_email:
        response = client.post(
            "/api/v1/auth/reset-password",
            json=reset_data
        )
        
        # Check if the notification email was sent
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Try to login with the new password
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "NewPassword123!"}
    )
    
    assert login_response.status_code == status.HTTP_200_OK


def test_reset_password_invalid_token(client):
    """Test that resetting with an invalid token returns an error."""
    reset_data = {
        "token": "invalid-token",
        "new_password": "NewPassword123!"
    }
    
    response = client.post(
        "/api/v1/auth/reset-password",
        json=reset_data
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired token" in response.json()["detail"].lower()


def test_reset_password_expired_token(client, db_session, verified_test_user):
    """Test that resetting with an expired token returns an error."""
    # Create an expired password reset token for the test user
    token_value = "test-expired-token"
    
    # Create an expired token in the database
    db_token = Token(
        id=str(uuid4()),
        user_id=verified_test_user.id,
        token=token_value,
        token_type=TokenType.PASSWORD_RESET,
        expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        is_revoked=False,
        created_at=datetime.utcnow() - timedelta(hours=25)
    )
    db_session.add(db_token)
    db_session.commit()
    
    reset_data = {
        "token": token_value,
        "new_password": "NewPassword123!"
    }
    
    response = client.post(
        "/api/v1/auth/reset-password",
        json=reset_data
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired token" in response.json()["detail"].lower() 