import json
import pytest
from fastapi import status
from unittest.mock import patch, MagicMock

from app.models.user import User
from app.models.token import Token, TokenType
from datetime import datetime, timedelta
from uuid import uuid4


def test_enable_mfa(client, verified_test_user, test_auth_headers):
    """Test initiating MFA enablement process."""
    # Mock email sending
    with patch("app.services.email.send_mfa_code_email") as mock_send_email:
        response = client.post(
            "/api/v1/auth/mfa/enable",
            headers=test_auth_headers
        )
        
        # Check if the MFA code email was sent
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    assert "message" in response.json()
    assert "verification code" in response.json()["message"].lower()


def test_verify_mfa(client, db_session, verified_test_user, test_auth_headers):
    """Test verifying the MFA code and enabling MFA."""
    # Create an MFA token for the test user
    mfa_code = "123456"
    
    # Create a token in the database
    db_token = Token(
        id=str(uuid4()),
        user_id=verified_test_user.id,
        token=mfa_code,
        token_type=TokenType.MFA,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
        is_revoked=False,
        created_at=datetime.utcnow()
    )
    db_session.add(db_token)
    db_session.commit()
    
    # Mock email sending
    with patch("app.services.email.send_security_notification_email") as mock_send_email:
        response = client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": mfa_code},
            headers=test_auth_headers
        )
        
        # Check if the security notification email was sent
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == verified_test_user.email
    assert data["mfa_enabled"] is True
    
    # Check that MFA is enabled in the database
    db_session.refresh(verified_test_user)
    assert verified_test_user.mfa_enabled is True


def test_verify_mfa_invalid_code(client, verified_test_user, test_auth_headers):
    """Test that verifying with an invalid MFA code returns an error."""
    response = client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": "invalid-code"},
        headers=test_auth_headers
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired mfa code" in response.json()["detail"].lower()


def test_disable_mfa(client, db_session, verified_test_user, test_auth_headers):
    """Test disabling MFA."""
    # Enable MFA for the test user first
    verified_test_user.mfa_enabled = True
    db_session.commit()
    
    # Mock email sending
    with patch("app.services.email.send_security_notification_email") as mock_send_email:
        response = client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": "testpassword"},
            headers=test_auth_headers
        )
        
        # Check if the security notification email was sent
        assert mock_send_email.called
    
    # Check response status code and content
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == verified_test_user.email
    assert data["mfa_enabled"] is False
    
    # Check that MFA is disabled in the database
    db_session.refresh(verified_test_user)
    assert verified_test_user.mfa_enabled is False


def test_disable_mfa_incorrect_password(client, db_session, verified_test_user, test_auth_headers):
    """Test that disabling MFA fails if the password is incorrect."""
    # Enable MFA for the test user first
    verified_test_user.mfa_enabled = True
    db_session.commit()
    
    response = client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "wrongpassword"},
        headers=test_auth_headers
    )
    
    # Check response status code and error message
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect password" in response.json()["detail"].lower()
    
    # Check that MFA is still enabled in the database
    db_session.refresh(verified_test_user)
    assert verified_test_user.mfa_enabled is True 