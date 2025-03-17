import json
import pytest
from fastapi import status
from unittest.mock import patch, MagicMock

from app.models.user import User
from app.models.login_attempt import LoginAttempt
from datetime import datetime, timedelta
from uuid import uuid4


def test_failed_login_creates_login_attempt(client, db_session):
    """Test that a failed login creates a login attempt record."""
    # Attempt to login with non-existent credentials
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistent@example.com", "password": "wrongpassword"},
    )
    
    # Verify login attempt record was created
    login_attempts = db_session.query(LoginAttempt).filter(
        LoginAttempt.email == "nonexistent@example.com"
    ).all()
    
    assert len(login_attempts) == 1
    assert login_attempts[0].success == False


def test_successful_login_creates_login_attempt(client, db_session, verified_test_user):
    """Test that a successful login creates a login attempt record."""
    # Login with valid credentials
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    
    # Verify login attempt record was created
    login_attempts = db_session.query(LoginAttempt).filter(
        LoginAttempt.email == verified_test_user.email,
        LoginAttempt.success == True,
    ).all()
    
    assert len(login_attempts) >= 1


def test_account_lockout_after_max_attempts(client, db_session, verified_test_user, monkeypatch):
    """Test that an account gets locked after the maximum number of failed attempts."""
    from app.core.config import settings
    
    # Override settings for test
    monkeypatch.setattr(settings, "MAX_LOGIN_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 30)
    
    # Mock email sending
    with patch("app.services.email.send_security_notification_email") as mock_send_email:
        # Make failed login attempts up to the limit
        for i in range(settings.MAX_LOGIN_ATTEMPTS):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": verified_test_user.email, "password": "wrongpassword"},
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            
            # Verify the attempts left message
            data = response.json()
            if i < settings.MAX_LOGIN_ATTEMPTS - 1:
                assert f"{settings.MAX_LOGIN_ATTEMPTS - i - 1} attempts remaining" in data["detail"]
        
        # One more attempt should trigger lockout
        response = client.post(
            "/api/v1/auth/login",
            data={"username": verified_test_user.email, "password": "wrongpassword"},
        )
        
        # Check if the notification email was sent
        assert mock_send_email.called
    
    # Verify account is locked
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    data = response.json()
    assert "Account temporarily locked" in data["detail"]


def test_cant_login_when_account_locked(client, db_session, verified_test_user, monkeypatch):
    """Test that login is not possible when account is locked."""
    from app.core.config import settings
    
    # Override settings for test
    monkeypatch.setattr(settings, "MAX_LOGIN_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 30)
    
    # Create login attempt records to simulate account lockout
    for i in range(settings.MAX_LOGIN_ATTEMPTS):
        login_attempt = LoginAttempt(
            id=str(uuid4()),
            email=verified_test_user.email,
            ip_address="127.0.0.1",
            success=False,
            timestamp=datetime.utcnow(),
        )
        db_session.add(login_attempt)
    
    db_session.commit()
    
    # Try to login with correct credentials
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    
    # Should be locked out even with correct password
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    data = response.json()
    assert "Account temporarily locked" in data["detail"]


def test_check_account_status(client, db_session, verified_test_user, test_auth_headers, monkeypatch):
    """Test checking account lockout status."""
    from app.core.config import settings
    
    # Override settings for test
    monkeypatch.setattr(settings, "MAX_LOGIN_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 30)
    
    # Create a failed login attempt record
    login_attempt = LoginAttempt(
        id=str(uuid4()),
        email=verified_test_user.email,
        ip_address="127.0.0.1",
        success=False,
        timestamp=datetime.utcnow(),
    )
    db_session.add(login_attempt)
    db_session.commit()
    
    # Check account status
    response = client.get(
        f"/api/v1/auth/account-status/{verified_test_user.email}",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    assert data["recent_attempts"] >= 1
    assert data["recent_failed_attempts"] >= 1
    assert "is_locked" in data
    
    # Account should not be locked yet (only one failed attempt)
    assert data["is_locked"] is False


def test_check_account_status_when_locked(client, db_session, verified_test_user, test_auth_headers, monkeypatch):
    """Test checking account status when the account is locked."""
    from app.core.config import settings
    
    # Override settings for test
    monkeypatch.setattr(settings, "MAX_LOGIN_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 30)
    
    # Create login attempt records to simulate account lockout
    for i in range(settings.MAX_LOGIN_ATTEMPTS):
        login_attempt = LoginAttempt(
            id=str(uuid4()),
            email=verified_test_user.email,
            ip_address="127.0.0.1",
            success=False,
            timestamp=datetime.utcnow(),
        )
        db_session.add(login_attempt)
    
    db_session.commit()
    
    # Check account status
    response = client.get(
        f"/api/v1/auth/account-status/{verified_test_user.email}",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    assert data["recent_attempts"] >= settings.MAX_LOGIN_ATTEMPTS
    assert data["recent_failed_attempts"] >= settings.MAX_LOGIN_ATTEMPTS
    assert data["is_locked"] is True
    assert data["lockout_remaining"] is not None
    assert data["lockout_remaining"] <= settings.ACCOUNT_LOCKOUT_MINUTES


def test_unlock_account(client, db_session, verified_test_user, test_admin_headers, monkeypatch):
    """Test that an admin can unlock a locked account."""
    from app.core.config import settings
    
    # Override settings for test
    monkeypatch.setattr(settings, "MAX_LOGIN_ATTEMPTS", 3)
    
    # Create login attempt records to simulate account lockout
    for i in range(settings.MAX_LOGIN_ATTEMPTS):
        login_attempt = LoginAttempt(
            id=str(uuid4()),
            email=verified_test_user.email,
            ip_address="127.0.0.1",
            success=False,
            timestamp=datetime.utcnow(),
        )
        db_session.add(login_attempt)
    
    db_session.commit()
    
    # Verify account is locked
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    # Admin unlocks the account
    response = client.post(
        f"/api/v1/auth/unlock-account/{verified_test_user.email}",
        headers=test_admin_headers,
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    
    # Verify account is unlocked
    response = client.post(
        "/api/v1/auth/login",
        data={"username": verified_test_user.email, "password": "testpassword"},
    )
    assert response.status_code == status.HTTP_200_OK


def test_non_admin_cant_unlock_account(client, verified_test_user, test_auth_headers):
    """Test that a non-admin user cannot unlock accounts."""
    response = client.post(
        f"/api/v1/auth/unlock-account/{verified_test_user.email}",
        headers=test_auth_headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN 