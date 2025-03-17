import json
import pytest
from fastapi import status
from unittest.mock import patch

from app.models.user import User
from app.models.token import Token
from app.models.oauth_account import OAuthProvider


def test_get_me(client, verified_test_user, test_auth_headers):
    """Test getting the current user's profile."""
    response = client.get(
        "/api/v1/users/me",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == verified_test_user.email
    assert data["first_name"] == verified_test_user.first_name
    assert data["last_name"] == verified_test_user.last_name
    assert "password" not in data
    assert "password_hash" not in data


def test_update_me(client, verified_test_user, test_auth_headers):
    """Test updating the current user's profile."""
    # Prepare update data
    update_data = {
        "first_name": "Updated",
        "last_name": "User",
        "mobile": "+8801712345678",
    }
    
    response = client.put(
        "/api/v1/users/me",
        json=update_data,
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["first_name"] == update_data["first_name"]
    assert data["last_name"] == update_data["last_name"]
    assert data["mobile"] == update_data["mobile"]
    assert data["email"] == verified_test_user.email  # Email shouldn't change


def test_get_oauth_accounts(client, db_session, verified_test_user, test_auth_headers):
    """Test getting the current user's OAuth accounts."""
    # Create an OAuth account for the test user
    from app import crud
    oauth_account = crud.oauth_account.create(
        db=db_session,
        user_id=verified_test_user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="12345",
    )
    
    response = client.get(
        "/api/v1/users/me/oauth-accounts",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert len(data) == 1
    assert data[0]["provider"] == OAuthProvider.GOOGLE.value
    assert data[0]["provider_user_id"] == "12345"


def test_delete_oauth_account(client, db_session, verified_test_user, test_auth_headers):
    """Test deleting an OAuth account."""
    # Create an OAuth account for the test user
    from app import crud
    oauth_account = crud.oauth_account.create(
        db=db_session,
        user_id=verified_test_user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="12345",
    )
    
    response = client.delete(
        f"/api/v1/users/me/oauth-accounts/{OAuthProvider.GOOGLE.value}",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_204_NO_CONTENT
    
    # Verify that the OAuth account was deleted
    oauth_accounts = crud.oauth_account.get_by_user_id(db_session, user_id=verified_test_user.id)
    assert len(oauth_accounts) == 0


def test_delete_nonexistent_oauth_account(client, verified_test_user, test_auth_headers):
    """Test deleting a nonexistent OAuth account."""
    response = client.delete(
        f"/api/v1/users/me/oauth-accounts/{OAuthProvider.GOOGLE.value}",
        headers=test_auth_headers,
    )
    
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_read_current_user(client, test_user, test_auth_headers):
    """Test retrieving the current user's information."""
    response = client.get("/api/v1/users/me", headers=test_auth_headers)
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["email"] == test_user.email
    assert data["first_name"] == test_user.first_name
    assert data["last_name"] == test_user.last_name


def test_update_current_user(client, db_session, test_user, test_auth_headers):
    """Test updating the current user's information."""
    update_data = {
        "first_name": "Updated",
        "last_name": "User",
    }
    
    response = client.put(
        "/api/v1/users/me",
        headers=test_auth_headers,
        json=update_data,
    )
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["first_name"] == "Updated"
    assert data["last_name"] == "User"
    
    # Verify the changes in the database
    user = db_session.query(User).filter(User.id == test_user.id).first()
    assert user.first_name == "Updated"
    assert user.last_name == "User"


def test_read_oauth_accounts_empty(client, test_user, test_auth_headers):
    """Test retrieving the current user's OAuth accounts when there are none."""
    response = client.get(
        "/api/v1/users/me/oauth-accounts",
        headers=test_auth_headers,
    )
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_delete_account(client, db_session, test_user, test_auth_headers):
    """Test deleting the current user's account."""
    # First, create some tokens for the user
    from datetime import datetime, timedelta
    from app.models.token import Token, TokenType
    from uuid import uuid4
    
    # Access token
    access_token = Token(
        id=uuid4(),
        user_id=test_user.id,
        token_hash="test_access_token",
        type=TokenType.ACCESS,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    # Refresh token
    refresh_token = Token(
        id=uuid4(),
        user_id=test_user.id,
        token_hash="test_refresh_token",
        type=TokenType.REFRESH,
        expires_at=datetime.utcnow() + timedelta(days=7),
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db_session.add(access_token)
    db_session.add(refresh_token)
    db_session.commit()
    
    # Now delete the account
    response = client.delete(
        "/api/v1/users/me",
        headers=test_auth_headers,
        json={"password": "testpassword"},
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    
    # Verify the user has been deleted
    user = db_session.query(User).filter(User.id == test_user.id).first()
    assert user is None
    
    # Verify the tokens have been deleted
    tokens = db_session.query(Token).filter(Token.user_id == test_user.id).all()
    assert len(tokens) == 0


def test_delete_account_wrong_password(client, db_session, test_user, test_auth_headers):
    """Test attempting to delete the account with an incorrect password."""
    response = client.delete(
        "/api/v1/users/me",
        headers=test_auth_headers,
        json={"password": "wrongpassword"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    # Verify the user still exists
    user = db_session.query(User).filter(User.id == test_user.id).first()
    assert user is not None 