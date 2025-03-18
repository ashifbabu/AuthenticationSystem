from unittest.mock import patch, MagicMock, AsyncMock
import json
import pytest
from fastapi import status
from datetime import datetime, timedelta

from app.schemas.oauth import OAuthProvider, OAuthUserInfo


@pytest.fixture
def mock_exchange_code_for_token():
    """Mock the exchange_code_for_token function."""
    with patch("app.services.oauth.exchange_code_for_token") as mock:
        mock.return_value = {"access_token": "mock_access_token"}
        yield mock


@pytest.fixture
def mock_get_user_info():
    """Mock the get_user_info function."""
    with patch("app.services.oauth.get_user_info") as mock:
        # Create a sample user info object
        user_info = OAuthUserInfo(
            provider=OAuthProvider.GOOGLE,
            provider_user_id="123456789",
            email="test.oauth@example.com",
            first_name="Test",
            last_name="OAuth",
            picture_url="https://example.com/picture.jpg",
            raw_data={},
        )
        mock.return_value = user_info
        yield mock


@pytest.fixture
def mock_oauth_response():
    """Mock response for OAuth provider."""
    return {
        "id": "12345",
        "email": "oauth.user@example.com",
        "given_name": "OAuth",
        "family_name": "User",
        "picture": "https://example.com/avatar.jpg",
    }


@pytest.mark.parametrize("provider", ["google", "facebook", "github", "linkedin", "twitter"])
def test_oauth_login_redirect(client, provider):
    """Test that OAuth login redirects to the provider's login page."""
    response = client.get(f"/api/v1/auth/oauth/{provider}")
    
    # Should redirect to provider's OAuth login page
    assert response.status_code == status.HTTP_302_FOUND
    
    # The Location header should contain the redirect URL
    assert "location" in response.headers
    provider_domains = {
        "google": "accounts.google.com",
        "facebook": "facebook.com",
        "github": "github.com",
        "linkedin": "linkedin.com",
        "twitter": "twitter.com",
    }
    assert provider_domains[provider] in response.headers["location"].lower()


@pytest.mark.parametrize("provider", ["google", "facebook", "github", "linkedin", "twitter"])
@pytest.mark.asyncio
async def test_oauth_callback_existing_user(client, db_session, verified_test_user, mock_oauth_response, provider):
    """Test OAuth callback with an existing user."""
    # Mock the exchange_code_for_token function
    with patch("app.api.endpoints.auth.exchange_code_for_token", new_callable=AsyncMock) as mock_exchange:
        mock_exchange.return_value = {"access_token": "mock_access_token"}
        
        # Mock the get_user_info function
        with patch("app.api.endpoints.auth.get_user_info", new_callable=AsyncMock) as mock_get_info:
            mock_get_info.return_value = {
                "provider": provider,
                "provider_user_id": mock_oauth_response["id"],
                "email": verified_test_user.email,  # Use existing user's email
                "full_name": f"{mock_oauth_response['given_name']} {mock_oauth_response['family_name']}",
                "picture_url": mock_oauth_response["picture"],
            }
            
            # Call the OAuth callback
            response = await client.get(
                "/api/v1/auth/oauth/callback",
                params={
                    "provider": provider,
                    "code": "test_auth_code",
                }
            )
            
            # Check response status and content
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            
            # Verify that a new OAuth account was created for the existing user
            from app import crud
            oauth_account = crud.oauth_account.get_by_provider_and_user(
                db_session,
                provider=provider,
                provider_user_id=mock_oauth_response["id"],
            )
            
            assert oauth_account is not None
            assert oauth_account.user_id == verified_test_user.id


@pytest.mark.parametrize("provider", ["google", "facebook", "github", "linkedin", "twitter"])
@pytest.mark.asyncio
async def test_oauth_callback_new_user(client, db_session, mock_oauth_response, provider):
    """Test OAuth callback with a new user."""
    # Use a different email than existing test users
    new_email = f"new.oauth.user.{provider}@example.com"
    
    # Mock the exchange_code_for_token function
    with patch("app.api.endpoints.auth.exchange_code_for_token", new_callable=AsyncMock) as mock_exchange:
        mock_exchange.return_value = {"access_token": "mock_access_token"}
        
        # Mock the get_user_info function
        with patch("app.api.endpoints.auth.get_user_info", new_callable=AsyncMock) as mock_get_info:
            mock_get_info.return_value = {
                "provider": provider,
                "provider_user_id": mock_oauth_response["id"],
                "email": new_email,
                "full_name": f"{mock_oauth_response['given_name']} {mock_oauth_response['family_name']}",
                "picture_url": mock_oauth_response["picture"],
            }
            
            # Call the OAuth callback
            response = await client.get(
                "/api/v1/auth/oauth/callback",
                params={
                    "provider": provider,
                    "code": "test_auth_code",
                }
            )
            
            # Check response status and content
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            
            # Verify that a new user was created
            from app import crud
            user = crud.user.get_by_email(db_session, email=new_email)
            
            assert user is not None
            assert user.email == new_email
            assert user.is_email_verified is True  # OAuth users should be verified
            
            # Verify OAuth account was created
            oauth_account = crud.oauth_account.get_by_provider_and_user(
                db_session,
                provider=provider,
                provider_user_id=mock_oauth_response["id"],
            )
            
            assert oauth_account is not None
            assert oauth_account.user_id == user.id


@pytest.mark.parametrize("provider", ["google", "facebook", "github", "linkedin", "twitter"])
@pytest.mark.asyncio
async def test_oauth_callback_existing_oauth_user(client, db_session, verified_test_user, mock_oauth_response, provider):
    """Test OAuth callback with an existing OAuth user."""
    # Create an OAuth account for the test user
    from app import crud
    oauth_account = crud.oauth_account.create(
        db=db_session,
        user_id=verified_test_user.id,
        provider=provider,
        provider_user_id=mock_oauth_response["id"],
        access_token="old_access_token",
        refresh_token="old_refresh_token",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    
    # Mock the exchange_code_for_token function
    with patch("app.api.endpoints.auth.exchange_code_for_token", new_callable=AsyncMock) as mock_exchange:
        mock_exchange.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }
        
        # Mock the get_user_info function
        with patch("app.api.endpoints.auth.get_user_info", new_callable=AsyncMock) as mock_get_info:
            mock_get_info.return_value = {
                "provider": provider,
                "provider_user_id": mock_oauth_response["id"],
                "email": verified_test_user.email,
                "full_name": f"{mock_oauth_response['given_name']} {mock_oauth_response['family_name']}",
                "picture_url": mock_oauth_response["picture"],
            }
            
            # Call the OAuth callback
            response = await client.get(
                "/api/v1/auth/oauth/callback",
                params={
                    "provider": provider,
                    "code": "test_auth_code",
                }
            )
            
            # Check response status and content
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            
            # Verify OAuth account was updated
            updated_oauth_account = crud.oauth_account.get_by_provider_and_user(
                db_session,
                provider=provider,
                provider_user_id=mock_oauth_response["id"],
            )
            
            assert updated_oauth_account is not None
            assert updated_oauth_account.access_token == "new_access_token"
            assert updated_oauth_account.refresh_token == "new_refresh_token"
            assert updated_oauth_account.expires_at is not None 