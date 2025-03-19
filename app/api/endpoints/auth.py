from datetime import datetime, timedelta
from typing import Any, Optional, Dict
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Body, Depends, HTTPException, status, Request, BackgroundTasks, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, JSONResponse
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app import crud
from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.enums import OAuthProvider
from app.models.user import User
from app.models.token import TokenType
from app.models.login_attempt import LoginAttempt
from app.schemas.token import Token, RefreshToken, VerificationToken, TokenPayload
from app.schemas.user import UserCreate, UserUpdate, User as UserSchema, MFAResponse
from app.schemas.password import PasswordChange, PasswordReset
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_password_reset_token,
    generate_verification_token,
    generate_mfa_code,
    verify_password,
    get_password_hash,
)
from app.schemas.auth import (
    ChangePassword,
    ForgotPassword,
    Login,
    MFAEnable,
    MFAVerify,
    ResetPassword,
    VerifyEmail,
)
from app.schemas.oauth import OAuthCallback, OAuthRequest, OAuthUserInfo
from app.schemas.password import PasswordReset, PasswordResetRequest
from app.schemas.mfa import MFADisable, MFAResponse, MFAVerify
from app.schemas.login_attempt import LoginAttemptStats
from app.services.oauth import (
    get_oauth_login_url,
    exchange_code_for_token,
    get_user_info,
)
from app.services.email import (
    send_verification_email,
    send_password_reset_email,
    send_mfa_code_email,
    send_security_notification_email,
)
from app.crud.user import (
    get_by_email,
    create as create_user,
    authenticate,
    set_email_verified,
    update as update_user,
    set_password,
    enable_mfa,
    delete as delete_user,
    get_by_id,
)
from app.crud.token import (
    create_access_token as create_db_access_token,
    create_refresh_token as create_db_refresh_token,
    get_token,
    revoke_token,
    create_verification_token,
)
from app.crud.oauth_account import (
    get_by_provider_and_user as get_oauth_account,
    create as create_oauth_account,
)
from app.crud.login_attempt import (
    create as create_login_attempt,
    count_recent_failed_attempts,
    get_recent_attempts,
    is_account_locked,
)


router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/csrf-token")
def get_csrf_token():
    """Get a CSRF token for form submissions."""
    token = secrets.token_urlsafe(32)
    response = JSONResponse(content={"csrf_token": token})
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    return response


@router.post("/register", response_model=UserSchema)
def register_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
) -> Any:
    """
    Register a new user.
    """
    # Check if a user with the given email already exists
    existing_user = get_by_email(db, email=user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )
    
    # Create the user
    user = create_user(db, obj_in=user_in)
    
    # Generate and store email verification token
    token = generate_verification_token()
    crud.token.create_verification_token(
        db=db,
        user_id=user.id,
        token=token,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_delta=timedelta(hours=24)
    )
    
    # Send verification email
    send_verification_email(user.email, token)
    
    return user


@router.post("/verify-email", response_model=UserSchema)
def verify_email(
    *,
    db: Session = Depends(get_db),
    token_in: VerifyEmail,
) -> Any:
    """
    Verify a user's email address using the token sent via email.
    """
    # Verify the token
    verification_token = crud.token.get_token(db, token=token_in.token, token_type=TokenType.EMAIL_VERIFICATION)
    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )
    
    # Get the user
    user = crud.user.get(db, id=verification_token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Update user's email verification status
    user = crud.user.update(
        db,
        db_obj=user,
        obj_in={"is_email_verified": True}
    )
    
    # Delete the used token
    crud.token.delete_token(db, token=token_in.token)
    
    return user


@router.post("/login", response_model=Token)
def login(
    *,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Get access token for authenticated user.
    
    Implements account lockout after multiple failed login attempts.
    Sends security notification emails for suspicious login activity.
    """
    email = form_data.username
    password = form_data.password
    
    # Extract client information
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # Check if the account is locked due to too many failed attempts
    if crud.login_attempt.is_account_locked(
        db, email=email, max_attempts=settings.MAX_LOGIN_ATTEMPTS, lockout_minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to too many failed login attempts",
        )
    
    # Authenticate user
    user = crud.user.authenticate(db, email=email, password=password)
    if not user:
        # Record failed login attempt
        crud.login_attempt.create(
            db,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    
    # Record successful login attempt
    crud.login_attempt.create(
        db,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True
    )
    
    # Check if email is verified
    if not user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in",
        )
    
    # Create access and refresh tokens
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(user_id=user.id)
    
    # Store tokens in the database
    create_db_access_token(db, user_id=user.id, token=access_token)
    create_db_refresh_token(db, user_id=user.id, token=refresh_token)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh", response_model=Token)
def refresh_token(
    *,
    db: Session = Depends(get_db),
    refresh_token_in: RefreshToken,
) -> Any:
    """
    Refresh access token.
    """
    # Verify the refresh token
    try:
        payload = jwt.decode(
            refresh_token_in.refresh_token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if the token has been revoked
    if not crud.token.get_token(db, token=refresh_token_in.refresh_token, token_type=TokenType.REFRESH):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get the user
    user = crud.user.get(db, id=token_data.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    if not crud.user.is_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    
    # Create new access token
    access_token = create_access_token(subject=user.id)
    
    # Store the new access token
    crud.token.create_access_token(db, user_id=user.id, token=access_token)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token_in.refresh_token,
        "token_type": "bearer"
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    refresh_token_in: RefreshToken,
) -> None:
    """
    Logout the current user by revoking the refresh token.
    """
    # Revoke the refresh token
    revoke_token(db, token=refresh_token_in.refresh_token)
    return None


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
def forgot_password(
    *,
    db: Session = Depends(get_db),
    email_in: str = Body(..., embed=True),
    background_tasks: BackgroundTasks,
) -> None:
    """
    Password recovery email.
    """
    user = get_by_email(db, email=email_in)
    if user:
        token = generate_password_reset_token()
        set_email_verified(db, user=user, token=token, token_type=TokenType.PASSWORD_RESET, expires_delta=timedelta(hours=24))
        background_tasks.add_task(
            send_password_reset_email, user.email, token
        )
    return None


@router.post("/reset-password", response_model=Token)
def reset_password(
    *,
    db: Session = Depends(get_db),
    reset_in: PasswordReset,
    request: Request,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Resets the user's password using a valid reset token.
    
    If the token is valid, updates the user's password and returns new access tokens.
    Sends security notification for password reset.
    """
    # Verify the token
    token = get_token(db, token=reset_in.token, token_type=TokenType.PASSWORD_RESET)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    # Get the user
    user = get_by_email(db, user_id=token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Update the password
    user_in = {"password": reset_in.new_password}
    update_user(db, db_obj=user, obj_in=user_in)
    
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Send a security notification email
    background_tasks.add_task(
        send_security_notification_email,
        email_to=user.email,
        event_type="password_change",
        details={
            "timestamp": datetime.utcnow(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": "Unknown (IP geolocation not implemented)",
            "method": "Password reset",
        },
        username=user.first_name,
    )
    
    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user_id=user.id, expires_delta=refresh_token_expires)
    
    # Store the tokens in the database
    create_db_access_token(db, user_id=user.id, token=access_token, expires_delta=access_token_expires)
    
    create_db_refresh_token(db, user_id=user.id, token=refresh_token, expires_delta=refresh_token_expires)
    
    # Update last login timestamp
    update_user(db, db_obj=user, obj_in={"last_login": datetime.utcnow()})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.put("/change-password", response_model=Token)
def change_password(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    password_in: ChangePassword,
) -> Any:
    """
    Change password for the current user.
    """
    if not verify_password(password_in.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )
    
    # Update password
    set_password(db, user=current_user, new_password=password_in.new_password)
    
    # Create new tokens
    access_token = create_access_token(subject=current_user.id)
    refresh_token = create_refresh_token(user_id=current_user.id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/mfa/enable", response_model=MFAResponse)
def enable_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Enable MFA for the current user.
    """
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )
    
    # Generate MFA code
    mfa_code = generate_mfa_code()
    
    # Store MFA code
    set_email_verified(db, user=current_user, token=mfa_code, token_type=TokenType.MFA, expires_delta=timedelta(minutes=10))
    
    # Send MFA code via email
    send_mfa_code_email(current_user.email, mfa_code)
    
    return {"mfa_enabled": True}


@router.post("/mfa/verify", response_model=MFAResponse)
def verify_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    mfa_in: MFAVerify,
) -> Any:
    """
    Verify MFA code and enable MFA for the user.
    """
    # Verify MFA code
    token = get_token(db, token=mfa_in.code, token_type=TokenType.MFA)
    
    if not token or token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code",
        )
    
    # Enable MFA
    update_user(db, db_obj=current_user, obj_in={"mfa_enabled": True})
    
    return {"mfa_verified": True}


@router.post("/mfa/disable", response_model=MFAResponse)
def disable_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    mfa_in: MFADisable,
) -> Any:
    """
    Disable MFA for the current user.
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )
    
    # Verify password
    if not verify_password(mfa_in.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )
    
    # Disable MFA
    update_user(db, db_obj=current_user, obj_in={"mfa_enabled": False})
    
    return {"mfa_enabled": False}


@router.get("/oauth/{provider}/login")
def oauth_login(
    provider: str,
    redirect_uri: str = Query(..., description="The URL to redirect to after OAuth login"),
    state: Optional[str] = Query(None, description="Optional state parameter for CSRF protection"),
    db: Session = Depends(get_db),
) -> Any:
    """
    Initiate OAuth login flow.
    """
    try:
        oauth_provider = OAuthProvider(provider.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}"
        )
    
    # Generate OAuth login URL with state
    login_url = get_oauth_login_url(oauth_provider, redirect_uri, state)
    
    # Return redirect response
    return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)


@router.post("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    oauth_callback: OAuthCallback,
    db: Session = Depends(get_db),
) -> Any:
    """
    Handle OAuth callback and create/update user.
    """
    try:
        oauth_provider = OAuthProvider(provider.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}"
        )
    
    try:
        # Exchange code for token
        token_data = await exchange_code_for_token(oauth_provider, oauth_callback.code, oauth_callback.redirect_uri)
        
        # Get user info from provider
        user_info = await get_user_info(oauth_provider, token_data)
        
        # Check if user already exists with this OAuth account
        oauth_account = crud.oauth_account.get_by_provider_and_user(
            db,
            provider=oauth_provider,
            provider_user_id=user_info.provider_user_id
        )
        
        if oauth_account:
            # Get existing user
            user = crud.user.get(db, id=oauth_account.user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
        else:
            # Check if user exists with this email
            user = crud.user.get_by_email(db, email=user_info.email)
            if user:
                # Link OAuth account to existing user
                crud.oauth_account.create(
                    db,
                    user_id=user.id,
                    provider=oauth_provider,
                    provider_user_id=user_info.provider_user_id,
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    expires_at=token_data["expires_at"]
                )
            else:
                # Create new user
                user_in = UserCreate(
                    email=user_info.email,
                    first_name=user_info.first_name,
                    last_name=user_info.last_name,
                    is_active=True,
                    is_email_verified=True,  # OAuth emails are pre-verified
                    gender=user_info.gender,
                    date_of_birth=user_info.date_of_birth,
                    password=secrets.token_urlsafe(32),  # Generate a random password
                    confirm_password=secrets.token_urlsafe(32)  # Same random password for confirmation
                )
                user = crud.user.create(db, obj_in=user_in)
                
                # Create OAuth account
                crud.oauth_account.create(
                    db,
                    user_id=user.id,
                    provider=oauth_provider,
                    provider_user_id=user_info.provider_user_id,
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    expires_at=token_data["expires_at"]
                )
        
        # Create access and refresh tokens
        access_token = create_access_token(subject=user.id)
        refresh_token = create_refresh_token(user_id=user.id)
        
        # Store tokens in the database
        crud.token.create_access_token(db, user_id=user.id, token=access_token)
        crud.token.create_refresh_token(db, user_id=user.id, token=refresh_token)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/account-status/{email}", response_model=LoginAttemptStats)
def check_account_status(
    *,
    db: Session = Depends(get_db),
    email: str,
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Check account lockout status and login attempt statistics.
    
    This endpoint is restricted to admins or the user checking their own account.
    """
    # Security check - users can only check their own account status
    if current_user.email != email and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this account information",
        )
    
    # Get account statistics
    recent_attempts = get_recent_attempts(db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
    
    recent_failed_attempts = count_recent_failed_attempts(
        db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    )
    
    is_locked = is_account_locked(
        db, email=email, max_attempts=settings.MAX_LOGIN_ATTEMPTS, lockout_minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    )
    
    lockout_remaining = None
    if is_locked and recent_attempts:
        # Calculate remaining lockout time
        most_recent_attempt = recent_attempts[0]
        
        elapsed_minutes = (datetime.utcnow() - most_recent_attempt.timestamp).total_seconds() / 60
        lockout_remaining = max(0, int(settings.ACCOUNT_LOCKOUT_MINUTES - elapsed_minutes))
    
    return {
        "recent_attempts": len(recent_attempts),
        "recent_failed_attempts": recent_failed_attempts,
        "is_locked": is_locked,
        "lockout_remaining": lockout_remaining,
    }


@router.post("/unlock-account/{email}", status_code=status.HTTP_204_NO_CONTENT)
def unlock_account(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    email: str,
) -> None:
    """
    Unlock a user account.
    """
    # Check if the user has admin privileges
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges",
        )
    
    # Get the user to unlock
    user = get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Unlock the account
    update_user(db, db_obj=user, obj_in={"is_locked": False})
    return None


def get_oauth_login_url(provider: OAuthProvider, redirect_uri: str = None, state: Optional[str] = None) -> str:
    """Get the OAuth login URL for the specified provider."""
    if provider not in [OAuthProvider.GOOGLE, OAuthProvider.FACEBOOK]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported OAuth provider: {provider}"
        )

    base_urls = {
        OAuthProvider.GOOGLE: "https://accounts.google.com/o/oauth2/v2/auth",
        OAuthProvider.FACEBOOK: "https://www.facebook.com/v12.0/dialog/oauth"
    }

    client_ids = {
        OAuthProvider.GOOGLE: settings.GOOGLE_CLIENT_ID,
        OAuthProvider.FACEBOOK: settings.FACEBOOK_CLIENT_ID
    }

    scopes = {
        OAuthProvider.GOOGLE: ["openid", "email", "profile"],
        OAuthProvider.FACEBOOK: ["email", "public_profile"]
    }

    params = {
        "client_id": client_ids[provider],
        "redirect_uri": redirect_uri or settings.OAUTH_REDIRECT_URL,
        "response_type": "code",
        "scope": " ".join(scopes[provider]),
        "state": state
    }

    return f"{base_urls[provider]}?{urlencode(params)}" 