from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
import secrets
from fastapi.responses import RedirectResponse
from typing import Optional
from uuid import uuid4

from app.api.deps import get_db, get_current_user
from app.crud import user as user_crud
from app.crud import token as token_crud
from app.crud import oauth as oauth_crud
from app.models.user import User
from app.models.token import TokenType, OAuthStateToken
from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
)
from app.schemas.user import UserCreate, UserUpdate
from app.schemas.token import Token, RefreshToken
from app.core.config import settings
from app.schemas.oauth import OAuthProvider, OAuthUserInfo, OAuthAccountCreate, OAuthAccountUpdate
from app.core.oauth import get_oauth_login_url, exchange_code_for_token, get_user_info

router = APIRouter()

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """Authenticate user."""
    user = user_crud.get_by_email(db, email=email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

@router.post("/register", response_model=UserCreate)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    if user_crud.get_by_email(db, email=user_in.email):
        raise HTTPException(
            status_code=409,
            detail="A user with this email already exists."
        )
    user = user_crud.create(db, obj_in=user_in)
    return user

@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login user."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Inactive user"
        )
    
    if user.is_locked:
        raise HTTPException(
            status_code=400,
            detail="Account is locked"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(
        subject=user.id,
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        expires_delta=refresh_token_expires
    )
    
    # Store tokens in database
    token_crud.create_access_token(
        db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires
    )
    token_crud.create_refresh_token(
        db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """Verify user's email address."""
    user = user_crud.verify_email(db, token=token)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification token"
        )
    return {"message": "Email verified successfully"}

@router.post("/refresh", response_model=Token)
def refresh_token(
    token_in: RefreshToken,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Refresh access token."""
    token = token_crud.get_token(
        db,
        token=token_in.refresh_token,
        token_type=TokenType.REFRESH
    )
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid refresh token"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(
        subject=current_user.id,
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        user_id=current_user.id,
        expires_delta=refresh_token_expires
    )
    
    # Store new tokens in database
    token_crud.create_access_token(
        db,
        user_id=current_user.id,
        token=access_token,
        expires_delta=access_token_expires
    )
    token_crud.create_refresh_token(
        db,
        user_id=current_user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires
    )
    
    # Revoke old refresh token
    token_crud.revoke_token(db, token=token_in.refresh_token)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/logout", status_code=204)
def logout(
    token_in: RefreshToken,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Logout user by revoking refresh token."""
    token = token_crud.get_token(
        db,
        token=token_in.refresh_token,
        token_type=TokenType.REFRESH
    )
    if token and token.token_type == TokenType.REFRESH:
        token_crud.revoke_token(db, token=token_in.refresh_token)
    return Response(status_code=204)

@router.post("/forgot-password", status_code=204)
def forgot_password(email: str, db: Session = Depends(get_db)):
    """Send password reset email."""
    user = user_crud.get_by_email(db, email=email)
    if user:
        # Generate and send reset token
        token = user_crud.create_verification_token(
            db,
            user_id=user.id,
            token_type=TokenType.PASSWORD_RESET,
            expires_delta=timedelta(hours=24)
        )
    return Response(status_code=204)

@router.post("/reset-password")
def reset_password(
    token: str,
    new_password: str,
    db: Session = Depends(get_db),
):
    """Reset password using reset token."""
    user = user_crud.reset_password(
        db,
        token=token,
        new_password=new_password
    )
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token"
        )
    return {"message": "Password reset successfully"}

@router.put("/change-password")
def change_password(
    current_password: str,
    new_password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change user's password."""
    if not verify_password(current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect password"
        )
    user_crud.update(
        db,
        db_obj=current_user,
        obj_in={"hashed_password": get_password_hash(new_password)}
    )
    return {"message": "Password changed successfully"}

@router.get("/account-status/{email}")
def check_account_status(
    email: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Check account status."""
    user = user_crud.get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    return {
        "is_active": user.is_active,
        "is_email_verified": user.is_email_verified,
        "is_locked": user.is_locked,
        "recent_failed_attempts": user.recent_failed_attempts
    }

@router.post("/unlock-account/{email}", status_code=204)
def unlock_account(
    email: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Unlock user account."""
    user = user_crud.get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    user_crud.update(
        db,
        db_obj=user,
        obj_in={"is_locked": False, "recent_failed_attempts": 0}
    )
    return Response(status_code=204)

@router.post("/mfa/enable")
def enable_mfa(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Enable MFA for current user."""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled"
        )
    
    # Generate and store MFA secret
    user = user_crud.enable_mfa(db, user=current_user)
    return {
        "mfa_enabled": True,
        "mfa_secret": user.mfa_secret,
        "mfa_qr_code": user.mfa_qr_code
    }

@router.post("/mfa/verify")
def verify_mfa(
    code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify MFA code."""
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is not enabled"
        )
    
    if not user_crud.verify_mfa_code(db, user=current_user, code=code):
        raise HTTPException(
            status_code=400,
            detail="Invalid MFA code"
        )
    
    return {"mfa_verified": True}

@router.post("/mfa/disable")
def disable_mfa(
    password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Disable MFA for current user."""
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is not enabled"
        )
    
    if not verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect password"
        )
    
    user = user_crud.update(
        db,
        db_obj=current_user,
        obj_in={"mfa_enabled": False, "mfa_secret": None}
    )
    return {"mfa_enabled": False}

@router.get("/oauth/{provider}/login")
async def oauth_login(
    provider: OAuthProvider,
    db: Session = Depends(get_db)
) -> RedirectResponse:
    """OAuth login endpoint."""
    # Generate state token
    state = secrets.token_urlsafe(32)
    
    # Store state token in database
    token = OAuthStateToken(
        id=str(uuid4()),
        user_id=None,  # No user associated yet
        token=state,
        token_type=TokenType.OAUTH_STATE,
        expires_at=datetime.utcnow() + timedelta(minutes=10),  # State token expires in 10 minutes
        created_at=datetime.utcnow(),
        is_revoked=False
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    
    # Get OAuth login URL
    login_url = await get_oauth_login_url(
        provider=provider,
        redirect_uri=settings.OAUTH_REDIRECT_URI,
        state=state
    )
    
    # Redirect to OAuth provider's login page
    return RedirectResponse(url=login_url, status_code=307)

@router.get("/oauth/callback/{provider}")
async def oauth_callback(
    provider: OAuthProvider,
    code: str,
    state: str,
    redirect_uri: str,
    db: Session = Depends(get_db)
) -> dict:
    """OAuth callback endpoint."""
    # Verify state token
    state_token = token_crud.get_oauth_state_token(db, state)
    
    if not state_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid state token"
        )
    
    # Exchange code for token
    token_data = await exchange_code_for_token(
        provider=provider,
        code=code,
        redirect_uri=redirect_uri
    )
    
    # Get user info from provider
    user_info = await get_user_info(
        provider=provider,
        access_token=token_data["access_token"]
    )
    
    # Find or create user
    oauth_account = oauth_crud.get_by_provider_and_account_id(
        db,
        provider=provider,
        account_id=user_info.account_id
    )
    
    if oauth_account:
        user = oauth_account.user
        # Update OAuth account with new tokens
        oauth_crud.update(
            db,
            db_obj=oauth_account,
            obj_in=OAuthAccountUpdate(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                expires_at=datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600))
            )
        )
    else:
        # Create new user if email doesn't exist
        existing_user = user_crud.get_by_email(db, email=user_info.email)
        if existing_user:
            # Link OAuth account to existing user
            user = existing_user
            oauth_crud.create(
                db,
                obj_in=OAuthAccountCreate(
                    provider=provider,
                    account_id=user_info.account_id,
                    account_email=user_info.email,
                    user_id=user.id,
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    expires_at=datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600)),
                    is_active=True,
                    raw_data=user_info.raw_data
                )
            )
        else:
            # Create new user with random password
            password = secrets.token_urlsafe(32)
            user = user_crud.create(
                db,
                obj_in=UserCreate(
                    email=user_info.email,
                    first_name=user_info.first_name or "",
                    last_name=user_info.last_name or "",
                    password=password,
                    confirm_password=password,
                    is_email_verified=True  # Email is verified through OAuth
                )
            )
            # Create OAuth account
            oauth_crud.create(
                db,
                obj_in=OAuthAccountCreate(
                    provider=provider,
                    account_id=user_info.account_id,
                    account_email=user_info.email,
                    user_id=user.id,
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    expires_at=datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600)),
                    is_active=True,
                    raw_data=user_info.raw_data
                )
            )
    
    # Create access and refresh tokens
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    # Store refresh token in database
    token_crud.create_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    # Revoke state token
    token_crud.revoke_token(db, state_token.id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    } 