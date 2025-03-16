from datetime import datetime, timedelta
from typing import Any, Optional
import secrets

from fastapi import APIRouter, Body, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.dependencies.deps import get_db
from app.crud import user as user_crud
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_password_reset_token,
    generate_verification_token,
    generate_mfa_code,
    verify_password,
)
from app.models.token import TokenType
from app.models.user import User
from app.models.oauth_account import OAuthProvider
from app.schemas.auth import (
    ChangePassword,
    ForgotPassword,
    Login,
    MFAEnable,
    MFAVerify,
    ResetPassword,
    VerifyEmail,
)
from app.schemas.token import RefreshToken, Token, VerificationToken
from app.schemas.user import User as UserSchema, UserCreate, UserUpdate
from app.services import email
from app.schemas.oauth import OAuthCallback, OAuthRequest, OAuthUserInfo
from app.schemas.password import PasswordReset, PasswordResetRequest
from app.schemas.mfa import MFADisable, MFAResponse, MFAVerify
from app.schemas.login_attempt import LoginAttemptStats


router = APIRouter(prefix="/auth", tags=["auth"])


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
    existing_user = user_crud.get_by_email(db, email=user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )
    
    # Create the user
    user = user_crud.create(db, obj_in=user_in)
    
    # Generate and store email verification token
    token = generate_verification_token()
    user_crud.create_verification_token(
        db=db,
        user_id=user.id,
        token=token,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_delta=timedelta(hours=24),
    )
    
    # Send verification email
    email.send_verification_email(user.email, token)
    
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
    verification_token = user_crud.verify_token(
        db=db,
        token=token_in.token,
        token_type=TokenType.EMAIL_VERIFICATION,
    )
    
    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    # Get the user and mark email as verified
    user = user_crud.get_by_id(db, user_id=verification_token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    user = crud.user.set_email_verified(db, user=user)
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
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Check if the account is locked due to too many failed attempts
    if crud.login_attempt.is_account_locked(
        db, email=email, max_attempts=settings.MAX_LOGIN_ATTEMPTS, lockout_minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    ):
        # Record the failed attempt
        crud.login_attempt.create(
            db, email=email, ip_address=ip_address, user_agent=user_agent, success=False
        )
        
        # Check if the user exists to send a notification
        user = crud.user.get_by_email(db, email=email)
        if user:
            # Send a security notification email
            background_tasks.add_task(
                email.send_security_notification_email,
                email_to=user.email,
                event_type="account_locked",
                details={
                    "timestamp": datetime.utcnow(),
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "location": "Unknown (IP geolocation not implemented)",
                },
                username=user.first_name,
            )
        
        # Return an error with information about the lockout
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed login attempts. "
                   f"Please try again after {settings.ACCOUNT_LOCKOUT_MINUTES} minutes or reset your password.",
        )
    
    # Authenticate the user
    user = crud.user.authenticate(db, email=email, password=password)
    
    if not user:
        # Record the failed attempt
        crud.login_attempt.create(
            db, email=email, ip_address=ip_address, user_agent=user_agent, success=False
        )
        
        # Get the count of recent failed attempts to include in the error message
        failed_attempts = crud.login_attempt.count_recent_failed_attempts(
            db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES
        )
        attempts_left = settings.MAX_LOGIN_ATTEMPTS - failed_attempts
        
        if attempts_left <= 0:
            detail = f"Account temporarily locked due to too many failed login attempts. " \
                     f"Please try again after {settings.ACCOUNT_LOCKOUT_MINUTES} minutes or reset your password."
        else:
            detail = f"Incorrect email or password. {attempts_left} attempts remaining before account is locked."
        
        # If we're approaching the lockout threshold, send a notification if the user exists
        if failed_attempts >= settings.MAX_LOGIN_ATTEMPTS - 2:  # Send when 2 or fewer attempts left
            potential_user = crud.user.get_by_email(db, email=email)
            if potential_user:
                background_tasks.add_task(
                    email.send_security_notification_email,
                    email_to=potential_user.email,
                    event_type="login_attempt",
                    details={
                        "timestamp": datetime.utcnow(),
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "location": "Unknown (IP geolocation not implemented)",
                        "attempts_remaining": attempts_left,
                        "status": "Failed login attempt",
                    },
                    username=potential_user.first_name,
                )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not crud.user.is_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    
    # Record the successful attempt
    crud.login_attempt.create(
        db, email=email, ip_address=ip_address, user_agent=user_agent, success=True
    )
    
    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.id, expires_delta=refresh_token_expires)
    
    # Store tokens in the database
    crud.token.create_access_token(
        db=db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires,
    )
    
    crud.token.create_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires,
    )
    
    # Update last_login timestamp
    crud.user.update_last_login(db, user=user)
    
    # Check if this is a login from a new IP or device and notify the user
    recent_successful_logins = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.email == email,
        models.LoginAttempt.success == True,
        models.LoginAttempt.timestamp >= datetime.utcnow() - timedelta(days=30)
    ).all()
    
    # If this is the first successful login or from a new IP/device
    if len(recent_successful_logins) <= 1 or not any(
        attempt.ip_address == ip_address and attempt.user_agent == user_agent
        for attempt in recent_successful_logins[1:]  # Skip the current login
    ):
        # Send a notification about the new device login
        background_tasks.add_task(
            email.send_security_notification_email,
            email_to=user.email,
            event_type="login_attempt",
            details={
                "timestamp": datetime.utcnow(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "location": "Unknown (IP geolocation not implemented)",
                "status": "Successful login from new device or location",
            },
            username=user.first_name,
        )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
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
    if not crud.token.is_valid_refresh_token(db, token=refresh_token_in.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get the user
    user = crud.user.get_by_id(db, user_id=token_data.sub)
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
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    
    # Store new access token in the database
    crud.token.create_access_token(
        db=db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token_in.refresh_token,
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    refresh_token_in: RefreshToken,
) -> Any:
    """
    Logout the current user by revoking the refresh token.
    """
    crud.token.revoke_refresh_token(db, token=refresh_token_in.refresh_token)
    return None


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
def forgot_password(
    *,
    db: Session = Depends(get_db),
    request_in: PasswordResetRequest,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Initiates the password reset process.
    
    Sends a password reset email to the provided email address if it exists in the system.
    Always returns a 204 response for security reasons (to not leak whether an email exists).
    """
    # Check if the user exists
    user = crud.user.get_by_email(db, email=request_in.email)
    if not user:
        # Return success even if the user doesn't exist for security reasons
        return None
    
    # Create a password reset token
    reset_token_value = generate_password_reset_token()
    reset_token = crud.token.create_verification_token(
        db=db,
        user_id=user.id,
        token=reset_token_value,
        token_type=TokenType.PASSWORD_RESET,
        expires_delta=timedelta(hours=24),  # Token valid for 24 hours
    )
    
    # Send the password reset email
    background_tasks.add_task(
        email.send_password_reset_email,
        email_to=user.email,
        token=reset_token_value,
        username=user.first_name,
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
    token = crud.token.verify_token(
        db=db,
        token=reset_in.token,
        token_type=TokenType.PASSWORD_RESET,
    )
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    # Get the user
    user = crud.user.get_by_id(db, user_id=token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Update the password
    user_in = {"password": reset_in.new_password}
    crud.user.update(db, db_obj=user, obj_in=user_in)
    
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Send a security notification email
    background_tasks.add_task(
        email.send_security_notification_email,
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
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.id, expires_delta=refresh_token_expires)
    
    # Store the tokens in the database
    crud.token.create_access_token(
        db=db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires,
    )
    
    crud.token.create_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires,
    )
    
    # Update last login timestamp
    crud.user.update_last_login(db, user=user)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.put("/change-password", response_model=Token)
def change_password(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_verified_user),
    current_password: str = Body(...),
    new_password: str = Body(...),
    request: Request,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Change the user's password.
    
    Requires the current password for verification.
    Returns new access and refresh tokens.
    Sends security notification for password change.
    """
    # Verify the current password
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    
    # Update the password
    user_in = {"password": new_password}
    user = crud.user.update(db, db_obj=current_user, obj_in=user_in)
    
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Send a security notification email
    background_tasks.add_task(
        email.send_security_notification_email,
        email_to=user.email,
        event_type="password_change",
        details={
            "timestamp": datetime.utcnow(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": "Unknown (IP geolocation not implemented)",
        },
        username=user.first_name,
    )
    
    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.id, expires_delta=refresh_token_expires)
    
    # Store the tokens in the database
    crud.token.create_access_token(
        db=db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires,
    )
    
    crud.token.create_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires,
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/mfa/enable", response_model=UserSchema)
def enable_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Enable MFA for the current user.
    
    Generates an MFA verification code and sends it to the user's email.
    Returns a message with instructions.
    """
    # Generate an MFA verification code
    mfa_code = generate_mfa_code()
    
    # Store the MFA verification code
    mfa_token = crud.token.create_verification_token(
        db=db,
        user_id=current_user.id,
        token=mfa_code,
        token_type=TokenType.MFA,
        expires_delta=timedelta(minutes=10),  # Short expiration for security
    )
    
    # Send the MFA verification code via email
    background_tasks.add_task(
        email.send_mfa_code_email,
        email_to=current_user.email,
        code=mfa_code,
        username=current_user.first_name,
    )
    
    return {
        "message": "An MFA verification code has been sent to your email. Use this code to verify and enable MFA."
    }


@router.post("/mfa/verify", response_model=UserSchema)
def verify_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_verified_user),
    mfa_in: MFAVerify,
    request: Request,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Verify the MFA code and enable MFA for the user.
    
    Verifies the MFA code sent to the user's email.
    If valid, enables MFA for the user.
    Sends security notification for MFA enablement.
    """
    # Verify the MFA code
    token = crud.token.verify_token(
        db=db,
        token=mfa_in.code,
        token_type=TokenType.MFA,
    )
    
    if not token or token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired MFA code",
        )
    
    # Enable MFA for the user
    user = crud.user.enable_mfa(db, user=current_user, enable=True)
    
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Send a security notification email
    background_tasks.add_task(
        email.send_security_notification_email,
        email_to=user.email,
        event_type="mfa_enabled",
        details={
            "timestamp": datetime.utcnow(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": "Unknown (IP geolocation not implemented)",
        },
        username=user.first_name,
    )
    
    return user


@router.post("/mfa/disable", response_model=UserSchema)
def disable_mfa(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_verified_user),
    mfa_in: MFADisable,
    request: Request,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Disable MFA for the user.
    
    Requires the user's password for verification.
    Sends security notification for MFA disablement.
    """
    # Verify the password
    if not verify_password(mfa_in.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    
    # Disable MFA for the user
    user = crud.user.enable_mfa(db, user=current_user, enable=False)
    
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Send a security notification email
    background_tasks.add_task(
        email.send_security_notification_email,
        email_to=user.email,
        event_type="mfa_disabled",
        details={
            "timestamp": datetime.utcnow(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": "Unknown (IP geolocation not implemented)",
        },
        username=user.first_name,
    )
    
    return user


@router.get("/oauth/{provider}", status_code=status.HTTP_302_FOUND)
async def oauth_login(
    provider: OAuthProvider,
    request: Request,
    redirect_uri: Optional[str] = None,
) -> RedirectResponse:
    """
    Initiate OAuth login flow for the specified provider.
    """
    # Generate the OAuth login URL
    login_url = get_oauth_login_url(provider, redirect_uri)
    
    # Redirect the user to the provider's login page
    return RedirectResponse(url=login_url)


@router.get("/oauth/callback", response_model=Token)
async def oauth_callback(
    *,
    db: Session = Depends(get_db),
    provider: OAuthProvider,
    code: str,
    state: Optional[str] = None,
    redirect_uri: Optional[str] = None,
) -> Any:
    """
    Handle OAuth callback and authenticate the user.
    """
    # Exchange the authorization code for an access token
    token_data = await exchange_code_for_token(provider, code, redirect_uri)
    
    # Get user information from the provider
    user_info = await get_user_info(provider, token_data)
    
    # Check if there's an existing OAuth account
    oauth_account = crud.oauth_account.get_by_provider_and_id(
        db, provider=user_info.provider, provider_user_id=user_info.provider_user_id
    )
    
    user = None
    
    if oauth_account:
        # User already exists, get the user
        user = crud.user.get_by_id(db, user_id=oauth_account.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
    else:
        # Check if there's a user with the same email
        user = crud.user.get_by_email(db, email=user_info.email)
        
        if user:
            # Link the existing user with the OAuth account
            oauth_account = crud.oauth_account.create(
                db=db,
                user_id=user.id,
                provider=user_info.provider,
                provider_user_id=user_info.provider_user_id,
            )
        else:
            # Create a new user
            import uuid
            from datetime import date
            from app.schemas.user import Gender, UserCreate
            
            # Generate a secure random password that the user doesn't need to know
            random_password = secrets.token_urlsafe(16)
            
            user_in = UserCreate(
                first_name=user_info.first_name,
                last_name=user_info.last_name,
                date_of_birth=date(1900, 1, 1),  # Default date, can be updated later
                gender=Gender.PREFER_NOT_TO_SAY,  # Default gender, can be updated later
                email=user_info.email,
                mobile="+8801700000000",  # Default mobile, must be updated later
                password=random_password,
                confirm_password=random_password,
            )
            
            # Override validation for OAuth users
            user = User(
                id=uuid.uuid4(),
                first_name=user_info.first_name,
                last_name=user_info.last_name,
                date_of_birth=date(1900, 1, 1),
                gender=Gender.PREFER_NOT_TO_SAY,
                email=user_info.email,
                mobile="+8801700000000",
                password_hash=crud.user.get_password_hash(random_password),
                is_active=True,
                is_email_verified=True,  # OAuth users are considered verified
                mfa_enabled=False,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            
            db.add(user)
            db.commit()
            db.refresh(user)
            
            # Create the OAuth account
            oauth_account = crud.oauth_account.create(
                db=db,
                user_id=user.id,
                provider=user_info.provider,
                provider_user_id=user_info.provider_user_id,
            )
    
    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.id, expires_delta=refresh_token_expires)
    
    # Store tokens in the database
    crud.token.create_access_token(
        db=db,
        user_id=user.id,
        token=access_token,
        expires_delta=access_token_expires,
    )
    
    crud.token.create_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_delta=refresh_token_expires,
    )
    
    # Update last_login timestamp
    crud.user.update_last_login(db, user=user)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


@router.get("/account-status/{email}", response_model=LoginAttemptStats)
def check_account_status(
    *,
    db: Session = Depends(get_db),
    email: str,
    current_user: User = Depends(get_current_verified_user),
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
    recent_attempts = len(crud.login_attempt.get_recent_attempts(
        db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    ))
    
    recent_failed_attempts = crud.login_attempt.count_recent_failed_attempts(
        db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    )
    
    is_locked = crud.login_attempt.is_account_locked(
        db, email=email, max_attempts=settings.MAX_LOGIN_ATTEMPTS, lockout_minutes=settings.ACCOUNT_LOCKOUT_MINUTES
    )
    
    lockout_remaining = None
    if is_locked:
        # Calculate remaining lockout time
        most_recent_attempt = crud.login_attempt.get_recent_failed_attempts(
            db, email=email, minutes=settings.ACCOUNT_LOCKOUT_MINUTES
        )[0]
        
        from datetime import datetime
        elapsed_minutes = (datetime.utcnow() - most_recent_attempt.timestamp).total_seconds() / 60
        lockout_remaining = max(0, int(settings.ACCOUNT_LOCKOUT_MINUTES - elapsed_minutes))
    
    return {
        "recent_attempts": recent_attempts,
        "recent_failed_attempts": recent_failed_attempts,
        "is_locked": is_locked,
        "lockout_remaining": lockout_remaining,
    }


@router.post("/unlock-account/{email}", status_code=status.HTTP_204_NO_CONTENT)
def unlock_account(
    *,
    db: Session = Depends(get_db),
    email: str,
    current_user: User = Depends(get_current_verified_user),
) -> Any:
    """
    Unlock an account that has been locked due to too many failed login attempts.
    
    This endpoint is restricted to admins only.
    """
    # Only admins can unlock accounts
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to unlock accounts",
        )
    
    # Check if the user exists
    user = crud.user.get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Delete all failed login attempts for this user
    from sqlalchemy import and_
    db.query(models.LoginAttempt).filter(
        and_(
            models.LoginAttempt.email == email,
            models.LoginAttempt.success == False,
        )
    ).delete()
    db.commit()
    
    return None 