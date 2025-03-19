import uuid
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from sqlalchemy import and_
from passlib.context import CryptContext
import pyotp
import qrcode
import io
import base64

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.models.token import Token, TokenType, VerificationToken, PasswordResetToken
from app.models.oauth import OAuthAccount
from app.schemas.user import UserCreate, UserUpdate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_by_email(db: Session, *, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_by_id(db: Session, *, id: str) -> Optional[User]:
    return db.query(User).filter(User.id == id).first()


def create(db: Session, *, obj_in: UserCreate) -> User:
    """Create a new user."""
    db_obj = User(
        id=str(uuid.uuid4()),
        first_name=obj_in.first_name,
        last_name=obj_in.last_name,
        email=obj_in.email,
        date_of_birth=obj_in.date_of_birth,
        gender=obj_in.gender,
        mobile=obj_in.mobile,
        hashed_password=get_password_hash(obj_in.password) if obj_in.password else None,
        is_active=True,
        is_email_verified=obj_in.is_email_verified if hasattr(obj_in, 'is_email_verified') else False,
        mfa_enabled=False,
        is_superuser=False,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def update(
    db: Session, *, db_obj: User, obj_in: Union[UserUpdate, Dict[str, Any]]
) -> User:
    if isinstance(obj_in, dict):
        update_data = obj_in
    else:
        update_data = obj_in.dict(exclude_unset=True)
    
    # Don't attempt to update password directly through this method
    if "password" in update_data:
        del update_data["password"]
    
    for field in update_data:
        if hasattr(db_obj, field):
            setattr(db_obj, field, update_data[field])
    
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def set_password(db: Session, *, user: User, password: str) -> User:
    """Set a new password for the user."""
    user.hashed_password = get_password_hash(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, *, email: str, password: str) -> Optional[User]:
    """Authenticate a user by email and password."""
    user = get_by_email(db, email=email)
    if not user:
        return None
    if not user.hashed_password:  # OAuth user without password
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_email_verified:
        return None
    return user


def set_email_verified(db: Session, *, user: User) -> User:
    """Set a user's email as verified."""
    user.is_email_verified = True
    user.updated_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def toggle_mfa(db: Session, *, user: User, enable: bool) -> User:
    """Enable or disable MFA for a user."""
    user.mfa_enabled = enable
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def delete(db: Session, *, user_id: str) -> None:
    """Delete a user."""
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        # Delete all tokens first
        db.query(Token).filter(Token.user_id == user_id).delete()
        # Delete all OAuth accounts
        db.query(OAuthAccount).filter(OAuthAccount.user_id == user_id).delete()
        # Delete the user
        db.delete(user)
        db.commit()


def remove(db: Session, *, id: str) -> None:
    """Remove a user by ID."""
    return delete(db, user_id=id)


def is_active(user: User) -> bool:
    return user.is_active


def is_email_verified(user: User) -> bool:
    return user.is_email_verified


def update_last_login(db: Session, user: User) -> User:
    """Update the user's last login timestamp."""
    user.last_login = datetime.utcnow()
    user.updated_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def enable_mfa(db: Session, user: User, enable: bool = True) -> User:
    """Enable MFA for a user."""
    if enable:
        # Generate MFA secret
        secret = pyotp.random_base32()
        user.mfa_secret = secret

        # Generate QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            user.email,
            issuer_name="AuthenticationSystem"
        )
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        user.mfa_qr_code = qr_code
    else:
        user.mfa_secret = None
        user.mfa_qr_code = None
    
    user.mfa_enabled = enable
    user.updated_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def verify_mfa_code(db: Session, user: User, code: str) -> bool:
    """Verify MFA code."""
    if not user.mfa_enabled or not user.mfa_secret:
        return False
    
    totp = pyotp.TOTP(user.mfa_secret)
    return totp.verify(code)


def create_verification_token(
    db: Session,
    user_id: str,
    token: str,
    token_type: TokenType,
    expires_delta: timedelta
) -> VerificationToken:
    """Create a verification token for a user."""
    db_token = VerificationToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token=token,
        token_type=token_type,
        expires_at=datetime.utcnow() + expires_delta,
        created_at=datetime.utcnow()
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token


def verify_email(db: Session, token: str) -> Optional[User]:
    """Verify user's email using a verification token."""
    # Get the verification token
    verification_token = db.query(VerificationToken).filter(
        and_(
            VerificationToken.token == token,
            VerificationToken.token_type == TokenType.EMAIL_VERIFICATION,
            VerificationToken.expires_at > datetime.utcnow(),
            VerificationToken.is_revoked == False
        )
    ).first()

    if not verification_token:
        return None

    # Get the user
    user = get_by_id(db, id=verification_token.user_id)
    if not user:
        return None

    # Mark the token as revoked
    verification_token.is_revoked = True
    db.add(verification_token)

    # Set user's email as verified
    user = set_email_verified(db, user=user)

    db.commit()
    db.refresh(user)
    return user


def reset_password(db: Session, token: str, new_password: str) -> Optional[User]:
    """Reset user's password using a reset token."""
    # Get the verification token
    db_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.is_revoked == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    
    if not db_token:
        return None
        
    # Get the user
    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user:
        return None
        
    # Update password and mark token as revoked
    user.hashed_password = get_password_hash(new_password)
    db_token.is_revoked = True
    db.commit()
    db.refresh(user)
    return user 