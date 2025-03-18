import uuid
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from sqlalchemy import and_
from passlib.context import CryptContext

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.models.token import VerificationToken, TokenType
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
        password_hash=get_password_hash(obj_in.password) if obj_in.password else None,
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
    user.password_hash = get_password_hash(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, *, email: str, password: str) -> Optional[User]:
    """Authenticate a user by email and password."""
    user = get_by_email(db, email=email)
    if not user:
        return None
    if not user.password_hash:  # OAuth user without password
        return None
    if not verify_password(password, user.password_hash):
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
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()


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
    user.mfa_enabled = enable
    user.updated_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


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
        expires_at=datetime.utcnow() + expires_delta
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token 