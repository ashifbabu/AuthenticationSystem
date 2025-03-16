import uuid
from typing import Any, Dict, Optional, Union
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import and_
from passlib.context import CryptContext

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def create(db: Session, *, obj_in: UserCreate) -> User:
    db_obj = User(
        id=str(uuid.uuid4()),
        first_name=obj_in.first_name,
        last_name=obj_in.last_name,
        email=obj_in.email,
        date_of_birth=obj_in.date_of_birth,
        gender=obj_in.gender,
        mobile=obj_in.mobile,
        password_hash=pwd_context.hash(obj_in.password),
        is_active=True,
        is_email_verified=False,
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
    user.password_hash = pwd_context.hash(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


def authenticate(db: Session, *, email: str, password: str) -> Optional[User]:
    """Authenticate a user by email and password."""
    user = get_by_email(db, email=email)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def set_email_verified(db: Session, *, user: User) -> User:
    """Set a user's email as verified."""
    user.is_email_verified = True
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
    user.last_login = datetime.utcnow()
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