from typing import Optional
from sqlalchemy.orm import Session

from app.models.oauth import OAuthAccount
from app.schemas.oauth import OAuthProvider, OAuthAccountCreate, OAuthAccountUpdate

def get(db: Session, id: str) -> Optional[OAuthAccount]:
    """Get OAuth account by ID."""
    return db.query(OAuthAccount).filter(OAuthAccount.id == id).first()

def get_by_provider_and_account_id(
    db: Session,
    provider: OAuthProvider,
    account_id: str
) -> Optional[OAuthAccount]:
    """Get OAuth account by provider and account ID."""
    return db.query(OAuthAccount).filter(
        OAuthAccount.provider == provider,
        OAuthAccount.account_id == account_id
    ).first()

def get_by_user_and_provider(
    db: Session,
    user_id: str,
    provider: OAuthProvider
) -> Optional[OAuthAccount]:
    """Get OAuth account by user ID and provider."""
    return db.query(OAuthAccount).filter(
        OAuthAccount.user_id == user_id,
        OAuthAccount.provider == provider
    ).first()

def get_multi_by_user(
    db: Session,
    user_id: str,
    skip: int = 0,
    limit: int = 100
) -> list[OAuthAccount]:
    """Get multiple OAuth accounts by user ID."""
    return db.query(OAuthAccount).filter(
        OAuthAccount.user_id == user_id
    ).offset(skip).limit(limit).all()

def create(db: Session, obj_in: OAuthAccountCreate) -> OAuthAccount:
    """Create new OAuth account."""
    db_obj = OAuthAccount(
        provider=obj_in.provider,
        account_id=obj_in.account_id,
        account_email=obj_in.account_email,
        user_id=obj_in.user_id,
        access_token=obj_in.access_token,
        refresh_token=obj_in.refresh_token,
        expires_at=obj_in.expires_at,
        raw_data=obj_in.raw_data,
        is_active=obj_in.is_active
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def update(
    db: Session,
    db_obj: OAuthAccount,
    obj_in: OAuthAccountUpdate
) -> OAuthAccount:
    """Update OAuth account."""
    update_data = obj_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_obj, field, value)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def delete(db: Session, id: str) -> Optional[OAuthAccount]:
    """Delete OAuth account."""
    obj = db.query(OAuthAccount).get(id)
    if obj:
        db.delete(obj)
        db.commit()
    return obj

def delete_by_user_and_provider(
    db: Session,
    user_id: str,
    provider: OAuthProvider
) -> Optional[OAuthAccount]:
    """Delete OAuth account by user ID and provider."""
    obj = get_by_user_and_provider(db, user_id, provider)
    if obj:
        db.delete(obj)
        db.commit()
    return obj 