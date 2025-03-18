from typing import Optional
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.oauth import OAuthAccount, OAuthProvider
from app.models.user import User


def get_by_provider_and_user(
    db: Session, provider: OAuthProvider, provider_user_id: str
) -> Optional[OAuthAccount]:
    """Get an OAuth account by provider and provider user ID."""
    return db.query(OAuthAccount).filter(
        OAuthAccount.provider == provider,
        OAuthAccount.provider_user_id == provider_user_id,
    ).first()


def get_by_user_id_and_provider(
    db: Session, user_id: UUID, provider: OAuthProvider
) -> Optional[OAuthAccount]:
    """Get an OAuth account by user ID and provider."""
    return db.query(OAuthAccount).filter(
        OAuthAccount.user_id == user_id,
        OAuthAccount.provider == provider,
    ).first()


def create(
    db: Session, 
    user_id: UUID, 
    provider: OAuthProvider, 
    provider_user_id: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    expires_at: Optional[datetime] = None
) -> OAuthAccount:
    """Create a new OAuth account."""
    db_obj = OAuthAccount(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def get_or_create(
    db: Session, 
    user_id: UUID, 
    provider: OAuthProvider, 
    provider_user_id: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    expires_at: Optional[datetime] = None
) -> OAuthAccount:
    """Get an existing OAuth account or create a new one."""
    oauth_account = get_by_user_id_and_provider(db, user_id, provider)
    
    if oauth_account:
        # Update token data if provided
        if access_token:
            oauth_account.access_token = access_token
        if refresh_token:
            oauth_account.refresh_token = refresh_token
        if expires_at:
            oauth_account.expires_at = expires_at
            
        # Check if the provider_user_id has changed
        if oauth_account.provider_user_id != provider_user_id:
            oauth_account.provider_user_id = provider_user_id
            
        db.add(oauth_account)
        db.commit()
        db.refresh(oauth_account)
        return oauth_account
    
    return create(
        db, 
        user_id, 
        provider, 
        provider_user_id,
        access_token,
        refresh_token,
        expires_at
    )


def delete(db: Session, oauth_account_id: UUID) -> None:
    """Delete an OAuth account."""
    db.query(OAuthAccount).filter(OAuthAccount.id == oauth_account_id).delete()
    db.commit() 