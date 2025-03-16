from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.token import AccessToken, RefreshToken, TokenType, VerificationToken, Token
from app.models.user import User
from app.core.security import get_password_hash


def create_verification_token(
    db: Session,
    user_id: UUID,
    token: str,
    token_type: TokenType,
    expires_delta: timedelta,
) -> Token:
    """Create a verification token."""
    expires_at = datetime.utcnow() + expires_delta
    
    db_obj = Token(
        user_id=user_id,
        token_hash=token,  # We're not hashing verification tokens in this implementation
        type=token_type,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    
    return db_obj


def create_access_token(
    db: Session,
    user_id: UUID,
    token: str,
    expires_delta: timedelta,
) -> Token:
    """Create an access token entry."""
    expires_at = datetime.utcnow() + expires_delta
    
    db_obj = Token(
        user_id=user_id,
        token_hash=token,  # We're not hashing JWT tokens as they're self-contained
        type=TokenType.ACCESS,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    
    return db_obj


def create_refresh_token(
    db: Session,
    user_id: UUID,
    token: str,
    expires_delta: timedelta,
) -> Token:
    """Create a refresh token entry."""
    expires_at = datetime.utcnow() + expires_delta
    
    db_obj = Token(
        user_id=user_id,
        token_hash=token,  # We're not hashing JWT tokens as they're self-contained
        type=TokenType.REFRESH,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
        is_used=False,
    )
    
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    
    return db_obj


def get_token(
    db: Session,
    token: str,
    token_type: TokenType,
) -> Optional[Token]:
    """Get a token by its value and type."""
    return db.query(Token).filter(
        Token.token_hash == token,
        Token.type == token_type,
        Token.is_used == False,
        Token.expires_at > datetime.utcnow(),
    ).first()


def verify_token(
    db: Session,
    token: str,
    token_type: TokenType,
) -> Optional[Token]:
    """Verify a token and mark it as used."""
    db_obj = get_token(db, token, token_type)
    
    if not db_obj:
        return None
    
    # Mark the token as used for single-use tokens
    if token_type in [TokenType.EMAIL_VERIFICATION, TokenType.PASSWORD_RESET, TokenType.MFA]:
        db_obj.is_used = True
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
    
    return db_obj


def revoke_refresh_token(db: Session, token: str) -> bool:
    """Revoke a refresh token."""
    db_obj = db.query(Token).filter(
        Token.token_hash == token,
        Token.type == TokenType.REFRESH,
    ).first()
    
    if not db_obj:
        return False
    
    db_obj.is_used = True
    db.add(db_obj)
    db.commit()
    
    return True


def cleanup_expired_tokens(db: Session) -> int:
    """Remove expired tokens from the database."""
    now = datetime.utcnow()
    
    # Delete expired verification tokens
    verification_result = db.query(VerificationToken).filter(
        VerificationToken.expires_at <= now
    ).delete()
    
    # Delete expired access tokens
    access_result = db.query(AccessToken).filter(
        AccessToken.expires_at <= now
    ).delete()
    
    # Delete expired refresh tokens
    refresh_result = db.query(RefreshToken).filter(
        RefreshToken.expires_at <= now
    ).delete()
    
    db.commit()
    return verification_result + access_result + refresh_result


def is_valid_refresh_token(db: Session, token: str) -> bool:
    """Check if a refresh token is valid."""
    db_obj = get_token(db, token, TokenType.REFRESH)
    return db_obj is not None


def delete_all_user_tokens(db: Session, user_id: UUID) -> None:
    """Delete all tokens for a user."""
    db.query(Token).filter(Token.user_id == user_id).delete()
    db.commit() 