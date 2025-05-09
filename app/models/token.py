from datetime import datetime
from enum import Enum
from sqlalchemy import Boolean, Column, DateTime, String, ForeignKey
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base_class import Base
from uuid import uuid4
from app.core.enums import OAuthProvider


class TokenType(str, Enum):
    """Token type enumeration."""
    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    MFA = "mfa"
    OAUTH_STATE = "oauth_state"


class Token(Base):
    """Base token model."""
    __tablename__ = "tokens"
    __table_args__ = {'extend_existing': True}

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    token = Column(String, nullable=False)
    token_type = Column(SQLAlchemyEnum(TokenType), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    provider = Column(SQLAlchemyEnum(OAuthProvider), nullable=True)
    redirect_uri = Column(String, nullable=True)
    
    # Relationship to User model
    user = relationship("User", back_populates="tokens", overlaps="access_tokens,refresh_tokens,verification_tokens,oauth_state_tokens")

    __mapper_args__ = {
        "polymorphic_identity": None,
        "polymorphic_on": token_type
    }


class AccessToken(Token):
    """Access token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.ACCESS
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="access_tokens", overlaps="tokens")


class RefreshToken(Token):
    """Refresh token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.REFRESH
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="refresh_tokens", overlaps="tokens")


class VerificationToken(Token):
    """Verification token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.EMAIL_VERIFICATION
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="verification_tokens", overlaps="tokens")


class OAuthStateToken(Token):
    """OAuth state token model."""
    __mapper_args__ = {'polymorphic_identity': TokenType.OAUTH_STATE}
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="oauth_state_tokens", overlaps="tokens")


class PasswordResetToken(Token):
    """Password reset token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.PASSWORD_RESET
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="password_reset_tokens", overlaps="tokens")