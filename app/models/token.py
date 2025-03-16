from enum import Enum
from sqlalchemy import Boolean, Column, DateTime, String, ForeignKey
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class TokenType(str, Enum):
    """Token type enumeration."""
    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    MFA = "mfa"


class Token(Base):
    """Token model."""
    __tablename__ = "tokens"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    token_type = Column(SQLAlchemyEnum(TokenType), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    is_revoked = Column(Boolean, default=False)
    
    # Relationship to User model
    user = relationship("User")


class AccessToken(Token):
    """Access token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.ACCESS,
        'polymorphic_on': Token.token_type
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="access_tokens")


class RefreshToken(Token):
    """Refresh token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.REFRESH,
        'polymorphic_on': Token.token_type
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="refresh_tokens")


class VerificationToken(Token):
    """Verification token model for type discrimination."""
    __mapper_args__ = {
        'polymorphic_identity': TokenType.EMAIL_VERIFICATION,
        'polymorphic_on': Token.token_type
    }
    
    # Specify relationship back to User model
    user = relationship("User", back_populates="verification_tokens") 