from enum import Enum
from sqlalchemy import Column, String, ForeignKey, Enum as SQLAlchemyEnum, DateTime, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base_class import Base
from uuid import UUID
from app.core.enums import OAuthProvider


class OAuthAccount(Base):
    """OAuth account model."""
    __tablename__ = "oauth_accounts"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider = Column(SQLAlchemyEnum(OAuthProvider))
    provider_user_id = Column(String, nullable=False)
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    token_type = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationship to User model
    user = relationship("User", back_populates="oauth_accounts")

    # Ensure uniqueness of provider + provider_user_id
    __table_args__ = (
        UniqueConstraint('provider', 'provider_user_id', name='uix_provider_provider_user_id'),
    ) 