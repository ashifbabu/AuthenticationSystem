from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, JSON, UniqueConstraint, Table, DateTime, Boolean, Enum
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.core.enums import OAuthProvider

class OAuthAccount(Base):
    """OAuth account model."""
    __tablename__ = "oauth_accounts"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    provider = Column(Enum(OAuthProvider), nullable=False)
    account_id = Column(String, nullable=False)
    account_email = Column(String, nullable=False)
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    raw_data = Column(JSON, nullable=False)

    # Relationships
    user = relationship("User", back_populates="oauth_accounts")

    # Table constraints
    __table_args__ = (
        # Ensure unique provider + account_id combination
        UniqueConstraint('provider', 'account_id', name='uix_provider_account_id'),
    ) 