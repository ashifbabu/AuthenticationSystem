from sqlalchemy import Column, String, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class OAuthProvider(str):
    """OAuth provider enumeration."""
    GOOGLE = "google"
    FACEBOOK = "facebook"


class OAuthAccount(Base):
    """OAuth account model."""
    __tablename__ = "oauth_accounts"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider = Column(String, nullable=False)  # "google" or "facebook"
    provider_user_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now())

    # Relationship to User model
    user = relationship("User", back_populates="oauth_accounts")

    # Ensure uniqueness of provider + provider_user_id
    __table_args__ = (
        {"schema": "public"},
    ) 