import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Column, DateTime, Enum as SQLAlchemyEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class OAuthProvider(str, Enum):
    GOOGLE = "google"
    FACEBOOK = "facebook"


class OAuthAccount(Base):
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    provider = Column(SQLAlchemyEnum(OAuthProvider), nullable=False)
    provider_user_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="oauth_accounts") 