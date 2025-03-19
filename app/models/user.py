import uuid
from datetime import date, datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import Boolean, Column, Date, DateTime, Enum as SQLAlchemyEnum, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class Gender(str, Enum):
    """Gender enumeration."""
    MALE = "male"
    FEMALE = "female"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


class User(Base):
    """User model."""
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=True)
    gender = Column(SQLAlchemyEnum(Gender), nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    mobile = Column(String, nullable=True)
    hashed_password = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_email_verified = Column(Boolean, default=False)
    is_locked = Column(Boolean, default=False)
    recent_failed_attempts = Column(Integer, default=0)
    mfa_secret = Column(String, nullable=True)
    mfa_qr_code = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")
    access_tokens = relationship("AccessToken", back_populates="user", cascade="all, delete-orphan", overlaps="tokens")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan", overlaps="tokens")
    verification_tokens = relationship("VerificationToken", back_populates="user", cascade="all, delete-orphan", overlaps="tokens")
    oauth_state_tokens = relationship("OAuthStateToken", back_populates="user", cascade="all, delete-orphan", overlaps="tokens")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan", overlaps="tokens") 