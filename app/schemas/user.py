from datetime import date
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, validator


class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    mobile: str
    date_of_birth: date
    gender: Gender


class UserCreate(UserBase):
    password: str
    confirm_password: str

    @validator("confirm_password")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile: Optional[str] = None
    date_of_birth: Optional[date] = None
    gender: Optional[Gender] = None


class User(UserBase):
    id: str
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool
    is_superuser: bool

    class Config:
        from_attributes = True


class UserResponse(User):
    """Alias for User schema for API responses."""
    pass


class UserInDB(UserBase):
    id: str
    password_hash: str
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool
    is_superuser: bool

    class Config:
        from_attributes = True 