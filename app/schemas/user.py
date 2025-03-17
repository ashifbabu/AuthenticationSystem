from datetime import date, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, validator, Field


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
    password: str = Field(..., min_length=8)
    confirm_password: str

    @validator("confirm_password")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v
    
    @validator("password")
    def password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(not c.isalnum() for c in v)
        
        if not (has_upper and has_lower and has_digit and has_special):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        
        return v
    
    @validator("first_name", "last_name")
    def validate_names(cls, v):
        """Validate that names contain only alphabetic characters."""
        if not v.isalpha():
            raise ValueError("Name must contain only alphabetic characters")
        return v.title()
    
    @validator("mobile")
    def validate_mobile(cls, v):
        """Validate Bangladeshi phone number format."""
        import re
        pattern = r"^\+880\d{10}$"
        if not re.match(pattern, v):
            raise ValueError("Mobile must be in Bangladeshi format (+880XXXXXXXXXX)")
        return v
    
    @validator("date_of_birth")
    def validate_age(cls, v):
        """Validate that user is at least 13 years old."""
        today = datetime.now().date()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 13:
            raise ValueError("User must be at least 13 years old")
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