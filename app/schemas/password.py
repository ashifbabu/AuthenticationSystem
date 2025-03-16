from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""
    email: EmailStr


class PasswordReset(BaseModel):
    """Schema for password reset."""
    token: str
    new_password: str = Field(..., min_length=8)
    
    @validator("new_password")
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


class ChangePassword(BaseModel):
    """Schema for password change."""
    current_password: str
    new_password: str = Field(..., min_length=8)
    
    @validator("new_password")
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