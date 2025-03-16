from pydantic import BaseModel, Field, validator


class MFAVerify(BaseModel):
    """Schema for verifying an MFA code."""
    code: str = Field(..., min_length=6, max_length=6)


class MFADisable(BaseModel):
    """Schema for disabling MFA."""
    password: str


class MFAResponse(BaseModel):
    """Schema for MFA operation response."""
    message: str 