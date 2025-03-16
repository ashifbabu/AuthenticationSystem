from typing import Optional
from pydantic import BaseModel
from uuid import UUID


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str


class TokenPayload(BaseModel):
    sub: Optional[UUID] = None
    exp: Optional[int] = None


class RefreshToken(BaseModel):
    refresh_token: str


class VerificationToken(BaseModel):
    token: str 