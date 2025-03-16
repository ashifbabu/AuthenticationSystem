from pydantic import BaseModel, EmailStr


class Login(BaseModel):
    email: EmailStr
    password: str


class ForgotPassword(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    token: str
    new_password: str
    confirm_password: str


class ChangePassword(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class VerifyEmail(BaseModel):
    token: str


class MFAEnable(BaseModel):
    enable: bool = True


class MFAVerify(BaseModel):
    code: str 