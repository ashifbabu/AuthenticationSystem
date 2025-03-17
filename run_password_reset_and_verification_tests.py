from datetime import date, datetime, timedelta
from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Request, Query
from fastapi.testclient import TestClient
from pydantic import BaseModel, EmailStr, field_validator, Field
from enum import Enum
import uuid
import json
import secrets
from typing import Optional, Dict, Any, List


# Mock settings
class Settings:
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = 24
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 30
    FRONTEND_URL = "https://example.com"
    

settings = Settings()


# Create mock models and schemas
class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


class TokenType(str, Enum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    mobile: str
    date_of_birth: date
    gender: Gender


class UserInDB(UserBase):
    id: str
    password_hash: str
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool
    is_superuser: bool
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None


class TokenInDB(BaseModel):
    id: str
    user_id: str
    email: str
    token: str
    token_type: TokenType
    expires_at: datetime
    created_at: datetime
    is_used: bool = False


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordReset(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator("confirm_password")
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v
    
    @field_validator("new_password")
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


class EmailVerificationRequest(BaseModel):
    token: str


# Mock database
users_db = {}
tokens_db: List[TokenInDB] = []


# Password hashing mock
def get_password_hash(password: str) -> str:
    return f"hashed_{password}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hashed_password == f"hashed_{plain_password}"


# Create a mock FastAPI app
app = FastAPI()


# Mock email service
def send_verification_email(email_to: str, token: str, user: UserInDB):
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    print(f"\nSending verification email to {email_to}")
    print(f"Verification URL: {verification_url}")
    print(f"User: {user.first_name} {user.last_name}\n")


def send_password_reset_email(email_to: str, token: str, user: UserInDB):
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    print(f"\nSending password reset email to {email_to}")
    print(f"Reset URL: {reset_url}")
    print(f"User: {user.first_name} {user.last_name}")
    print(f"Token expires in {settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes\n")


# Token generation and validation
def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def create_verification_token(user_id: str, email: str) -> str:
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    
    token_obj = TokenInDB(
        id=str(uuid.uuid4()),
        user_id=user_id,
        email=email,
        token=token,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=expires_at,
        created_at=datetime.utcnow()
    )
    tokens_db.append(token_obj)
    
    return token


def create_password_reset_token(user_id: str, email: str) -> str:
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    
    token_obj = TokenInDB(
        id=str(uuid.uuid4()),
        user_id=user_id,
        email=email,
        token=token,
        token_type=TokenType.PASSWORD_RESET,
        expires_at=expires_at,
        created_at=datetime.utcnow()
    )
    tokens_db.append(token_obj)
    
    return token


def verify_token(token: str, token_type: TokenType) -> Optional[TokenInDB]:
    for token_obj in tokens_db:
        if token_obj.token == token and token_obj.token_type == token_type:
            # Check if token is expired
            if token_obj.expires_at < datetime.utcnow():
                return None
            
            # Check if token is already used
            if token_obj.is_used:
                return None
            
            return token_obj
    
    return None


# Create a few test users
def create_test_users():
    # Regular active user with email not verified
    users_db["unverified@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="Unverified",
        last_name="User",
        email="unverified@example.com",
        mobile="+8801712345678",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.MALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=False,
        mfa_enabled=False,
        is_superuser=False
    )
    
    # Regular active user with email verified
    users_db["verified@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="Verified",
        last_name="User",
        email="verified@example.com",
        mobile="+8801712345679",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.FEMALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=True,
        mfa_enabled=False,
        is_superuser=False
    )
    
    # Inactive user
    users_db["inactive@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="Inactive",
        last_name="User",
        email="inactive@example.com",
        mobile="+8801712345680",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.OTHER,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=False,
        is_email_verified=False,
        mfa_enabled=False,
        is_superuser=False
    )


# API Endpoints
@app.post("/api/v1/auth/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(request: PasswordResetRequest, background_tasks: BackgroundTasks):
    """
    Request a password reset link.
    """
    email = request.email
    
    # Don't reveal if the user exists or not (security)
    if email not in users_db:
        return {"message": "If a user with that email exists, a password reset link will be sent."}
    
    user = users_db[email]
    
    # Check if the user is active
    if not user.is_active:
        return {"message": "If a user with that email exists, a password reset link will be sent."}
    
    # Generate password reset token
    token = create_password_reset_token(user.id, email)
    
    # Send password reset email
    background_tasks.add_task(
        send_password_reset_email, 
        email_to=email,
        token=token,
        user=user
    )
    
    return {"message": "If a user with that email exists, a password reset link will be sent."}


@app.post("/api/v1/auth/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(request: PasswordReset):
    """
    Reset password using the token received via email.
    """
    # Verify the token
    token_obj = verify_token(request.token, TokenType.PASSWORD_RESET)
    if not token_obj:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    # Find the user
    email = token_obj.email
    if email not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    user = users_db[email]
    
    # Update password
    user.password_hash = get_password_hash(request.new_password)
    
    # Mark token as used
    token_obj.is_used = True
    
    # Reset failed login attempts counter
    user.failed_login_attempts = 0
    user.last_failed_login = None
    
    return {"message": "Password reset successful. You can now log in with your new password."}


@app.post("/api/v1/auth/request-verification-email", status_code=status.HTTP_202_ACCEPTED)
async def request_verification_email(request: Request, email: EmailStr = Query(...), background_tasks: BackgroundTasks = None):
    """
    Request a new verification email.
    """
    # Use a new background tasks if none was provided
    if background_tasks is None:
        background_tasks = BackgroundTasks()
    
    # Don't reveal if the user exists or not (security)
    if email not in users_db:
        return {"message": "If a user with that email exists, a verification email will be sent."}
    
    user = users_db[email]
    
    # Check if the user is active
    if not user.is_active:
        return {"message": "If a user with that email exists, a verification email will be sent."}
    
    # Check if email is already verified
    if user.is_email_verified:
        return {"message": "Email is already verified."}
    
    # Generate verification token
    token = create_verification_token(user.id, email)
    
    # Send verification email
    background_tasks.add_task(
        send_verification_email, 
        email_to=email,
        token=token,
        user=user
    )
    
    return {"message": "If a user with that email exists, a verification email will be sent."}


@app.post("/api/v1/auth/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(request: EmailVerificationRequest):
    """
    Verify email using the token received via email.
    """
    # Verify the token
    token_obj = verify_token(request.token, TokenType.EMAIL_VERIFICATION)
    if not token_obj:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    # Find the user
    email = token_obj.email
    if email not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    user = users_db[email]
    
    # Update user
    user.is_email_verified = True
    
    # Mark token as used
    token_obj.is_used = True
    
    return {"message": "Email verification successful."}


# Create a test client
client = TestClient(app)


def run_tests():
    test_count = 0
    passed_count = 0
    failed_tests = []
    
    # Create test users
    create_test_users()
    
    # Password Reset Tests
    # ------------------------------
    
    # Test 1: Request password reset for existing user
    test_count += 1
    print("\n========== Test 1: Request Password Reset (Existing User) ==========")
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "verified@example.com"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "password reset link will be sent" in data["message"]
        
        # Check that a token was created
        token_found = False
        for token in tokens_db:
            if token.email == "verified@example.com" and token.token_type == TokenType.PASSWORD_RESET:
                token_found = True
                break
        
        assert token_found, "Password reset token not created"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 1: Request Password Reset (Existing User)")
    
    # Test 2: Request password reset for non-existent user
    test_count += 1
    print("\n========== Test 2: Request Password Reset (Non-existent User) ==========")
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "password reset link will be sent" in data["message"]
        
        # Check that no token was created
        token_found = False
        for token in tokens_db:
            if token.email == "nonexistent@example.com":
                token_found = True
                break
        
        assert not token_found, "Token should not be created for non-existent user"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 2: Request Password Reset (Non-existent User)")
    
    # Test 3: Request password reset for inactive user
    test_count += 1
    print("\n========== Test 3: Request Password Reset (Inactive User) ==========")
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "inactive@example.com"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "password reset link will be sent" in data["message"]
        
        # Check that no token was created or email sent
        token_found = False
        for token in tokens_db:
            if token.email == "inactive@example.com" and token.token_type == TokenType.PASSWORD_RESET:
                token_found = True
                break
        
        assert not token_found, "Token should not be created for inactive user"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 3: Request Password Reset (Inactive User)")
    
    # For Test 4, we need to save a valid token first
    valid_reset_token = None
    for user_email in ["verified@example.com"]:
        user = users_db[user_email]
        token = create_password_reset_token(user.id, user_email)
        if user_email == "verified@example.com":
            valid_reset_token = token
    
    # Test 4: Reset password with valid token
    test_count += 1
    print("\n========== Test 4: Reset Password (Valid Token) ==========")
    try:
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_reset_token,
                "new_password": "NewStrongPassword123!",
                "confirm_password": "NewStrongPassword123!"
            }
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "message" in data
        assert "Password reset successful" in data["message"]
        
        # Check that password was updated
        user = users_db["verified@example.com"]
        assert user.password_hash == get_password_hash("NewStrongPassword123!")
        
        # Check that token was marked as used
        token_used = False
        for token in tokens_db:
            if token.token == valid_reset_token and token.is_used:
                token_used = True
                break
        
        assert token_used, "Token should be marked as used"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 4: Reset Password (Valid Token)")
    
    # Test 5: Reset password with invalid token
    test_count += 1
    print("\n========== Test 5: Reset Password (Invalid Token) ==========")
    try:
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "invalid-token",
                "new_password": "NewStrongPassword123!",
                "confirm_password": "NewStrongPassword123!"
            }
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 400
        data = response.json()
        
        assert "detail" in data
        assert "Invalid or expired token" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 5: Reset Password (Invalid Token)")
    
    # Test 6: Reset password with used token
    test_count += 1
    print("\n========== Test 6: Reset Password (Used Token) ==========")
    try:
        # Try to use the same token from Test 4 again
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_reset_token,
                "new_password": "AnotherPassword123!",
                "confirm_password": "AnotherPassword123!"
            }
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 400
        data = response.json()
        
        assert "detail" in data
        assert "Invalid or expired token" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 6: Reset Password (Used Token)")
    
    # Test 7: Reset password with weak password
    test_count += 1
    print("\n========== Test 7: Reset Password (Weak Password) ==========")
    try:
        # Create a new token for this test
        user = users_db["verified@example.com"]
        new_token = create_password_reset_token(user.id, "verified@example.com")
        
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": new_token,
                "new_password": "weakpassword",
                "confirm_password": "weakpassword"
            }
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 7: Reset Password (Weak Password)")
    
    # Test 8: Reset password with mismatched passwords
    test_count += 1
    print("\n========== Test 8: Reset Password (Mismatched Passwords) ==========")
    try:
        # Create a new token for this test
        user = users_db["verified@example.com"]
        new_token = create_password_reset_token(user.id, "verified@example.com")
        
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": new_token,
                "new_password": "StrongPassword123!",
                "confirm_password": "DifferentPassword123!"
            }
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 8: Reset Password (Mismatched Passwords)")
    
    # Email Verification Tests
    # ------------------------------
    
    # Test 9: Request verification email for unverified user
    test_count += 1
    print("\n========== Test 9: Request Verification Email (Unverified User) ==========")
    try:
        response = client.post(
            f"/api/v1/auth/request-verification-email?email=unverified@example.com"
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "verification email will be sent" in data["message"]
        
        # Check that a token was created
        token_found = False
        for token in tokens_db:
            if token.email == "unverified@example.com" and token.token_type == TokenType.EMAIL_VERIFICATION:
                token_found = True
                break
        
        assert token_found, "Verification token not created"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 9: Request Verification Email (Unverified User)")
    
    # Test 10: Request verification email for already verified user
    test_count += 1
    print("\n========== Test 10: Request Verification Email (Already Verified User) ==========")
    try:
        response = client.post(
            f"/api/v1/auth/request-verification-email?email=verified@example.com"
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "already verified" in data["message"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 10: Request Verification Email (Already Verified User)")
    
    # Test 11: Request verification email for inactive user
    test_count += 1
    print("\n========== Test 11: Request Verification Email (Inactive User) ==========")
    try:
        response = client.post(
            f"/api/v1/auth/request-verification-email?email=inactive@example.com"
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "verification email will be sent" in data["message"]
        
        # Check that no token was created or email sent
        token_found = False
        for token in tokens_db:
            if token.email == "inactive@example.com" and token.token_type == TokenType.EMAIL_VERIFICATION:
                token_found = True
                break
        
        assert not token_found, "Token should not be created for inactive user"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 11: Request Verification Email (Inactive User)")
    
    # Test 12: Request verification email for non-existent user
    test_count += 1
    print("\n========== Test 12: Request Verification Email (Non-existent User) ==========")
    try:
        response = client.post(
            f"/api/v1/auth/request-verification-email?email=nonexistent@example.com"
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 202
        data = response.json()
        
        assert "message" in data
        assert "verification email will be sent" in data["message"]
        
        # Check that no token was created
        token_found = False
        for token in tokens_db:
            if token.email == "nonexistent@example.com":
                token_found = True
                break
        
        assert not token_found, "Token should not be created for non-existent user"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 12: Request Verification Email (Non-existent User)")
    
    # For Test 13, we need to save a valid verification token
    valid_verification_token = None
    for token in tokens_db:
        if token.email == "unverified@example.com" and token.token_type == TokenType.EMAIL_VERIFICATION and not token.is_used:
            valid_verification_token = token.token
            break
    
    if not valid_verification_token:
        # Create one if not found
        user = users_db["unverified@example.com"]
        valid_verification_token = create_verification_token(user.id, "unverified@example.com")
    
    # Test 13: Verify email with valid token
    test_count += 1
    print("\n========== Test 13: Verify Email (Valid Token) ==========")
    try:
        response = client.post(
            "/api/v1/auth/verify-email",
            json={"token": valid_verification_token}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "message" in data
        assert "Email verification successful" in data["message"]
        
        # Check that user is now verified
        user = users_db["unverified@example.com"]
        assert user.is_email_verified, "User should be marked as verified"
        
        # Check that token was marked as used
        token_used = False
        for token in tokens_db:
            if token.token == valid_verification_token and token.is_used:
                token_used = True
                break
        
        assert token_used, "Token should be marked as used"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 13: Verify Email (Valid Token)")
    
    # Test 14: Verify email with invalid token
    test_count += 1
    print("\n========== Test 14: Verify Email (Invalid Token) ==========")
    try:
        response = client.post(
            "/api/v1/auth/verify-email",
            json={"token": "invalid-token"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 400
        data = response.json()
        
        assert "detail" in data
        assert "Invalid or expired token" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 14: Verify Email (Invalid Token)")
    
    # Test 15: Verify email with used token
    test_count += 1
    print("\n========== Test 15: Verify Email (Used Token) ==========")
    try:
        # Try to use the same token from Test 13 again
        response = client.post(
            "/api/v1/auth/verify-email",
            json={"token": valid_verification_token}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 400
        data = response.json()
        
        assert "detail" in data
        assert "Invalid or expired token" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 15: Verify Email (Used Token)")
    
    # Print summary
    print("\n========== Test Summary ==========")
    print(f"Tests run: {test_count}")
    print(f"Tests passed: {passed_count}")
    print(f"Tests failed: {test_count - passed_count}")
    
    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"- {test}")
    else:
        print("\nAll tests passed!")


if __name__ == "__main__":
    run_tests() 