from datetime import date, datetime, timedelta
from fastapi import FastAPI, HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.testclient import TestClient
from pydantic import BaseModel, EmailStr, validator, Field
from enum import Enum
import uuid
import json
from typing import Optional, Dict, Any


# Mock settings
class Settings:
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 30
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    

settings = Settings()


# Create mock models and schemas
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


class UserInDB(UserBase):
    id: str
    password_hash: str
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool
    is_superuser: bool
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


class LoginAttempt(BaseModel):
    email: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    success: bool


# Mock database
users_db = {}
login_attempts_db = []


# Password hashing mock
def get_password_hash(password: str) -> str:
    return f"hashed_{password}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hashed_password == f"hashed_{plain_password}"


# Create a mock FastAPI app
app = FastAPI()
background_tasks = BackgroundTasks()


# Mock email service
def send_security_notification_email(email_to: str, event_type: str, details: dict, username: str):
    print(f"\nSending security notification to {email_to}")
    print(f"Event type: {event_type}")
    print(f"Details: {json.dumps(details, default=str)}")
    print(f"Username: {username}\n")


# Create a few test users
def create_test_users():
    # Regular active user with email verified
    users_db["user@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="Test",
        last_name="User",
        email="user@example.com",
        mobile="+8801712345678",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.MALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=True,
        mfa_enabled=False,
        is_superuser=False
    )
    
    # User with email not verified
    users_db["unverified@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="Unverified",
        last_name="User",
        email="unverified@example.com",
        mobile="+8801712345679",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.FEMALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=False,
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
        is_email_verified=True,
        mfa_enabled=False,
        is_superuser=False
    )
    
    # User with MFA enabled
    users_db["mfa@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="MFA",
        last_name="User",
        email="mfa@example.com",
        mobile="+8801712345681",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.MALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=True,
        mfa_enabled=True,
        is_superuser=False
    )
    
    # User with previous failed login attempts
    users_db["lockedout@example.com"] = UserInDB(
        id=str(uuid.uuid4()),
        first_name="LockedOut",
        last_name="User",
        email="lockedout@example.com",
        mobile="+8801712345682",
        date_of_birth=date(1990, 1, 1),
        gender=Gender.FEMALE,
        password_hash=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_email_verified=True,
        mfa_enabled=False,
        is_superuser=False,
        failed_login_attempts=settings.MAX_LOGIN_ATTEMPTS,
        last_failed_login=datetime.utcnow()
    )


def is_account_locked(email: str) -> bool:
    if email not in users_db:
        return False
    
    user = users_db[email]
    
    if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
        if user.last_failed_login:
            lockout_time = user.last_failed_login + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            if datetime.utcnow() < lockout_time:
                return True
            # Reset counter if lockout period has passed
            user.failed_login_attempts = 0
            return False
    return False


def record_login_attempt(email: str, ip_address: str, user_agent: str, success: bool):
    login_attempts_db.append(
        LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            success=success
        )
    )
    
    # If login failed, increment the counter
    if not success and email in users_db:
        user = users_db[email]
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.utcnow()


@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible login endpoint.
    """
    email = form_data.username
    password = form_data.password
    
    # Mock request info
    ip_address = "192.168.1.1"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/105.0.0.0"
    
    # Check if the account is locked
    if is_account_locked(email):
        # Record the failed attempt
        record_login_attempt(email, ip_address, user_agent, False)
        
        # Send notification if user exists
        if email in users_db:
            user = users_db[email]
            background_tasks.add_task(
                send_security_notification_email,
                email_to=email,
                event_type="account_locked",
                details={
                    "timestamp": datetime.utcnow(),
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "location": "Unknown (IP geolocation not implemented)",
                },
                username=user.first_name,
            )
        
        # Return an error
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed login attempts. "
                   f"Please try again after {settings.ACCOUNT_LOCKOUT_MINUTES} minutes or reset your password.",
        )
    
    # Check if user exists
    if email not in users_db:
        # Record the failed attempt
        record_login_attempt(email, ip_address, user_agent, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = users_db[email]
    
    # Verify password
    if not verify_password(password, user.password_hash):
        # Record the failed attempt
        record_login_attempt(email, ip_address, user_agent, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if the user is active
    if not user.is_active:
        # Record the failed attempt
        record_login_attempt(email, ip_address, user_agent, False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    
    # Check if email is verified
    if not user.is_email_verified:
        # Record the failed attempt
        record_login_attempt(email, ip_address, user_agent, False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email before logging in.",
        )
    
    # Create tokens
    access_token = f"access_token_{user.id}_{uuid.uuid4()}"
    refresh_token = f"refresh_token_{user.id}_{uuid.uuid4()}"
    
    # Reset failed login attempts counter
    user.failed_login_attempts = 0
    user.last_failed_login = None
    
    # Record the successful login
    record_login_attempt(email, ip_address, user_agent, True)
    
    # Check if this is a login from a new IP or device
    is_new_device = True
    for attempt in login_attempts_db:
        if (attempt.email == email and 
            attempt.success and 
            attempt.ip_address == ip_address and 
            attempt.user_agent == user_agent and
            attempt.timestamp < datetime.utcnow() - timedelta(minutes=5)):
            is_new_device = False
            break
    
    # Send notification if this is a new device
    if is_new_device:
        background_tasks.add_task(
            send_security_notification_email,
            email_to=email,
            event_type="login_attempt",
            details={
                "timestamp": datetime.utcnow(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "location": "Unknown (IP geolocation not implemented)",
                "status": "Successful login from new device or location",
            },
            username=user.first_name,
        )
    
    # For MFA-enabled users, we'd return a different response here
    # But for this mock test, we'll just return the tokens
    if user.mfa_enabled:
        # In a real implementation, we'd return a temporary token
        # that would be used to verify the MFA code
        # For now, we'll just note that MFA is required
        print(f"MFA is required for user {email}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }


# Create a test client
client = TestClient(app)


def run_tests():
    test_count = 0
    passed_count = 0
    failed_tests = []
    
    # Create test users
    create_test_users()
    
    # Test 1: Successful login
    test_count += 1
    print("\n========== Test 1: Successful Login ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "user@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 1: Successful Login")
    
    # Test 2: Failed login with wrong password
    test_count += 1
    print("\n========== Test 2: Wrong Password ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "user@example.com", "password": "WrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 401
        data = response.json()
        
        assert "detail" in data
        assert "Incorrect email or password" in data["detail"]
        
        # Check that failed login was recorded
        user = users_db["user@example.com"]
        assert user.failed_login_attempts == 1
        assert user.last_failed_login is not None
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 2: Wrong Password")
    
    # Test 3: Login to a non-existent account
    test_count += 1
    print("\n========== Test 3: Non-existent Account ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "nonexistent@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 401
        data = response.json()
        
        assert "detail" in data
        assert "Incorrect email or password" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 3: Non-existent Account")
    
    # Test 4: Login to an inactive account
    test_count += 1
    print("\n========== Test 4: Inactive Account ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "inactive@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 403
        data = response.json()
        
        assert "detail" in data
        assert "Inactive user" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 4: Inactive Account")
    
    # Test 5: Login to an unverified account
    test_count += 1
    print("\n========== Test 5: Unverified Email ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "unverified@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 403
        data = response.json()
        
        assert "detail" in data
        assert "Email not verified" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 5: Unverified Email")
    
    # Test 6: Account lockout after multiple failed attempts
    test_count += 1
    print("\n========== Test 6: Account Lockout ==========")
    try:
        # We'll use a fresh user for this test
        test_email = "lockout_test@example.com"
        users_db[test_email] = UserInDB(
            id=str(uuid.uuid4()),
            first_name="Lockout",
            last_name="Test",
            email=test_email,
            mobile="+8801712345683",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            password_hash=get_password_hash("StrongPassword123!"),
            is_active=True,
            is_email_verified=True,
            mfa_enabled=False,
            is_superuser=False
        )
        
        # Make MAX_LOGIN_ATTEMPTS failed login attempts
        for i in range(settings.MAX_LOGIN_ATTEMPTS):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": test_email, "password": "WrongPassword123!"}
            )
            assert response.status_code == 401
            print(f"Failed login attempt {i+1}: Status code {response.status_code}")
        
        # Try one more time, should be locked out
        response = client.post(
            "/api/v1/auth/login",
            data={"username": test_email, "password": "WrongPassword123!"}
        )
        print(f"Lockout status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 429
        data = response.json()
        
        assert "detail" in data
        assert "Account temporarily locked" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 6: Account Lockout")
    
    # Test 7: Already locked account
    test_count += 1
    print("\n========== Test 7: Already Locked Account ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "lockedout@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 429
        data = response.json()
        
        assert "detail" in data
        assert "Account temporarily locked" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 7: Already Locked Account")
    
    # Test 8: Login with MFA enabled account
    test_count += 1
    print("\n========== Test 8: MFA Enabled Account ==========")
    try:
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "mfa@example.com", "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # For the mock, we're returning tokens directly,
        # but we're printing a message in the mock implementation
        # In a real implementation, we'd return a 200 with a temporary token
        # or a 202 indicating MFA is required
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 8: MFA Enabled Account")
    
    # Test 9: Successful login resets failed attempts counter
    test_count += 1
    print("\n========== Test 9: Successful Login Resets Failed Attempts Counter ==========")
    try:
        # We'll use a fresh user for this test
        test_email = "reset_counter@example.com"
        users_db[test_email] = UserInDB(
            id=str(uuid.uuid4()),
            first_name="Reset",
            last_name="Counter",
            email=test_email,
            mobile="+8801712345684",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            password_hash=get_password_hash("StrongPassword123!"),
            is_active=True,
            is_email_verified=True,
            mfa_enabled=False,
            is_superuser=False,
            failed_login_attempts=3,  # Start with some failed attempts
            last_failed_login=datetime.utcnow() - timedelta(minutes=5)
        )
        
        # Successful login
        response = client.post(
            "/api/v1/auth/login",
            data={"username": test_email, "password": "StrongPassword123!"}
        )
        print(f"Status code: {response.status_code}")
        
        assert response.status_code == 200
        
        # Check that failed login counter was reset
        user = users_db[test_email]
        assert user.failed_login_attempts == 0
        assert user.last_failed_login is None
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 9: Successful Login Resets Failed Attempts Counter")
    
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