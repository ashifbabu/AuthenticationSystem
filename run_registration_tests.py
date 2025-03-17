from datetime import date, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, EmailStr, validator, Field
from enum import Enum
import uuid


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
        from datetime import datetime
        today = datetime.now().date()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 13:
            raise ValueError("User must be at least 13 years old")
        return v


class UserResponse(UserBase):
    id: str
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True


# Create mock database for email uniqueness checking
registered_emails = set()


# Create a mock FastAPI app
app = FastAPI()


@app.post("/api/v1/auth/register", response_model=UserResponse)
def register_user(user_in: UserCreate):
    """
    Register a new user.
    """
    # Check if a user with the given email already exists
    if user_in.email in registered_emails:
        raise HTTPException(
            status_code=409,
            detail="A user with this email already exists",
        )
    
    # Add email to registered emails
    registered_emails.add(user_in.email)
    
    # Create a mock user
    user = UserResponse(
        id=str(uuid.uuid4()),
        first_name=user_in.first_name,
        last_name=user_in.last_name,
        email=user_in.email,
        mobile=user_in.mobile,
        date_of_birth=user_in.date_of_birth,
        gender=user_in.gender,
        is_active=True,
        is_email_verified=False,
        mfa_enabled=False
    )
    
    return user


# Create a test client
client = TestClient(app)


def run_tests():
    test_count = 0
    passed_count = 0
    failed_tests = []
    
    # Test 1: Successful registration
    test_count += 1
    print("\n========== Test 1: Successful Registration ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),  # 25 years ago
            "gender": Gender.MALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",  # Unique email
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["first_name"] == user_data["first_name"].title()
        assert data["last_name"] == user_data["last_name"].title()
        assert data["email"] == user_data["email"]
        assert "id" in data
        assert data["is_active"] is True
        assert data["is_email_verified"] is False
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 1: Successful Registration")
    
    # Test 2: Password Mismatch
    test_count += 1
    print("\n========== Test 2: Password Mismatch ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.FEMALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "DifferentPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("password" in str(error["loc"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 2: Password Mismatch")
    
    # Test 3: Duplicate Email
    test_count += 1
    print("\n========== Test 3: Duplicate Email ==========")
    try:
        email = f"test.user.{uuid.uuid4()}@example.com"
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.MALE.value,
            "email": email,
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        # First registration
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"First registration status: {response.status_code}")
        
        assert response.status_code == 200
        
        # Second registration with same email
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Second registration status: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 409
        data = response.json()
        
        assert "detail" in data
        assert "already exists" in data["detail"]
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 3: Duplicate Email")
    
    # Test 4: Invalid Email Format
    test_count += 1
    print("\n========== Test 4: Invalid Email Format ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.MALE.value,
            "email": "invalid-email-format",  # Invalid email format
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("email" in str(error["loc"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 4: Invalid Email Format")
    
    # Test 5: Underage User
    test_count += 1
    print("\n========== Test 5: Underage User ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 12)),  # 12 years old
            "gender": Gender.MALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("date_of_birth" in str(error["loc"]) for error in data["detail"])
        assert any("User must be at least 13 years old" in str(error["msg"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 5: Underage User")
    
    # Test 6: Invalid Mobile Format
    test_count += 1
    print("\n========== Test 6: Invalid Mobile Format ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.MALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",
            "mobile": "1234567890",  # Invalid Bangladeshi format
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("mobile" in str(error["loc"]) for error in data["detail"])
        assert any("Bangladeshi format" in str(error["msg"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 6: Invalid Mobile Format")
    
    # Test 7: Weak Password
    test_count += 1
    print("\n========== Test 7: Weak Password ==========")
    try:
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.MALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",
            "mobile": "+8801712345678",
            "password": "password",  # Weak password
            "confirm_password": "password"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("password" in str(error["loc"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 7: Weak Password")
    
    # Test 8: Invalid Name Format
    test_count += 1
    print("\n========== Test 8: Invalid Name Format ==========")
    try:
        user_data = {
            "first_name": "Test123",  # Name with numbers
            "last_name": "User",
            "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
            "gender": Gender.MALE.value,
            "email": f"test.user.{uuid.uuid4()}@example.com",
            "mobile": "+8801712345678",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert any("first_name" in str(error["loc"]) for error in data["detail"])
        assert any("alphabetic characters" in str(error["msg"]) for error in data["detail"])
        
        print("Test PASSED")
        passed_count += 1
    except Exception as e:
        print(f"Test FAILED: {str(e)}")
        failed_tests.append("Test 8: Invalid Name Format")
    
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