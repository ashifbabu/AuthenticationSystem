import pytest
from datetime import date, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.testclient import TestClient
from pydantic import BaseModel, EmailStr, validator
from enum import Enum
from typing import Optional
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
    password: str
    confirm_password: str

    @validator("confirm_password")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        
        return v
    
    @validator("first_name", "last_name")
    def validate_names(cls, v):
        if not v.isalpha():
            raise ValueError("Names must contain only alphabetic characters")
        return v.title()
    
    @validator("mobile")
    def validate_mobile(cls, v):
        # Validate Bangladeshi phone number format: +880XXXXXXXXXX
        if not v.startswith("+880") or len(v) != 14 or not v[4:].isdigit():
            raise ValueError("Mobile must be in Bangladeshi format (+880XXXXXXXXXX)")
        return v
    
    @validator("date_of_birth")
    def validate_age(cls, v):
        from datetime import datetime
        today = datetime.now().date()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 13:
            raise ValueError("User must be at least 13 years old")
        return v
    
    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        # More validations could be added here
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


def test_register_user_success():
    """Test successful user registration."""
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
    
    assert response.status_code == 200, f"Response: {response.text}"
    data = response.json()
    
    # Verify response data
    assert data["first_name"] == user_data["first_name"].title()  # Title case due to validator
    assert data["last_name"] == user_data["last_name"].title()
    assert data["email"] == user_data["email"]
    assert "id" in data
    assert data["is_active"] is True
    assert data["is_email_verified"] is False


def test_register_user_password_mismatch():
    """Test registration with password mismatch."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.FEMALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "DifferentPassword123!"  # Different password
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("password" in str(error["loc"]) for error in data["detail"])


def test_register_user_duplicate_email():
    """Test registration with an email that already exists."""
    # First registration
    email = f"test.user.{uuid.uuid4()}@example.com"
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": email,  # Use the same email for both registrations
        "mobile": "+8801712345678",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }
    
    # First registration should succeed
    response = client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 200, f"First registration failed: {response.text}"
    
    # Second registration with same email should fail
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 409, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert "already exists" in data["detail"]


def test_register_user_invalid_email():
    """Test registration with invalid email format."""
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
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("email" in str(error["loc"]) for error in data["detail"])


def test_register_user_underage():
    """Test registration with a user who is too young."""
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
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("date_of_birth" in str(error["loc"]) for error in data["detail"])


def test_register_user_invalid_mobile():
    """Test registration with invalid mobile format."""
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
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("mobile" in str(error["loc"]) for error in data["detail"])


def test_register_user_weak_password():
    """Test registration with a weak password."""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": str(date.today() - timedelta(days=365 * 25)),
        "gender": Gender.MALE.value,
        "email": f"test.user.{uuid.uuid4()}@example.com",
        "mobile": "+8801712345678",
        "password": "pass",  # Weak password
        "confirm_password": "pass"
    }
    
    response = client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("password" in str(error["loc"]) for error in data["detail"])


def test_register_user_invalid_name():
    """Test registration with invalid name format (containing numbers or special characters)."""
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
    
    assert response.status_code == 422, f"Response: {response.text}"
    data = response.json()
    
    # Verify error response
    assert "detail" in data
    assert any("first_name" in str(error["loc"]) for error in data["detail"]) 