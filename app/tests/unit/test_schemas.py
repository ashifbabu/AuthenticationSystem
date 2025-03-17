import pytest
from datetime import date, datetime, timedelta
from pydantic import ValidationError

from app.schemas.user import UserCreate, Gender


def test_valid_user_create():
    """Test that a valid UserCreate schema passes validation."""
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date.today() - timedelta(days=365 * 20),  # 20 years old
        "gender": Gender.MALE,
        "email": "john.doe@example.com",
        "mobile": "+8801712345678",
        "password": "secretpassword",
        "confirm_password": "secretpassword",
    }
    
    user = UserCreate(**user_data)
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.gender == Gender.MALE
    assert user.email == "john.doe@example.com"
    assert user.mobile == "+8801712345678"
    assert user.password == "secretpassword"
    assert user.confirm_password == "secretpassword"


def test_password_mismatch():
    """Test that passwords must match."""
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date.today() - timedelta(days=365 * 20),
        "gender": Gender.MALE,
        "email": "john.doe@example.com",
        "mobile": "+8801712345678",
        "password": "secretpassword",
        "confirm_password": "differentpassword",
    }
    
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**user_data)
    
    assert "passwords do not match" in str(excinfo.value)


def test_name_validation():
    """Test that names must contain only alphabetic characters."""
    user_data = {
        "first_name": "John123",
        "last_name": "Doe",
        "date_of_birth": date.today() - timedelta(days=365 * 20),
        "gender": Gender.MALE,
        "email": "john.doe@example.com",
        "mobile": "+8801712345678",
        "password": "secretpassword",
        "confirm_password": "secretpassword",
    }
    
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**user_data)
    
    assert "must contain only alphabetic characters" in str(excinfo.value)


def test_mobile_validation():
    """Test that mobile numbers must be in the correct Bangladeshi format."""
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date.today() - timedelta(days=365 * 20),
        "gender": Gender.MALE,
        "email": "john.doe@example.com",
        "mobile": "1234567890",  # Invalid format
        "password": "secretpassword",
        "confirm_password": "secretpassword",
    }
    
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**user_data)
    
    assert "must be a valid Bangladeshi phone number" in str(excinfo.value)


def test_age_validation():
    """Test that users must be at least 13 years old."""
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date.today() - timedelta(days=365 * 10),  # 10 years old
        "gender": Gender.MALE,
        "email": "john.doe@example.com",
        "mobile": "+8801712345678",
        "password": "secretpassword",
        "confirm_password": "secretpassword",
    }
    
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**user_data)
    
    assert "user must be at least 13 years old" in str(excinfo.value) 