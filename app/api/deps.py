from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional
from jose import JWTError, jwt

from app.core.config import settings
from app.db.session import get_db
from app.crud.user import get
from app.models.user import User
from app.crud import user as user_crud

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)


async def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> Optional[User]:
    """
    Get the current authenticated user based on the JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        print(f"Decoding token: {token}")
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        print(f"Token payload: {payload}")
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        print(f"User ID: {user_id}, Token type: {token_type}")
        if user_id is None or token_type != "access":
            print("Invalid user_id or token_type")
            raise credentials_exception
    except JWTError as e:
        print(f"JWT Error: {str(e)}")
        raise credentials_exception
    
    user = get(db, user_id=user_id)
    if user is None:
        print("User not found in database")
        raise credentials_exception
    print(f"Found user: {user.id} ({user.email})")
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get the current active user.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Get the current verified user.
    """
    if not current_user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )
    return current_user
