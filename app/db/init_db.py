from sqlalchemy.orm import Session
from app.db.base import Base
from app.db.session import engine
from app.core.config import settings
from app.schemas.user import UserCreate
from app.crud import user as user_crud
from app.models.user import Gender

def init_db(db: Session) -> None:
    """Initialize the database."""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Create a superuser if it doesn't exist
    user = user_crud.get_by_email(db, email=settings.FIRST_SUPERUSER_EMAIL)
    if not user:
        user_in = UserCreate(
            email=settings.FIRST_SUPERUSER_EMAIL,
            password=settings.FIRST_SUPERUSER_PASSWORD,
            confirm_password=settings.FIRST_SUPERUSER_PASSWORD,
            first_name="Super",
            last_name="User",
            is_superuser=True,
            is_active=True,
            is_email_verified=True,
            gender=Gender.OTHER
        )
        user = user_crud.create(db, obj_in=user_in) 