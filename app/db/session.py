from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# Create engine for PostgreSQL database
engine = create_engine(settings.DATABASE_URI, pool_pre_ping=True)

# Create a session factory that will be used to create new database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 