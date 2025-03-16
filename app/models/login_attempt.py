from sqlalchemy import Boolean, Column, DateTime, String, Integer
from sqlalchemy.sql import func

from app.db.base_class import Base


class LoginAttempt(Base):
    """
    Model to track login attempts for rate limiting and account lockout.
    """
    __tablename__ = "login_attempts"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    ip_address = Column(String, index=True, nullable=False)
    user_agent = Column(String, nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False)

    @classmethod
    def count_recent_failed_attempts(cls, db, email, minutes=30):
        """
        Count the number of failed login attempts for a given email in the last N minutes.
        """
        from datetime import datetime, timedelta
        from sqlalchemy import and_

        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        return db.query(cls).filter(
            and_(
                cls.email == email,
                cls.success == False,
                cls.timestamp >= cutoff_time
            )
        ).count()

    @classmethod
    def is_account_locked(cls, db, email, max_attempts=5, lockout_minutes=30):
        """
        Check if an account is locked due to too many failed login attempts.
        """
        return cls.count_recent_failed_attempts(db, email, lockout_minutes) >= max_attempts 