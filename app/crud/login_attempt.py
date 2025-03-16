from datetime import datetime
import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.login_attempt import LoginAttempt


def create(
    db: Session,
    *,
    email: str,
    ip_address: str,
    user_agent: Optional[str] = None,
    success: bool = False
) -> LoginAttempt:
    """
    Create a new login attempt record.
    """
    db_obj = LoginAttempt(
        id=str(uuid.uuid4()),
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        timestamp=datetime.utcnow()
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def get_recent_attempts(
    db: Session,
    *,
    email: str,
    minutes: int = 30
) -> List[LoginAttempt]:
    """
    Get recent login attempts for a given email.
    """
    from datetime import timedelta
    from sqlalchemy import and_

    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(LoginAttempt).filter(
        and_(
            LoginAttempt.email == email,
            LoginAttempt.timestamp >= cutoff_time
        )
    ).order_by(LoginAttempt.timestamp.desc()).all()


def get_recent_failed_attempts(
    db: Session,
    *,
    email: str,
    minutes: int = 30
) -> List[LoginAttempt]:
    """
    Get recent failed login attempts for a given email.
    """
    from datetime import timedelta
    from sqlalchemy import and_

    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(LoginAttempt).filter(
        and_(
            LoginAttempt.email == email,
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= cutoff_time
        )
    ).order_by(LoginAttempt.timestamp.desc()).all()


def count_recent_failed_attempts(
    db: Session,
    *,
    email: str,
    minutes: int = 30
) -> int:
    """
    Count recent failed login attempts for a given email.
    """
    return LoginAttempt.count_recent_failed_attempts(db, email, minutes)


def is_account_locked(
    db: Session,
    *,
    email: str,
    max_attempts: int = 5,
    lockout_minutes: int = 30
) -> bool:
    """
    Check if an account is locked due to too many failed login attempts.
    """
    return LoginAttempt.is_account_locked(db, email, max_attempts, lockout_minutes)


def cleanup_old_attempts(db: Session, *, days: int = 30) -> int:
    """
    Remove login attempt records older than the specified number of days.
    """
    from datetime import timedelta
    
    cutoff_time = datetime.utcnow() - timedelta(days=days)
    result = db.query(LoginAttempt).filter(LoginAttempt.timestamp < cutoff_time).delete()
    db.commit()
    return result 