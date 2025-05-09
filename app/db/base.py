# Import all models here so that they can be discovered by Alembic
from app.db.base_class import Base
from app.models.user import User
from app.models.token import Token, AccessToken, RefreshToken, VerificationToken
from app.models.oauth import OAuthAccount
from app.models.login_attempt import LoginAttempt

# Import all models here that are needed by Alembic 