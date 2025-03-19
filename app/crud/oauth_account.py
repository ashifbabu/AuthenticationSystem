from typing import List, Optional
from uuid import uuid4
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.crud.base import CRUDBase
from app.models.oauth import OAuthAccount
from app.schemas.oauth import OAuthAccountCreate, OAuthAccountUpdate
from app.core.enums import OAuthProvider

class CRUDOAuthAccount(CRUDBase[OAuthAccount, OAuthAccountCreate, OAuthAccountUpdate]):
    def get_by_provider_and_account_id(
        self, db: Session, *, provider: OAuthProvider, account_id: str
    ) -> Optional[OAuthAccount]:
        return db.query(OAuthAccount).filter(
            and_(
                OAuthAccount.provider == provider,
                OAuthAccount.account_id == account_id
            )
        ).first()

    def get_by_provider_and_user_id(
        self, db: Session, *, provider: OAuthProvider, user_id: str
    ) -> Optional[OAuthAccount]:
        return db.query(OAuthAccount).filter(
            and_(
                OAuthAccount.provider == provider,
                OAuthAccount.user_id == user_id
            )
        ).first()

    def get_by_user_id(
        self, db: Session, *, user_id: str
    ) -> List[OAuthAccount]:
        return db.query(OAuthAccount).filter(
            OAuthAccount.user_id == user_id
        ).all()

    def create(
        self, db: Session, *, obj_in: OAuthAccountCreate
    ) -> OAuthAccount:
        db_obj = OAuthAccount(
            id=str(uuid4()),
            provider=obj_in.provider,
            account_id=obj_in.account_id,
            account_email=obj_in.account_email,
            user_id=obj_in.user_id,
            access_token=obj_in.access_token,
            refresh_token=obj_in.refresh_token,
            expires_at=obj_in.expires_at,
            is_active=obj_in.is_active
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

oauth_crud = CRUDOAuthAccount(OAuthAccount) 