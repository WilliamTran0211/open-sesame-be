from datetime import datetime, timezone
from typing import List
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.enum import MFAMethod
from app.models.user_mfa_method import UserMfaMethod
from app.repository.base import BaseRepository


class UserMfaMethodRepository(BaseRepository[UserMfaMethod]):
    def __init__(self, db: AsyncSession):
        super().__init__(UserMfaMethod, db)

    async def list_by_user(self, user_id: UUID) -> List[UserMfaMethod]:
        result = await self.db.execute(
            select(UserMfaMethod).where(UserMfaMethod.user_id == user_id)
        )
        return list(result.scalars().all())

    async def delete_by_user_method(self, user_id: UUID, method: MFAMethod) -> bool:
        result = await self.db.execute(
            delete(UserMfaMethod).where(
                UserMfaMethod.user_id == user_id, UserMfaMethod.method == method
            )
        )
        await self.db.flush()
        return result.rowcount > 0

    async def mark_used(self, id: UUID) -> None:
        await self.update(id, last_used_at=datetime.now(timezone.utc))
