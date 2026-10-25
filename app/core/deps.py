from functools import lru_cache
from typing import Annotated, Optional

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.core.redis import RedisClient
from app.core.security import JWTHelper, OTPHelper

_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient(get_settings().REDIS_URL)
        await _redis_client.connect()
        return _redis_client
    return _redis_client


@lru_cache()
def get_jwt_helper() -> JWTHelper:
    settings = get_settings()
    return JWTHelper(secret_key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_otp_helper() -> OTPHelper:
    return OTPHelper(length=6)


# Aliases
RedisDep = Annotated[RedisClient, Depends(get_redis_client)]
JWTDep = Annotated[JWTHelper, Depends(get_jwt_helper)]
OTPDep = Annotated[OTPHelper, Depends(get_otp_helper)]
