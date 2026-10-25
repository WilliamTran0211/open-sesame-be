from typing import Optional

from redis.asyncio import BlockingConnectionPool, Redis


class RedisClient:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._pool: Optional[BlockingConnectionPool] = None
        self._client: Optional[Redis] = None

    async def connect(self) -> None:
        # Blocking pool: khi hết connection thì chờ max timeout ms thay vì raise lỗi MaxConnectionsError
        self._pool = BlockingConnectionPool.from_url(
            self.redis_url, max_connections=50, timeout=5, decode_responses=True
        )
        self._client = Redis(connection_pool=self._pool)

    async def disconnect(self) -> None:
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()

    @property
    def client(self) -> Redis:
        if not self._client:
            raise RuntimeError("Redis not connected")
        return self._client

    async def get(self, key: str) -> Optional[str]:
        return await self.client.get(key)

    async def setex(self, key: str, ttl: int, val: str) -> None:
        # ttl in sec ~ 1 hour
        return await self.client.setex(key, ttl, val)

    async def delete(self, key: str) -> None:
        return await self.client.delete(key)

    async def incr(self, key: str) -> int:
        return await self.client.incr(key)

    async def expire(self, key: str, ttl: int) -> None:
        return await self.client.expire(key, ttl)

    async def ttl(self, key: str) -> int:
        return await self.client.ttl(key)

    async def acquire_lock(self, key: str, ttl: int) -> bool:
        """
        Sử dụng cho job clean up , trong trường hợp mutiple-worker thì các worker đều chạy process riêng
        dẫn đến job clean up có thể chạy 4 lần cùng lúc (không sai nhưng tốn tài nguyên)
        SET NX EX — True nếu worker này có được lock, False nếu worker khác đang giữ.
        """
        return bool(await self.client.set(key, "1", nx=True, ex=ttl))
