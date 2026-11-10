# app/core/security.py

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import jwt
import pyotp
from cryptography.fernet import Fernet
from passlib.context import CryptContext

RECOVERY_CODE_COUNT = 8


class PasswordHelper:
    _context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hash(cls, password: str) -> str:
        return cls._context.hash(password)

    @classmethod
    def verify(cls, plain: str, hashed: str) -> bool:
        try:
            return cls._context.verify(plain, hashed)
        except (ValueError, TypeError):
            return False


class TokenHelper:
    @staticmethod
    def hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def generate() -> str:
        # auto-gen random token
        return secrets.token_urlsafe(32)


class JWTHelper:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create(
        self,
        subject: str,
        expires_delta: timedelta = timedelta(hours=1),
        token_type: str = "access",
        **claims,
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(subject),
            "iat": now,
            "exp": now + expires_delta,
            "type": token_type,
            **claims,
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.InvalidTokenError:
            return None


class OTPHelper:
    def __init__(self, length: int = 6):
        self.length = length

    def generate(self) -> Tuple[str, str]:
        plain = "".join(str(secrets.randbelow(10)) for _ in range(self.length))
        hashed = hashlib.sha256(plain.encode()).hexdigest()
        return plain, hashed

    def verify(self, plain: str, hashed: str) -> bool:
        computed = hashlib.sha256(plain.encode()).hexdigest()
        return hmac.compare_digest(computed, hashed)


class SecurityHelper:
    @staticmethod
    def hash_sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())

    @staticmethod
    def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
        """RFC 7636 S256 verification only — 'plain' method is not supported."""
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(computed_challenge, code_challenge)


class TotpHelper:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(email: str, secret: str, issuer: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        return pyotp.TOTP(secret).verify(code, valid_window=1)


class RecoveryCodeHelper:
    @staticmethod
    def generate() -> Tuple[List[str], List[str]]:
        """Returns (raw codes to show the user, hashes to store)."""
        raw_codes = [TokenHelper.generate()[:10] for _ in range(RECOVERY_CODE_COUNT)]
        hashes = [TokenHelper.hash(code) for code in raw_codes]
        return raw_codes, hashes

    @staticmethod
    def consume(stored_hashes: List[str], code: str) -> List[str] | None:
        """Returns the hash list with the matching code removed, or None if
        the code didn't match any stored hash."""
        code_hash = TokenHelper.hash(code)
        if code_hash not in stored_hashes:
            return None
        remaining = list(stored_hashes)
        remaining.remove(code_hash)
        return remaining
