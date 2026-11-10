from enum import Enum


class ErrorMessage(str, Enum):
    """Error messages for authentication system"""

    # Client & Auth
    INVALID_CLIENT = "Invalid client credentials"
    INVALID_GRANT = "Invalid or expired grant"
    INVALID_REQUEST = "Invalid request format"
    UNAUTHORIZED_CLIENT = "Client not authorized"
    INVALID_SCOPE = "Invalid scope requested"
    ACCESS_DENIED = "Access denied by resource owner"
    UNSUPPORTED_MEDIA_TYPE = "Content-Type must be application/json"

    # Common errors
    NOT_FOUND = "Resource not found"
    CONFLICT = "Resource already exists"
    UNAUTHORIZED = "Authentication required"
    RATE_LIMITED = "Too many requests"

    # Verification
    INVALID_OTP = "Invalid or expired verification code"
    EMAIL_NOT_VERIFIED = "Email address has not been verified"

    # 2FA
    MFA_ALREADY_ENABLED = "Two-factor authentication is already enabled"
    MFA_NOT_ENABLED = "Two-factor authentication is not enabled"
    MFA_SETUP_NOT_STARTED = "Start 2FA setup first"
    MFA_METHOD_ALREADY_ENABLED = "This two-factor method is already enabled"
    MFA_METHOD_NOT_ENABLED = "This two-factor method is not enabled"
    INVALID_MFA_CODE = "Invalid authentication code"
    MFA_CHALLENGE_EXPIRED = "Login challenge expired or invalid — please log in again"

    # Server errors
    SERVER_ERROR = "Internal server error"
    SERVICE_UNAVAILABLE = "Service temporarily unavailable"
