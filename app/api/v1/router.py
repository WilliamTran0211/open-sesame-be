from fastapi import APIRouter

from .endpoints import auth, client, mfa, oauth, scope, user

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(user.router, prefix="/users", tags=["users"])
api_router.include_router(mfa.router, prefix="/users/me/2fa", tags=["2fa"])
api_router.include_router(oauth.router, prefix="/oauth", tags=["oauth"])
api_router.include_router(client.router, prefix="/clients", tags=["clients"])
api_router.include_router(scope.router, prefix="/scopes", tags=["scopes"])
