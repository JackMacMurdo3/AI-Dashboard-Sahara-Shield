'''
Defines FastAPI APIRouter instance to group all endpoints
'''

from fastapi import APIRouter
from sahara_shield.app.api.routes.users import users_router
from sahara_shield.app.api.routes.auth import auth_router

api_router = APIRouter()
api_router.include_router(users_router)
api_router.include_router(auth_router)
