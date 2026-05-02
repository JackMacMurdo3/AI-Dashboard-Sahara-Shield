'''
Defines FastAPI APIRouter instance to group all endpoints
'''

from fastapi import APIRouter
from sahara_shield.app.api.routes.users import users_router
from sahara_shield.app.api.routes.auth import auth_router
from sahara_shield.app.api.routes.protected_apps import protected_apps_router
from sahara_shield.app.api.routes.app_security_policies import app_security_policies
from sahara_shield.app.api.routes.flagged_requests import flagged_requests_router
from sahara_shield.app.api.routes.security_events import security_events_router
from sahara_shield.app.api.routes.defense import defense_router

api_router = APIRouter()
api_router.include_router(users_router)
api_router.include_router(auth_router)
api_router.include_router(protected_apps_router)
api_router.include_router(app_security_policies)
api_router.include_router(flagged_requests_router)
api_router.include_router(security_events_router)
api_router.include_router(defense_router)
