from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, SecurityEventsControllerDep

security_events_router = APIRouter(
    prefix='/security_events',
    tags=['security_events'],
)


@security_events_router.get('/me')
async def read_my_security_events(user: CurrentUserDep, controller: SecurityEventsControllerDep):
    return await controller.get_user_security_events(user)

@security_events_router.get('/me/protected_app/{protected_app_id}')
async def read_my_security_events_by_protected_app_id(protected_app_id:int, user:CurrentUserDep, controller: SecurityEventsControllerDep):
    return await controller.get_user_protected_app_security_events(user, protected_app_id)
