from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, SecurityEventsControllerDep

security_events_router = APIRouter(
    prefix='/security_events',
    tags=['security_events'],
)


@security_events_router.get('/me')
async def read_my_security_events(user: CurrentUserDep, controller: SecurityEventsControllerDep):
    return await controller.get_user_security_events(user)