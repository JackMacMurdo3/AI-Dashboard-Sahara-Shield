from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, FlaggedRequestsControllerDep

flagged_requests_router = APIRouter(
    prefix='/flagged_requests',
    tags=['flagged_requests'],
)

@flagged_requests_router.get('/me')
async def read_my_flagged_requests(user: CurrentUserDep, controller: FlaggedRequestsControllerDep):
    return await controller.get_user_flagged_requests(user)
