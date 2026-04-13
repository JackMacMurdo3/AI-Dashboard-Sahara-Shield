from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ReadScansServiceDep

scans_router = APIRouter(
    prefix='/scans',
    tags=['scans'],
)

@scans_router.get('/me')
async def read_current_user_scans(user:CurrentUserDep, read_scans_service:ReadScansServiceDep):
    user_id = user.id
    scans = await read_scans_service.read_by_user_id(user_id)
    return {
        'results': scans
    }
