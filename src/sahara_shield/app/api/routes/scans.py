from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ReadScansServiceDep
from sahara_shield.app.model.marshal import ScanSchema

scans_router = APIRouter(
    prefix='/scans',
    tags=['scans'],
)

@scans_router.get('/me')
async def read_my_scans(user:CurrentUserDep, read_scans_service:ReadScansServiceDep):
    user_id = user.id
    scans = await read_scans_service.read_by_user_id(user_id)
    scan_info = ScanSchema(load_instance=False).dump(scans, many=True)
    return {
        'results': scan_info
    }
