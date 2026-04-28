from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ReadProtectedAppsServiceDep
from sahara_shield.app.model.marshal import ProtectedAppSchema

protected_apps_router = APIRouter(
    prefix='/protected_apps',
    tags=['protected_apps'],
)

@protected_apps_router.get('/me')
async def read_my_protected_apps(user:CurrentUserDep, read_protected_apps_service:ReadProtectedAppsServiceDep):
    my_protected_apps = await read_protected_apps_service.read_by_owner_user_id(user.id)
    protected_apps_info = ProtectedAppSchema(load_instance=False).dump(my_protected_apps, many=True)
    return protected_apps_info
