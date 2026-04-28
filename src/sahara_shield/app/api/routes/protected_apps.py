from fastapi import APIRouter, HTTPException
from sahara_shield.app.api.deps import CurrentUserDep, ReadProtectedAppsServiceDep, CreateProtectedAppServiceDep
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

@protected_apps_router.post('/me')
async def create_protected_app(user:CurrentUserDep, create_protected_app_service:CreateProtectedAppServiceDep, name:str, url:str):
    try:
        protected_app = await create_protected_app_service.create(owner_user_id=user.id, name=name, url=url)
        protected_app_info = ProtectedAppSchema(load_instance=False).dump(protected_app)
        return protected_app_info
    except Exception as e:
        raise HTTPException(status_code=409, detail=str(e))
