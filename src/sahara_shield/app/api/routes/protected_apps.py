from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ProtectedAppControllerDep

protected_apps_router = APIRouter(
    prefix='/protected_apps',
    tags=['protected_apps'],
)

@protected_apps_router.get('/me')
async def read_my_protected_apps(user: CurrentUserDep, controller: ProtectedAppControllerDep):
    '''
    Retrieve all protected apps owned by the current user.
    '''
    return await controller.get_user_protected_apps(user)

@protected_apps_router.post('/me')
async def create_protected_app(
    user: CurrentUserDep,
    controller: ProtectedAppControllerDep,
    name: str,
    url: str,
    ):
    '''
    Create a new protected app for the current user.
    '''
    return await controller.create_protected_app(user, name, url)
