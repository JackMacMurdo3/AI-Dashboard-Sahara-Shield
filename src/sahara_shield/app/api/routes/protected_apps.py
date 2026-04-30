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

@protected_apps_router.get('/me/{id}')
async def read_my_protected_app_by_id(
    id: int,
    user: CurrentUserDep,
    controller: ProtectedAppControllerDep,
):
    '''
    Retrieve a protected app by ID owned by the current user.
    '''
    return await controller.get_user_protected_app_by_id(user, id)

@protected_apps_router.post('/me')
async def create_protected_app(
    user: CurrentUserDep,
    controller: ProtectedAppControllerDep,
    name: str,
    url: str,
    risk_score_severity_score_weight: float = 0.5,
    risk_score_confidence_pct_weight: float = 0.5,
    ):
    '''
    Create a new protected app for the current user.
    '''
    return await controller.create_protected_app(
        user,
        name,
        url,
        risk_score_severity_score_weight,
        risk_score_confidence_pct_weight,
    )
