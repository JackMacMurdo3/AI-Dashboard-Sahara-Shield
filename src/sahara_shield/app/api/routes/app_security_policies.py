from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, AppSecurityPolicyControllerDep

app_security_policies = APIRouter(
    prefix='/app_security_policies',
    tags=['app_security_policies'],
)

@app_security_policies.get('/me')
async def read_my_app_security_policies(user: CurrentUserDep, controller: AppSecurityPolicyControllerDep):
    return await controller.get_user_app_security_policies(user)

@app_security_policies.get('/me/protected_app/{protected_app_id:int}')
async def read_my_app_security_policies_by_protected_app_id(
    protected_app_id: int,
    user: CurrentUserDep,
    controller: AppSecurityPolicyControllerDep,
):
    return await controller.get_user_app_security_policies_by_protected_app_id(user, protected_app_id)

@app_security_policies.get('/me/{id:int}')
async def read_my_app_security_policy_by_id(
    id: int,
    user: CurrentUserDep,
    controller: AppSecurityPolicyControllerDep,
):
    return await controller.get_user_app_security_policy_by_id(user, id)
