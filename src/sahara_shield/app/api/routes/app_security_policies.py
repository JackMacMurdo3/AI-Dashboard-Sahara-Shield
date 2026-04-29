from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, AppSecurityPolicyControllerDep

app_security_policies = APIRouter(
    prefix='/app_security_policies',
    tags=['app_security_policies'],
)


@app_security_policies.get('/me')
async def read_my_app_security_policies(user: CurrentUserDep, controller: AppSecurityPolicyControllerDep):
    return await controller.get_user_app_security_policies(user)
