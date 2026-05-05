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


@app_security_policies.post('/me')
async def create_app_security_policy(
    user: CurrentUserDep,
    controller: AppSecurityPolicyControllerDep,
    protected_app_id: int,
    http_method: str,
    route_pattern: str,
    name: str | None = None,
    mode: str | None = None,
    aggregation_strategy_key: str | None = None,
    decision_engine_key: str | None = None,
    active: bool = True,
    priority: int = 100,
    action_score_threshold: int = 70,
):
    return await controller.create_app_security_policy(
        user,
        protected_app_id,
        http_method,
        route_pattern,
        name,
        mode,
        aggregation_strategy_key,
        decision_engine_key,
        active,
        priority,
        action_score_threshold,
    )
