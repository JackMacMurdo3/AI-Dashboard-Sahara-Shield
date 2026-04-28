from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ReadAppSecurityPoliciesServiceDep
from sahara_shield.app.model.marshal import AppSecurityPolicySchema

app_security_policies = APIRouter(
    prefix='/app_security_policies',
    tags=['app_security_policies'],
)

@app_security_policies.get('/me')
async def read_my_app_security_policies(user:CurrentUserDep, read_app_security_policies_service:ReadAppSecurityPoliciesServiceDep):
    my_app_security_policies = await read_app_security_policies_service.read_by_user_id(user.id)
    app_security_policies_info = AppSecurityPolicySchema(load_instance=False).dump(my_app_security_policies, many=True)
    return app_security_policies_info
