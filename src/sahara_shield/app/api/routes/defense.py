from fastapi import APIRouter
from sahara_shield.app.defense.marshal import SecurityDecision, InterceptedRequest
from sahara_shield.app.api.deps import SecurityDecisionControllerDep

defense_router = APIRouter(
    prefix='/defense',
    tags=['defense'],
)

@defense_router.post('/check', response_model=SecurityDecision)
async def check_request(
    req: InterceptedRequest,
    security_decision_controller: SecurityDecisionControllerDep,
):
    '''
    Return an allow/block decision for request.

    This endpoint is intended for use by a standalone reverse proxy process.
    '''

    return await security_decision_controller.get_security_decision(req)
