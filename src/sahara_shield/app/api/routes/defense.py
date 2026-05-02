from fastapi import APIRouter, Depends, HTTPException
from sahara_shield.app.defense.engine import make_decision
from sahara_shield.app.defense.marshal import DefenseCheckDecision, DefenseCheckRequest
from sahara_shield.app.api.deps import get_read_protected_apps_service
from sahara_shield.app.model.services import ReadProtectedAppsService

defense_router = APIRouter(
    prefix='/defense',
    tags=['defense'],
)

@defense_router.post('/check', response_model=DefenseCheckDecision)
async def check_request(
    payload: DefenseCheckRequest,
    read_protected_apps_service: ReadProtectedAppsService = Depends(get_read_protected_apps_service),
):
    '''
    Return an allow/block decision for request.

    This endpoint is intended for use by a standalone reverse proxy process.
    '''

    protected_app = await read_protected_apps_service.read_by_id(payload.protected_app_id)

    if protected_app is None:
        raise HTTPException(status_code=404, detail='Protected app not found')

    decision = make_decision(payload, protected_app)
    return decision
