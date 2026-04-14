from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, ReadEvidenceServiceDep
from sahara_shield.app.model.marshal import EvidenceSchema


evidence_router = APIRouter(
    prefix='/evidence',
    tags=['evidence'],
)

@evidence_router.get('/me')
async def read_current_user_evidence(user:CurrentUserDep, read_evidence_service:ReadEvidenceServiceDep):
    user_id = user.id
    evidence = await read_evidence_service.read_by_user_id(user_id)
    evidence_info = EvidenceSchema(load_instance=False).dump(evidence, many=True)
    return {
        'results': evidence_info
    }
