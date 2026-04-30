from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep, SecurityEventsControllerDep

security_events_router = APIRouter(
    prefix='/security_events',
    tags=['security_events'],
)


@security_events_router.get('/me')
async def read_my_security_events(user: CurrentUserDep, controller: SecurityEventsControllerDep):
    return await controller.get_user_security_events(user)

@security_events_router.get('/me/protected_app/{protected_app_id}')
async def read_my_security_events_by_protected_app_id(protected_app_id:int, user:CurrentUserDep, controller: SecurityEventsControllerDep):
    return await controller.get_user_protected_app_security_events(user, protected_app_id)

@security_events_router.get('/me/protected_app/{protected_app_id}/summary')
async def read_my_security_events_summary_by_protected_app_id(protected_app_id:int, user:CurrentUserDep, controller: SecurityEventsControllerDep):
    threat_severity_counts = await controller.get_user_protected_app_security_event_threat_severity_counts(
        user, 
        protected_app_id,
    )

    threat_type_counts = await controller.get_user_protected_app_security_event_threat_type_counts(
        user,
        protected_app_id,
    )

    confidence_pct_stats = await controller.get_user_protected_app_security_event_confidence_pct_stats(
        user,
        protected_app_id,
    )

    return {
        'threat_severity_counts': threat_severity_counts,
        'threat_type_counts': threat_type_counts,
        'confidence_pct_stats': confidence_pct_stats,
    }
