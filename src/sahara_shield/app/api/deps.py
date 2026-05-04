'''
Defines the dependencies to inject into the FastAPI routes.

See https://fastapi.tiangolo.com/tutorial/dependencies/ for more details
'''

from typing import Annotated
from fastapi import Depends, Cookie, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sahara_shield.app.core.db import db_session_mngr
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.model.services import (
    ReadUsersService, UserAuthService, CurrentUserService,
)
from sahara_shield.app.model.services import (
    ReadProtectedAppsService, ReadAppSecurityPoliciesService, 
    CreateProtectedAppService, CreateAppSecurityPolicyService, ReadFlaggedRequestsService, ReadSecurityEventsService,
)
from sahara_shield.app.controllers import (
    ProtectedAppController, AuthController, 
    AppSecurityPolicyController, FlaggedRequestsController, SecurityEventsController,
    SecurityDecisionController,
)
from sahara_shield.app.model.orm import User
from sahara_shield.app.defense.analysis_engines import (
    AnalysisEngine,
    analysis_engine_registry,
)
from sahara_shield.app.defense.decision_engines import (
    DecisionEngine,
    decision_engine_registry
)
from sahara_shield.app.model.enums import AnalysisEngineKeys, DecisionEngineKeys

def get_read_users_service(db_session:AsyncSession=Depends(db_session_mngr)):
    '''
    Dependency injection function that provides a ReadUsersService instance.
    '''

    return ReadUsersService(db_session)

def get_user_auth_service(db_session:AsyncSession=Depends(db_session_mngr)):
    '''
    Dependency injection function that provides a UserAuthService instance.
    '''

    return UserAuthService(db_session)

def get_current_user_service(
        db_session:AsyncSession=Depends(db_session_mngr), # see https://fastapi.tiangolo.com/advanced/advanced-dependencies/#a-callable-instance
        user_auth_service:UserAuthService=Depends(get_user_auth_service), 
        read_users_service=Depends(get_read_users_service)
        ):
    '''
        Dependency injection function that creates and returns a CurrentUserService instance.
    '''
    
    return CurrentUserService(db_session, user_auth_service, read_users_service)

def get_read_protected_apps_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadProtectedAppsService(db_session)

def get_create_protected_app_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return CreateProtectedAppService(db_session)

def get_read_app_security_policies_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadAppSecurityPoliciesService(db_session)

def get_create_app_security_policy_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return CreateAppSecurityPolicyService(db_session)

def get_read_flagged_requests_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadFlaggedRequestsService(db_session)

def get_read_security_events_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadSecurityEventsService(db_session)

def get_default_analysis_engine_key() -> AnalysisEngineKeys:
    registered_keys = list(analysis_engine_registry.keys())

    if not registered_keys:
        raise HTTPException(status_code=500, detail='No analysis engines registered')

    return registered_keys[0]

def get_analysis_engine_registry() -> dict[AnalysisEngineKeys, type[AnalysisEngine]]:
    '''
    Dependency injection function that provides the analysis engine registry.
    '''
    return analysis_engine_registry

async def get_current_user(
        session_id:str=Cookie(default=''), 
        current_user_service:CurrentUserService=Depends(get_current_user_service)
        ):
    '''
    Retrieve the current authenticated user for a request based on the provided session ID (token).
    This async function extracts the session ID from request cookies and fetches the associated user object. 
    It serves as a dependency for FastAPI endpoints that require user authentication.
    '''
    
    if session_id is None:
        raise HTTPException(status_code=401, detail='Unauthorized/unknown')
    
    try:
        user = await current_user_service.get_user(session_id)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f'Error getting user: {e}')
    
    return user

def get_app_settings():
    '''
    Dependency injection function that provides the app settings configuration.
    
    Returns:
        app_settings: The application configuration settings object.
    '''
    return app_settings

def get_protected_app_controller(
    create_service: CreateProtectedAppService = Depends(get_create_protected_app_service),
    read_service: ReadProtectedAppsService = Depends(get_read_protected_apps_service),
 ) -> ProtectedAppController:
    '''
    Dependency injection function that provides a ProtectedAppController instance.
    '''
    return ProtectedAppController(create_service, read_service)

def get_app_security_policy_controller(
    read_app_security_policies_service: ReadAppSecurityPoliciesService = Depends(get_read_app_security_policies_service),
    create_app_security_policy_service: CreateAppSecurityPolicyService = Depends(get_create_app_security_policy_service),
    read_protected_apps_service: ReadProtectedAppsService = Depends(get_read_protected_apps_service),
) -> AppSecurityPolicyController:
    '''
    Dependency injection function that provides an AppSecurityPolicyController instance.
    '''
    return AppSecurityPolicyController(
        create_app_security_policy_service,
        read_app_security_policies_service,
        read_protected_apps_service,
    )

def get_flagged_requests_controller(
        read_flagged_requests_service: ReadFlaggedRequestsService = Depends(get_read_flagged_requests_service),
        ) -> FlaggedRequestsController:
    '''
    Dependency injection function that provides a FlaggedRequestsController instance.
    '''
    return FlaggedRequestsController(read_flagged_requests_service)

def get_security_events_controller(
        read_security_events_service: ReadSecurityEventsService = Depends(get_read_security_events_service),
        ) -> SecurityEventsController:
    '''
    Dependency injection function that provides a SecurityEventsController instance.
    '''
    return SecurityEventsController(read_security_events_service)

def get_default_decision_engine_key() -> DecisionEngineKeys:
    registered_keys = list(decision_engine_registry.keys())

    if not registered_keys:
        raise HTTPException(status_code=500, detail='No decision engines registered')

    return registered_keys[0]

def get_decision_engine_registry():
    '''
    Dependency injection function that provides the decision engine registry.
    '''
    return decision_engine_registry

def get_auth_controller(
        auth_service: UserAuthService = Depends(get_user_auth_service),
        settings = Depends(get_app_settings),
        ) -> AuthController:
    '''
    Dependency injection function that provides an AuthController instance.
    '''
    return AuthController(auth_service, settings)

def get_security_decision_controller(
        read_protected_apps_service: ReadProtectedAppsService = Depends(get_read_protected_apps_service),
        read_app_security_policies_service: ReadAppSecurityPoliciesService = Depends(get_read_app_security_policies_service),
        analysis_engine_registry: dict[AnalysisEngineKeys, type[AnalysisEngine]] = Depends(get_analysis_engine_registry),
        default_analysis_engine_key: AnalysisEngineKeys = Depends(get_default_analysis_engine_key),
        decision_engine_registry: dict[DecisionEngineKeys, type[DecisionEngine]] = Depends(get_decision_engine_registry),
        default_decision_engine_key: DecisionEngineKeys = Depends(get_default_decision_engine_key),
        ) -> SecurityDecisionController:
    '''
    Dependency injection function that provides a SecurityDecisionController instance.
    '''
    return SecurityDecisionController(
        read_protected_apps_service,
        read_app_security_policies_service,
        analysis_engine_registry,
        default_analysis_engine_key,
        decision_engine_registry,
        default_decision_engine_key,
    )

# service dependencies for external module use
CurrentUserDep = Annotated[User, Depends(get_current_user)]

# controller dependencies for external module use
ProtectedAppControllerDep = Annotated[ProtectedAppController, Depends(get_protected_app_controller)]
AuthControllerDep = Annotated[AuthController, Depends(get_auth_controller)]
AppSecurityPolicyControllerDep = Annotated[AppSecurityPolicyController, Depends(get_app_security_policy_controller)]
FlaggedRequestsControllerDep = Annotated[FlaggedRequestsController, Depends(get_flagged_requests_controller)]
SecurityEventsControllerDep = Annotated[SecurityEventsController, Depends(get_security_events_controller)]
SecurityDecisionControllerDep = Annotated[
    SecurityDecisionController,
    Depends(get_security_decision_controller),
]
