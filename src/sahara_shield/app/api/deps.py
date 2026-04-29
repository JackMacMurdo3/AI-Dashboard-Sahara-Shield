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
    CreateProtectedAppService, ReadFlaggedRequestsService, ReadSecurityEventsService,
)
from sahara_shield.app.controllers import (
    ProtectedAppController, AuthController, 
    AppSecurityPolicyController, FlaggedRequestsController, SecurityEventsController,
)
from sahara_shield.app.model.orm import User

def get_read_users_service(db_session:AsyncSession=Depends(db_session_mngr)):
    '''
    Dependency injection function that provides a ReadUsersService instance.
    Args:
        db_session (AsyncSession): An asynchronous database session obtained from the database session manager dependency.
    Returns:
        ReadUsersService: An instance of ReadUsersService initialized with the provided database session.
    '''

    return ReadUsersService(db_session)

def get_user_auth_service(db_session:AsyncSession=Depends(db_session_mngr)):
    '''
    Dependency injection function that provides a UserAuthService instance.
    Args:
        db_session (AsyncSession): An asynchronous database session obtained from the database session manager dependency.
    Returns:
        UserAuthService: An instance of UserAuthService configured with the provided database 
        session for handling authentication-related operations.
    '''

    return UserAuthService(db_session)

def get_current_user_service(
        db_session:AsyncSession=Depends(db_session_mngr), # see https://fastapi.tiangolo.com/advanced/advanced-dependencies/#a-callable-instance
        user_auth_service:UserAuthService=Depends(get_user_auth_service), 
        read_users_service=Depends(get_read_users_service)
        ):
    '''
        Dependency injection function that creates and returns a CurrentUserService instance.
        Args:
            db_session (AsyncSession): An async database session manager that provides
                database access for user operations. Injected via FastAPI dependency.
            user_auth_service (UserAuthService): Service instance handling user authentication
                operations. Injected via FastAPI dependency.
            read_users_service: Service instance for reading user data from the database.
                Injected via FastAPI dependency.
        Returns:
            CurrentUserService: An initialized CurrentUserService instance configured with
                the provided database session and service dependencies, ready to handle
                current user operations.
    '''
    
    return CurrentUserService(db_session, user_auth_service, read_users_service)

def get_read_protected_apps_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadProtectedAppsService(db_session)

def get_create_protected_app_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return CreateProtectedAppService(db_session)

def get_read_app_security_policies_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadAppSecurityPoliciesService(db_session)

def get_read_flagged_requests_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadFlaggedRequestsService(db_session)

def get_read_security_events_service(db_session:AsyncSession=Depends(db_session_mngr)):
    return ReadSecurityEventsService(db_session)

async def get_current_user(
        session_id:str=Cookie(default=''), 
        current_user_service:CurrentUserService=Depends(get_current_user_service)
        ):
    '''
    Retrieve the current authenticated user for a request based on the provided session ID (token).
    This async function extracts the session ID from request cookies and fetches the associated user object. 
    It serves as a dependency for FastAPI endpoints that require user authentication.
    Args:
        session_id (str): The session identifier extracted from cookies. Defaults to an
            empty string if not provided.
        current_user_service (CurrentUserService): The service instance used to retrieve
            user information, injected via FastAPI's dependency injection system.
    Returns:
        User: The user object associated with the provided session ID.
    Raises:
        HTTPException: With status code 401 if:
            - The session_id is None or invalid
            - An error occurs while retrieving the user from the service
    Examples:
        Used as a dependency in a protected route:
        ```
        @app.get("/api/profile")
        async def get_profile(user: User = Depends(get_current_user)):
            return user.id
        ```
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
) -> AppSecurityPolicyController:
    '''
    Dependency injection function that provides an AppSecurityPolicyController instance.
    '''
    return AppSecurityPolicyController(read_app_security_policies_service)

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

def get_auth_controller(
    auth_service: UserAuthService = Depends(get_user_auth_service),
    settings = Depends(get_app_settings),
    ) -> AuthController:
    '''
    Dependency injection function that provides an AuthController instance.
    '''
    return AuthController(auth_service, settings)

# service dependencies for external module use
CurrentUserDep = Annotated[User, Depends(get_current_user)]

# controller dependencies for external module use
ProtectedAppControllerDep = Annotated[ProtectedAppController, Depends(get_protected_app_controller)]
AuthControllerDep = Annotated[AuthController, Depends(get_auth_controller)]
AppSecurityPolicyControllerDep = Annotated[AppSecurityPolicyController, Depends(get_app_security_policy_controller)]
FlaggedRequestsControllerDep = Annotated[FlaggedRequestsController, Depends(get_flagged_requests_controller)]
SecurityEventsControllerDep = Annotated[SecurityEventsController, Depends(get_security_events_controller)]
