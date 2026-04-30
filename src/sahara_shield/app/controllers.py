'''
Controllers layer of MVC architecture.

Controllers orchestrate service calls and handle request/response logic.
They form the bridge between API endpoints (routes) and business logic (services).
'''

from fastapi import HTTPException, Response
from sahara_shield.app.model.services import (
    CreateProtectedAppService, ReadProtectedAppsService,
    ReadAppSecurityPoliciesService, UserAuthService,
    ReadFlaggedRequestsService, ReadSecurityEventsService,
)
from sahara_shield.app.model.marshal import ProtectedAppSchema
from sahara_shield.app.model.marshal import AppSecurityPolicySchema
from sahara_shield.app.model.marshal import FlaggedRequestSchema
from sahara_shield.app.model.marshal import SecurityEventSchema
from sahara_shield.app.model.orm import User
from sahara_shield.app.core.config import AppSettings

class Controller():
    '''
    Base class for controller (layer) classes.

    Controllers handle request orchestration, calling services to perform
    business logic and preparing responses for API endpoints.
    Unlike services (which interact with the database), controllers
    coordinate multiple services and handle presentation concerns.
    '''
    pass

class ProtectedAppController(Controller):
    '''
    Orchestrates protected app operations.
    '''

    def __init__(
        self,
        create_protected_app_service: CreateProtectedAppService,
        read_protected_apps_service: ReadProtectedAppsService,
    ):
        self.create_service = create_protected_app_service
        self.read_service = read_protected_apps_service
        self.schema = ProtectedAppSchema(load_instance=False)

    async def create_protected_app(self, user: User, name: str, url: str):
        '''
        Create a new protected app for the current user.

        Args:
            user: Current authenticated user
            name: Name of the protected app
            url: URL of the protected app

        Returns:
            Serialized protected app data

        Raises:
            HTTPException: 409 if app already exists or validation fails
        '''
        try:
            protected_app = await self.create_service.create(
                owner_user_id=user.id, name=name, url=url
            )
            return self.schema.dump(protected_app)
        except Exception as e:
            raise HTTPException(status_code=409, detail=str(e))

    async def get_user_protected_apps(self, user: User):
        '''
        Retrieve all protected apps owned by the user.

        Args:
            user: Current authenticated user

        Returns:
            List of serialized protected app data
        '''
        protected_apps = await self.read_service.read_by_owner_user_id(user.id)
        return self.schema.dump(protected_apps, many=True)

    async def get_user_protected_app_by_id(self, user: User, id: int):
        '''
        Retrieve a protected app by ID if owned by the user.

        Args:
            user: Current authenticated user
            id: Protected app ID

        Returns:
            Serialized protected app data

        Raises:
            HTTPException: 404 if app is not found or not owned by the user
        '''
        protected_app = await self.read_service.read_by_id_and_owner_user_id(id, user.id)

        if protected_app is None:
            raise HTTPException(status_code=404, detail='Protected app not found')

        return self.schema.dump(protected_app)

    pass

class AppSecurityPolicyController(Controller):
    '''
    Orchestrates app security policy operations.
    '''

    def __init__(self, read_app_security_policies_service: ReadAppSecurityPoliciesService):
        self.read_service = read_app_security_policies_service
        self.schema = AppSecurityPolicySchema(load_instance=False)

    async def get_user_app_security_policies(self, user: User):
        '''
        Retrieve app security policies for the user's protected apps.
        '''
        policies = await self.read_service.read_by_user_id(user.id)
        return self.schema.dump(policies, many=True)

class FlaggedRequestsController(Controller):
    '''
    Orchestrates flagged request operations.
    '''

    def __init__(self, read_flagged_requests_service: ReadFlaggedRequestsService):
        self.read_service = read_flagged_requests_service
        self.schema = FlaggedRequestSchema(load_instance=False)

    async def get_user_flagged_requests(self, user: User):
        '''
        Retrieve flagged requests for the user's protected apps.
        '''
        flagged_requests = await self.read_service.read_by_user_id(user.id)
        return self.schema.dump(flagged_requests, many=True)

class SecurityEventsController(Controller):
    '''
    Orchestrates security event operations.
    '''

    def __init__(self, read_security_events_service: ReadSecurityEventsService):
        self.read_service = read_security_events_service
        self.schema = SecurityEventSchema(load_instance=False)

    async def get_user_security_events(self, user: User):
        '''
        Retrieve security events for the user's protected apps.
        '''
        events = await self.read_service.read_by_user_id(user.id)
        return self.schema.dump(events, many=True)

class AuthController(Controller):
    '''
    Orchestrates authentication operations.
    '''

    def __init__(self, user_auth_service: UserAuthService, app_settings:AppSettings):
        self.auth_service = user_auth_service
        self.app_settings = app_settings

    async def login(
        self,
        email: str,
        password: str,
        response: Response,
    ):
        '''
        Authenticate a user and create an authenticated session.

        Args:
            email: User email
            password: User password
            response: FastAPI Response object for setting cookies

        Returns:
            Success message with session info

        Raises:
            HTTPException: 401 if credentials are invalid
        '''
        try:
            user_id = await self.auth_service.authenticate(email, password)
        except Exception:
            raise HTTPException(status_code=401, detail='Invalid email or password')

        # reate and persist the auth session
        auth_session = await self.auth_service.create_auth_session(
            user_id, self.app_settings.AUTH_COOKIE_MAX_AGE, persist=True
        )
        await self.auth_service.save_changes()

        #Set the authentication cookie
        self._set_auth_cookie(response, auth_session)

        return {
            'message': f'Created authentication session for user {auth_session.user_id} at {auth_session.created_at}'
        }

    async def logout(
        self,
        session_id: str,
        response: Response,
    ):
        '''
        Terminate the user's authenticated session.

        Args:
            session_id: The session token to invalidate
            response: FastAPI Response object for deleting cookies

        Returns:
            Success message
        '''
        await self.auth_service.delete_auth_session_by_token(session_id)
        await self.auth_service.save_changes()

        # clear the authentication cookie
        self._delete_auth_cookie(response)

        return {'message': 'Logged out'}

    def _set_auth_cookie(self, response: Response, auth_session) -> None:
        '''
        Helper to set the authentication cookie on the response.

        Encapsulates cookie configuration details.
        '''
        response.set_cookie(
            key=self.app_settings.AUTH_COOKIE_KEY,
            value=auth_session.id,
            max_age=self.app_settings.AUTH_COOKIE_MAX_AGE,
            expires=auth_session.expires_at,
            path='/', # # see https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes#:~:text=mydomain.com.-,Path%20Attribute,-The%20Path%20attribute
            httponly=True,
            secure=True,
        )

    def _delete_auth_cookie(self, response: Response) -> None:
        '''
        Helper to delete the authentication cookie from the response.

        Encapsulates cookie removal details.
        '''
        response.delete_cookie(
            key=self.app_settings.AUTH_COOKIE_KEY,
            path='/',
            secure=True,
            httponly=True,
        )
