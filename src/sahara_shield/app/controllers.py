'''
Controllers layer of MVC architecture.

Controllers orchestrate service calls and handle request/response logic.
They form the bridge between API endpoints (routes) and business logic (services).
'''

from fastapi import HTTPException, Response
from sahara_shield.app.model.services import (
    CreateProtectedAppService, ReadProtectedAppsService,
    CreateAppSecurityPolicyService,
    ReadAppSecurityPoliciesService, UserAuthService,
    ReadFlaggedRequestsService, ReadSecurityEventsService,
)
from sahara_shield.app.model.marshal import (
    ProtectedAppSchema, AppSecurityPolicySchema,
    FlaggedRequestSchema, SecurityEventSchema,
)
from sahara_shield.app.model.orm import User, AppSecurityPolicy
from sahara_shield.app.model.enums import (
    ThreatSeverities, ThreatTypes,
    AnalysisEngineKeys,
    DecisionEngineKeys,
    PolicyModes, HTTPMethods,
)
from sahara_shield.app.core.config import AppSettings
from sahara_shield.app.defense.analysis_engines import AnalysisEngine
from sahara_shield.app.defense.decision_engines import DecisionEngine
from sahara_shield.app.defense.marshal import InterceptedRequest, SecurityDecision
from sahara_shield.app.defense.matching import match_app_security_policies

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

    async def create_protected_app(
        self,
        user: User,
        name: str,
        url: str,
        risk_score_severity_score_weight: float = 0.5,
        risk_score_confidence_pct_weight: float = 0.5,
    ):
        '''
        Create a new protected app for the current user.
        '''
        try:
            protected_app = await self.create_service.create(
                owner_user_id=user.id,
                name=name,
                url=url,
                risk_score_severity_score_weight=risk_score_severity_score_weight,
                risk_score_confidence_pct_weight=risk_score_confidence_pct_weight,
            )
            return self.schema.dump(protected_app)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def get_user_protected_apps(self, user: User):
        '''
        Retrieve all protected apps owned by the user.
        '''
        protected_apps = await self.read_service.read_by_owner_user_id(user.id)
        return self.schema.dump(protected_apps, many=True)

    async def get_user_protected_app_by_id(self, user: User, id: int):
        '''
        Retrieve a protected app by ID if owned by the user.
        '''
        protected_app = await self.read_service.read_by_id_and_owner_user_id(id, user.id)

        if protected_app is None:
            raise HTTPException(status_code=404, detail='Protected app not found')

        return self.schema.dump(protected_app)

class AppSecurityPolicyController(Controller):
    '''
    Orchestrates app security policy operations.
    '''

    def __init__(
        self,
        create_app_security_policy_service: CreateAppSecurityPolicyService,
        read_app_security_policies_service: ReadAppSecurityPoliciesService,
        read_protected_apps_service: ReadProtectedAppsService,
    ):
        self.create_service = create_app_security_policy_service
        self.read_service = read_app_security_policies_service
        self.read_protected_apps_service = read_protected_apps_service
        self.schema = AppSecurityPolicySchema(load_instance=False)

    async def create_app_security_policy(
        self,
        user: User,
        protected_app_id: int,
        http_method: str,
        route_pattern: str,
        name: str | None = None,
        mode: str | None = None,
        decision_engine_key: str | None = None,
        active: bool = True,
        priority: int = 100,
        action_score_threshold: int = 70,
    ):
        # verify protected app belongs to user
        protected_app = await self.read_protected_apps_service.read_by_id_and_owner_user_id(
            protected_app_id,
            user.id,
        )

        if protected_app is None:
            raise HTTPException(status_code=404, detail='Protected app not found')

        # convert http method enum
        try:
            http_method = http_method.upper()
            http_method_enum = http_method if isinstance(http_method, HTTPMethods) else HTTPMethods[http_method]
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid http_method')

        # convert policy modes enum
        try:
            mode = mode.upper() if mode is not None else None
            mode_enum = mode if (mode is None or isinstance(mode, PolicyModes)) else PolicyModes[mode]
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid mode')

        # convert decision engine keys enum
        try:
            decision_engine_key = decision_engine_key.upper() if decision_engine_key is not None else None
            decision_engine_enum = (
                decision_engine_key
                if (decision_engine_key is None or isinstance(decision_engine_key, DecisionEngineKeys))
                else DecisionEngineKeys[decision_engine_key]
            )
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid decision_engine_key')

        try:
            policy = await self.create_service.create(
                protected_app_id=protected_app_id,
                name=name,
                http_method=http_method_enum,
                route_pattern=route_pattern,
                mode=mode_enum,
                decision_engine_key=decision_engine_enum,
                active=active,
                priority=priority,
                action_score_threshold=action_score_threshold,
            )

            return self.schema.dump(policy)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def get_user_app_security_policies(self, user: User):
        '''
        Retrieve app security policies for the user's protected apps.
        '''
        policies = await self.read_service.read_by_user_id(user.id)
        return self.schema.dump(policies, many=True)

    async def get_user_app_security_policy_by_id(self, user: User, id: int):
        '''
        Retrieve a single app security policy belonging to the user's protected apps.
        '''
        policy = await self.read_service.read_by_id_and_user_id(id, user.id)

        if policy is None:
            raise HTTPException(status_code=404, detail='App security policy not found')

        return self.schema.dump(policy)

    async def get_user_app_security_policies_by_protected_app_id(self, user: User, protected_app_id: int):
        '''
        Retrieve app security policies for one protected app owned by the current user.
        '''
        policies = await self.read_service.read_by_protected_app_id_and_user_id(protected_app_id, user.id)
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
        Retrieve security events for a user's protected apps.
        '''
        events = await self.read_service.read_by_user_id(user.id)
        return self.schema.dump(events, many=True)
    
    async def get_user_protected_app_security_events(self, user:User, protected_app_id:int):
        '''
        Retrieve security events for a specific protected app belonging to a user.
        '''
        events = await self.read_service.read_by_user_id_and_protected_app_id(user.id, protected_app_id)
        return self.schema.dump(events, many=True)

    async def get_user_protected_app_security_event_threat_severity_counts(self, user: User, protected_app_id: int):
        '''
        Retrieve counts of security events grouped by threat severity for a protected app belonging to a user.
        '''
        rows = await self.read_service.read_threat_severity_counts_by_user_id_and_protected_app_id(
            user.id,
            protected_app_id,
        )

        severity_counts = {severity.value: 0 for severity in ThreatSeverities}

        for severity, count in rows:
            severity_counts[severity.value] = count

        return severity_counts
    
    async def get_user_protected_app_security_event_threat_type_counts(self, user:User, protected_app_id:int):
        '''
        Retrieve counts of security events grouped by threat type for a protected app belong to a user.
        '''

        rows = await self.read_service.read_threat_type_counts_by_user_id_and_protected_app_id(
            user.id, 
            protected_app_id,
        )

        threat_type_counts = {threat_type.value: 0 for threat_type in ThreatTypes}

        for threat_type, count in rows:
            threat_type_counts[threat_type.value] = count

        return threat_type_counts

    async def get_user_protected_app_security_event_confidence_pct_stats(self, user:User, protected_app_id:int):
        '''
        Compute mean and median confidence percentages for security events of a protected app.
        '''

        pcts = await self.read_service.read_confidence_pcts_by_user_id_and_protected_app_id(
            user.id,
            protected_app_id,
        )

        if not pcts:
            return {'mean': 0.0, 'median': 0.0}

        total = sum(pcts)
        n = len(pcts)
        mean = total / n

        # pcts are ordered ascending from the query
        mid = n // 2
        if n % 2 == 1:
            median = float(pcts[mid])
        else:
            median = (pcts[mid - 1] + pcts[mid]) / 2.0

        return {'mean': mean, 'median': median}

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

class SecurityDecisionController(Controller):
    def __init__(
            self,
            read_protected_apps_service:ReadProtectedAppsService,
            read_app_security_policies_service: ReadAppSecurityPoliciesService,
            analysis_engine_registry: dict[AnalysisEngineKeys, type[AnalysisEngine]],
            default_analysis_engine_key: AnalysisEngineKeys,
            decision_engine_registry: dict[DecisionEngineKeys, DecisionEngine],
            default_decision_engine_key: DecisionEngineKeys,
            ):
        self.read_protected_apps_service = read_protected_apps_service
        self.read_app_security_policies_service = read_app_security_policies_service
        self.analysis_engine_registry = analysis_engine_registry
        self.default_analysis_engine_key = default_analysis_engine_key
        self.decision_engine_registry = decision_engine_registry
        self.default_decision_engine_key = default_decision_engine_key

    def _resolve_analysis_engine(self, app_security_policy: AppSecurityPolicy | None = None) -> AnalysisEngine:
        '''
        Select the engine associated with a matched policy, falling back to the default engine.
        '''

        if len(self.analysis_engine_registry) == 0:
            raise HTTPException(status_code=500, detail='Server error: no analysis engines registered')

        default_engine = self.analysis_engine_registry[self.default_analysis_engine_key]

        analysis_engine_key = getattr(app_security_policy, 'analysis_engine_key', None)
        if analysis_engine_key is not None:
            return self.analysis_engine_registry.get(analysis_engine_key, default_engine)

        return default_engine

    def _resolve_decision_engine(self, app_security_policy: AppSecurityPolicy | None = None) -> DecisionEngine:
        '''
        Select the engine associated with a matched policy, falling back to the default engine.
        '''

        if len(self.decision_engine_registry) == 0:
            raise HTTPException(status_code=500, detail='Server error: no decision engines registered')

        default_engine = self.decision_engine_registry[self.default_decision_engine_key]

        if app_security_policy is not None:
            return self.decision_engine_registry.get(app_security_policy.decision_engine_key, default_engine)
        
        return default_engine

    async def get_security_decision(
        self,
        req: InterceptedRequest,
    ) -> SecurityDecision:
        protected_app = await self.read_protected_apps_service.read_by_id(req.protected_app_id)

        if protected_app is None:
            raise HTTPException(status_code=404, detail='Protected app not found')

        app_security_policies = await self.read_app_security_policies_service.read_by_protected_app_id(
            req.protected_app_id,
        )

        app_security_policies = match_app_security_policies(
            app_security_policies,
            req.http_method,
            req.route_path,
        )

        app_security_policy = app_security_policies[0] if app_security_policies else None

        analysis_engine: AnalysisEngine = self._resolve_analysis_engine(app_security_policy)() # instantiate analysis engine
        findings = await analysis_engine.analyze(req, protected_app)
        
        # check decision risk score against policy action score threshold
        # if decision risk score is higher and policy in enforce mode
        #   execute action
        #   create flagged request
        #   create security event
        # if decision risk score is higher and policy in monitor mode
        #   take no action
        #   create flagged request
        # if decision risk score is lower
        #   take no action
        
        decision_engine: DecisionEngine = self._resolve_decision_engine(app_security_policy)() # instantiate decision engine
        decision = await decision_engine.decide(findings)

        return decision
