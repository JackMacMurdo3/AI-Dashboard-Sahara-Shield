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
    CreateFlaggedRequestService, CreateSecurityEventService,
)
from sahara_shield.app.model.marshal import (
    ProtectedAppSchema, AppSecurityPolicySchema,
    FlaggedRequestSchema, SecurityEventSchema,
)
from sahara_shield.app.model.orm import User, AppSecurityPolicy
from sahara_shield.app.core.enums import (
    ThreatSeverities, ThreatTypes,
    AnalysisEngineKeys,
    AggregationStrategyKeys,
    DecisionEngineKeys,
    PolicyModes, HTTPMethods, SecurityActions,
)
from sahara_shield.app.core.config import AppSettings
from sahara_shield.app.defense.aggregation import AggregationStrategy
from sahara_shield.app.defense.analysis_engines import AnalysisEngine, GeminiLLMAnalysisEngine
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
    ):
        '''
        Create a new protected app for the current user.
        '''
        try:
            protected_app = await self.create_service.create(
                owner_user_id=user.id,
                name=name,
                url=url,
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
        analysis_engine_key: str | None = None,
        aggregation_strategy_key: str | None = None,
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

        # convert analysis engine keys enum
        try:
            analysis_engine_key = analysis_engine_key.upper() if analysis_engine_key is not None else None
            analysis_engine_enum = (
                analysis_engine_key
                if (analysis_engine_key is None or isinstance(analysis_engine_key, AnalysisEngineKeys))
                else AnalysisEngineKeys[analysis_engine_key]
            )
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid analysis_engine_key')

        # convert aggregation strategy keys enum
        try:
            aggregation_strategy_key = aggregation_strategy_key.upper() if aggregation_strategy_key is not None else None
            aggregation_strategy_enum = (
                aggregation_strategy_key
                if (aggregation_strategy_key is None or isinstance(aggregation_strategy_key, AggregationStrategyKeys))
                else AggregationStrategyKeys[aggregation_strategy_key]
            )
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid aggregation_strategy_key')

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
                analysis_engine_key=analysis_engine_enum,
                aggregation_strategy_key=aggregation_strategy_enum,
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

        # create and persist the auth session
        auth_session = await self.auth_service.create_auth_session(
            user_id, self.app_settings.AUTH_COOKIE_MAX_AGE, persist=True
        )
        await self.auth_service.save_changes()

        # set the authentication cookie
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
            create_flagged_request_service: CreateFlaggedRequestService,
            create_security_event_service: CreateSecurityEventService,
            analysis_engine_registry: dict[AnalysisEngineKeys, type[AnalysisEngine]],
            default_analysis_engine_key: AnalysisEngineKeys,
            decision_engine_registry: dict[DecisionEngineKeys, DecisionEngine],
            default_decision_engine_key: DecisionEngineKeys,
            aggregation_strategy_registry: dict[AggregationStrategyKeys, type[AggregationStrategy]],
            default_aggregation_strategy_key: AggregationStrategyKeys,
            app_settings:AppSettings,
            ):
        self.read_protected_apps_service = read_protected_apps_service
        self.read_app_security_policies_service = read_app_security_policies_service
        self.create_flagged_request_service = create_flagged_request_service
        self.create_security_event_service = create_security_event_service
        self.analysis_engine_registry = analysis_engine_registry
        self.default_analysis_engine_key = default_analysis_engine_key
        self.decision_engine_registry = decision_engine_registry
        self.default_decision_engine_key = default_decision_engine_key
        self.aggregation_strategy_registry = aggregation_strategy_registry
        self.default_aggregation_strategy_key = default_aggregation_strategy_key
        self.app_settings = app_settings

    def _resolve_analysis_engine(self, app_security_policy: AppSecurityPolicy | None = None) -> AnalysisEngine:
        '''
        Select the engine associated with a matched policy, falling back to the default engine.
        '''

        if len(self.analysis_engine_registry) == 0:
            raise HTTPException(status_code=500, detail='Server error: no analysis engines registered')

        engine = self.analysis_engine_registry[self.default_analysis_engine_key]

        analysis_engine_key = getattr(app_security_policy, 'analysis_engine_key', None)
        if analysis_engine_key is not None:
            engine = self.analysis_engine_registry.get(analysis_engine_key, engine)

        if issubclass(engine, GeminiLLMAnalysisEngine):
            if not self.app_settings.LLM_GEMINI_API_KEY or not self.app_settings.LLM_GEMINI_MODEL:
                raise HTTPException(
                    status_code=500,
                    detail='Server error: Gemini analysis engine requires LLM_GEMINI_API_KEY and LLM_GEMINI_MODEL',
                )

            return engine(
                api_key=self.app_settings.LLM_GEMINI_API_KEY,
                model=self.app_settings.LLM_GEMINI_MODEL,
            )

        return engine()

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

    def _resolve_aggregation_strategy(self, app_security_policy: AppSecurityPolicy | None = None) -> AggregationStrategy:
        '''
        Select the aggregation strategy associated with a matched policy, falling back to the default strategy.
        '''

        if len(self.aggregation_strategy_registry) == 0:
            raise HTTPException(status_code=500, detail='Server error: no aggregation strategies registered')

        default_strategy = self.aggregation_strategy_registry[self.default_aggregation_strategy_key]

        aggregation_strategy_key = getattr(app_security_policy, 'aggregation_strategy_key', None)
        if aggregation_strategy_key is not None:
            return self.aggregation_strategy_registry.get(aggregation_strategy_key, default_strategy)()

        return default_strategy()

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

        analysis_engine: AnalysisEngine = self._resolve_analysis_engine(app_security_policy)
        findings = [await analysis_engine.analyze(req, protected_app)]
        
        aggregation_strategy = self._resolve_aggregation_strategy(app_security_policy)
        decision_engine: DecisionEngine = self._resolve_decision_engine(app_security_policy)(aggregation_strategy=aggregation_strategy)
        decision = await decision_engine.decide(findings)

        try:
            req_http_method = HTTPMethods[req.http_method.upper()]
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid http_method')

        action_score_threshold = app_security_policy.action_score_threshold if app_security_policy is not None else 70
        policy_mode = app_security_policy.mode if app_security_policy is not None else PolicyModes.MONITOR
        policy_id = app_security_policy.id if app_security_policy is not None else None
        high_risk = decision.aggregated_risk_score >= action_score_threshold

        if high_risk:
            flagged_request = await self.create_flagged_request_service.create(
                app_security_policy_id=policy_id,
                http_method=req_http_method,
                route_path=req.route_path,
                query_string=req.query_string,
                headers=req.headers,
                body=req.body,
                source_ip=req.source_ip,
            )

            if policy_mode == PolicyModes.ENFORCE:
                await self.create_security_event_service.create(
                    flagged_request_id=flagged_request.id,
                    threat_type=decision.aggregated_threat_type,
                    threat_severity=decision.aggregated_threat_severity,
                    risk_score=decision.aggregated_risk_score,
                    action=decision.action,
                    reason_desc=decision.reason,
                )

                return SecurityDecision(
                    upstream_app_id=decision.upstream_app_id,
                    upstream_app_url=decision.upstream_app_url,
                    analysis_engine_key=decision.analysis_engine_key,
                    decision_engine_key=decision.decision_engine_key,
                    aggregated_threat_type=decision.aggregated_threat_type,
                    aggregated_threat_severity=decision.aggregated_threat_severity,
                    action=decision.action,
                    status_code=decision.status_code,
                    reason=(
                        f'Protected App: {decision.upstream_app_id}. '
                        f'Policy: {app_security_policy.id if app_security_policy is not None else '--'} ({app_security_policy.name if app_security_policy is not None else 'Default'}). '                        f'High-risk request identified. Enforcement action taken. '
                        f'{decision.reason}'
                        ),
                    aggregated_risk_score=decision.aggregated_risk_score,
                )

            # monitor mode - no security event generated, since no action taken
            return SecurityDecision(
                upstream_app_id=decision.upstream_app_id,
                upstream_app_url=decision.upstream_app_url,
                analysis_engine_key=decision.analysis_engine_key,
                decision_engine_key=decision.decision_engine_key,
                aggregated_threat_type=decision.aggregated_threat_type,
                aggregated_threat_severity=decision.aggregated_threat_severity,
                action=SecurityActions.ALLOW, # ignore decision's action
                status_code=200, # ignore decision's status code
                reason=(
                    f'Protected App: {decision.upstream_app_id}. '
                    f'Policy: {app_security_policy.id if app_security_policy is not None else '--'} ({app_security_policy.name if app_security_policy is not None else 'Default'}). '                    f'High-risk request identified. Monitored only, no enforcement action taken. '
                    f'{decision.reason}'
                    ),
                aggregated_risk_score=decision.aggregated_risk_score,
            )
        
        # low risk request, no need to create flagged request or security event
        return SecurityDecision(
            upstream_app_id=decision.upstream_app_id,
            upstream_app_url=decision.upstream_app_url,
            analysis_engine_key=decision.analysis_engine_key,
            decision_engine_key=decision.decision_engine_key,
            aggregated_threat_type=decision.aggregated_threat_type,
            aggregated_threat_severity=decision.aggregated_threat_severity,
            action=SecurityActions.ALLOW,
            status_code=200,
            reason=(
                f'Protected App: {decision.upstream_app_id}. '
                f'Policy: {app_security_policy.id if app_security_policy is not None else '--'} ({app_security_policy.name if app_security_policy is not None else 'Default'}). '
                'Low-risk score request identified. No action taken. '
                f'{decision.reason}'
                ),
            aggregated_risk_score=decision.aggregated_risk_score,
        )
