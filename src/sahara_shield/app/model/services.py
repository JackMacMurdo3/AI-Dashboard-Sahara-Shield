'''
Service layer in MVC architecture.
'''

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, Result, func
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
from sahara_shield.app.model.orm import (
    User, AuthSession, ProtectedApp, 
    AppSecurityPolicy, FlaggedRequest, SecurityEvent,
)
from sahara_shield.app.core.security import password_sec_measure
from sahara_shield.app.core.enums import (
    HTTPMethods, DecisionEngineKeys, PolicyModes, AggregationStrategyKeys,
    ThreatTypes, ThreatSeverities, SecurityActions,
)

class Service():
    '''
    Base class for asynchronous service (layer) classes. Intended for use with an asynchronous DBAPI.

    Services interact with the database and domain objects.
    They effectively encapsulate the bulk of the system's business logic.
    '''

    def __init__(self, db_session:AsyncSession):
        self.db_session = db_session

    async def save_changes(self):
        await self.db_session.commit()

    async def refresh(self, obj:object):
        await self.db_session.refresh(obj)

    async def discard_changes(self):
        await self.db_session.rollback()

class ReadUsersService(Service):
    '''
    Asynchronously retrieve users from the database
    '''

    async def read_by_id(self, id:int):
        stmt = select(User).where(User.id == id)

        res: Result = await self.db_session.execute(stmt)

        info = res.scalars().one_or_none()

        return info
    
class ReadProtectedAppsService(Service):
    '''
    Asynchronously retrieve protected apps from the database
    '''

    async def read_by_owner_user_id(self, owner_user_id:int):
        stmt = select(ProtectedApp).where(ProtectedApp.owner_user_id == owner_user_id)

        res: Result = await self.db_session.execute(stmt)

        info = res.scalars().all()

        return info

    async def read_by_id_and_owner_user_id(self, id:int, owner_user_id:int):
        stmt = select(ProtectedApp).where(
            ProtectedApp.id == id,
            ProtectedApp.owner_user_id == owner_user_id,
        )

        res: Result = await self.db_session.execute(stmt)

        info = res.scalars().one_or_none()

        return info

    async def read_by_id(self, id: int):
        stmt = select(ProtectedApp).where(ProtectedApp.id == id)

        res: Result = await self.db_session.execute(stmt)

        info = res.scalars().one_or_none()

        return info

class CreateProtectedAppService(Service):
    '''
    Asynchronously create new protected apps in the database
    '''

    async def create(
        self,
        owner_user_id: int,
        name: str,
        url: str,
    ) -> ProtectedApp:
        '''
        Asynchronously create a new protected app for a user
        '''
        
        try:
            protected_app = ProtectedApp(
                owner_user_id=owner_user_id,
                name=name,
                url=url,
            )
            self.db_session.add(protected_app)
            await self.save_changes()
            await self.refresh(protected_app) # see https://stackoverflow.com/questions/74252768/missinggreenlet-greenlet-spawn-has-not-been-called
            return protected_app
        
        except IntegrityError:
            await self.discard_changes()
            raise Exception('Creation failed; protected app may already exist or constraints were violated.')
    
class ReadAppSecurityPoliciesService(Service):
    '''
    Asynchronously retrieve app security policies from the database
    '''

    async def read_by_user_id(self, user_id:int):
        stmt = (
            # SELECT * FROM app_security_policies (only keep rows from left table, none from right table)
            select(AppSecurityPolicy)
            # app_security_policies = left table, protected_apps = right table
            # INNER JOIN protected_apps ON app_security_policies.protected_app_id = protected_apps.id
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            # WHERE protected_apps.user_id = user_id
            .where(ProtectedApp.owner_user_id == user_id)
            )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows
    
    async def read_by_id_and_user_id(self, id: int, user_id: int):
        stmt = (
            select(AppSecurityPolicy)
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            .where(AppSecurityPolicy.id == id)
            .where(ProtectedApp.owner_user_id == user_id)
        )

        res: Result = await self.db_session.execute(stmt)

        row = res.scalars().one_or_none()

        return row

    async def read_by_protected_app_id_and_user_id(self, protected_app_id: int, user_id: int):
        stmt = (
            select(AppSecurityPolicy)
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            .where(AppSecurityPolicy.protected_app_id == protected_app_id)
            .where(ProtectedApp.owner_user_id == user_id)
            .order_by(AppSecurityPolicy.priority.asc(), AppSecurityPolicy.id.asc())
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

    async def read_by_protected_app_id(self, protected_app_id: int):
        stmt = (
            select(AppSecurityPolicy)
            .where(AppSecurityPolicy.protected_app_id == protected_app_id)
            .order_by(AppSecurityPolicy.priority.asc(), AppSecurityPolicy.id.asc())
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

class CreateAppSecurityPolicyService(Service):
    '''
    Asynchronously create new AppSecurityPolicy records in the database.
    '''

    async def create(
        self,
        protected_app_id:int,
        http_method:HTTPMethods,
        route_pattern:str,
        name:str|None = None,
        mode:PolicyModes|None=None,
        aggregation_strategy_key:AggregationStrategyKeys|None=None,
        decision_engine_key:DecisionEngineKeys|None=None,
        active:bool=True,
        priority:int=100,
        action_score_threshold:int=70,
    ) -> AppSecurityPolicy:
        try:
            app_security_policy = AppSecurityPolicy(
                protected_app_id=protected_app_id,
                name=name,
                http_method=http_method,
                route_pattern=route_pattern,
                mode=mode,
                aggregation_strategy_key=aggregation_strategy_key,
                decision_engine_key=decision_engine_key,
                active=active,
                priority=priority,
                action_score_threshold=action_score_threshold,
            )

            self.db_session.add(app_security_policy)
            await self.save_changes()
            await self.refresh(app_security_policy)

            return app_security_policy
        except IntegrityError:
            await self.discard_changes()
            raise Exception('Creation failed; app security policy may already exist or constraints violated.')
    
class ReadFlaggedRequestsService(Service):
    '''
    Asynchronously retrieve flagged requests from the database.
    '''

    async def read_by_user_id(self, user_id: int):
        stmt = (
            # SELECT * FROM flagged_requests
            select(FlaggedRequest)
            # flagged_requests = left table, app_security_policies = right table
            # INNER JOIN app_security_policies ON flagged_requests.app_security_policy_id = app_security_policies.id
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            # result of prior join (prior_join) = left table, protected_apps = right table
            # INNER JOIN protected_apps ON prior_join.protected_app_id = protected_apps.id
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            # WHERE protected_apps.owner_user_id = user_id
            .where(ProtectedApp.owner_user_id == user_id)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

class CreateFlaggedRequestService(Service):
    '''
    Asynchronously create flagged request records in the database.
    '''

    async def create(
        self,
        http_method: HTTPMethods,
        route_path: str,
        app_security_policy_id: int | None = None,
        query_string: str | None = None,
        headers: dict | None = None,
        body: str | None = None,
        source_ip: str | None = None,
    ) -> FlaggedRequest:
        try:
            flagged_request = FlaggedRequest(
                app_security_policy_id=app_security_policy_id,
                http_method=http_method,
                route_path=route_path,
                query_string=query_string,
                headers=headers,
                body=body,
                source_ip=source_ip,
            )

            self.db_session.add(flagged_request)
            await self.save_changes()
            await self.refresh(flagged_request)

            return flagged_request
        except Exception as e:
            await self.discard_changes()
            raise Exception(f'Creation failed for flagged request: {e}')

class ReadSecurityEventsService(Service):
    '''
    Asynchronously retrieve security events related to flagged requests for a user's protected apps.
    '''

    async def read_by_user_id(self, user_id: int):
        stmt = (
            # SELECT * FROM security_events
            select(SecurityEvent)
            # security_events = left table, flagged_requests = right table
            .join(FlaggedRequest, SecurityEvent.flagged_request_id == FlaggedRequest.id)
            # prior join = left table, app_security_policies = right table
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            # join protected_apps to filter by owner
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            .where(ProtectedApp.owner_user_id == user_id)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows
    
    async def read_by_user_id_and_protected_app_id(self, user_id:int, protected_app_id:int):
        stmt = (
            # SELECT * FROM security_events
            select(SecurityEvent)
            # security_events = left table, flagged_requests = right table
            .join(FlaggedRequest, SecurityEvent.flagged_request_id == FlaggedRequest.id)
            # prior join = left table, app_security_policies = right table
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            # join protected_apps to filter by owner
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            .where(ProtectedApp.owner_user_id == user_id)
            .where(ProtectedApp.id == protected_app_id)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

    async def read_threat_severity_counts_by_user_id_and_protected_app_id(self, user_id: int, protected_app_id: int):
        stmt = (
            select(
                SecurityEvent.threat_severity,
                func.count(SecurityEvent.id),
            )
            .join(
                FlaggedRequest, 
                SecurityEvent.flagged_request_id == FlaggedRequest.id,
            )
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            .join(
                ProtectedApp, 
                AppSecurityPolicy.protected_app_id == ProtectedApp.id,
            )
            .where(ProtectedApp.owner_user_id == user_id)
            .where(ProtectedApp.id == protected_app_id)
            .group_by(SecurityEvent.threat_severity)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.all()

        return rows
    
    async def read_threat_type_counts_by_user_id_and_protected_app_id(self, user_id:int, protected_app_id:int):
        stmt = (
            select(
                SecurityEvent.threat_type, 
                func.count(SecurityEvent.id),
            )
            .join(
                FlaggedRequest, 
                SecurityEvent.flagged_request_id == FlaggedRequest.id,
                )
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            .join(
                ProtectedApp, 
                AppSecurityPolicy.protected_app_id == ProtectedApp.id,
                )
            .where(ProtectedApp.owner_user_id == user_id)
            .where(ProtectedApp.id == protected_app_id)
            .group_by(SecurityEvent.threat_type)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.all()

        return rows
    
class CreateSecurityEventService(Service):
    '''
    Asynchronously create security event records in the database.
    '''

    async def create(
        self,
        flagged_request_id: int,
        threat_type: ThreatTypes,
        threat_severity: ThreatSeverities,
        risk_score: int,
        action: SecurityActions,
        reason_desc: str,
    ) -> SecurityEvent:
        try:
            security_event = SecurityEvent(
                flagged_request_id=flagged_request_id,
                threat_type=threat_type,
                threat_severity=threat_severity,
                risk_score=risk_score,
                action=action,
                reason_desc=reason_desc,
            )

            self.db_session.add(security_event)
            await self.save_changes()
            await self.refresh(security_event)

            return security_event
        except Exception as e:
            await self.discard_changes()
            raise Exception(f'Creation failed for security event: {e}')
        
class UserAuthService(Service):
    async def authenticate(self, email:str, password:str):
        '''
        Asynchronously authenticates a user by email and password
        '''

        stmt = select(User.id, User.password_hash).where(User.email == email)
        res: Result = await self.db_session.execute(stmt)

        rows = res.mappings().all()
        if not rows:
            raise Exception(f'Cannot find user with email {email}')
        
        found_user = rows[0]
        valid_password = password_sec_measure.verify_password(password, found_user.password_hash)
        if not valid_password:
            raise Exception('Incorrect password')
        
        return found_user.id
    
    async def create_auth_session(self, user_id:int, max_age:int, persist:bool=True):
        '''
        Create a temporary authentication session for a user
        '''

        auth_session = AuthSession(user_id=user_id)
        auth_session.expires_at = auth_session.created_at + timedelta(seconds=max_age)

        if persist:
            self.db_session.add(auth_session)

        return auth_session
    
    async def delete_auth_session_by_token(self, session_token:str) -> None:
        '''
        Remove a temporary authentication session by session token (unique identifier)
        '''

        stmt = delete(AuthSession).where(AuthSession.id == session_token)

        await self.db_session.execute(stmt)

    async def get_auth_session_by_token(self, session_token:str, del_if_expired:bool=True) -> AuthSession|None:
        '''
        Retrieve an authentication session by session token (unique identifier)
        '''

        stmt = select(AuthSession).where(AuthSession.id == session_token)

        res: Result = await self.db_session.execute(stmt)

        row = res.scalars().one_or_none()

        if row is not None and row.is_expired() and del_if_expired:
            self.db_session.execute(delete(AuthSession).where(AuthSession.id == row.id))

        return row
    
class CurrentUserService(Service):
    '''
    Asynchronously get the info of the currently-authenticated User
    '''

    def __init__(self, db_session, user_auth_service:UserAuthService, read_users_service:ReadUsersService):
        super().__init__(db_session)
        self.user_auth_service = user_auth_service
        self.read_users_service = read_users_service

    async def get_user(self, session_token:str) -> User:
        auth_session = await self.user_auth_service.get_auth_session_by_token(session_token, del_if_expired=True)
        if auth_session is None:
            raise Exception(f'Cannot find session {session_token}')
        
        if auth_session.is_expired():
            raise Exception(f'Session {session_token} for user {auth_session.user_id} expired at {auth_session.expires_at}')
        
        user = await self.read_users_service.read_by_id(auth_session.user_id)
        
        if user is None:
            raise Exception(f'Cannot find info for user {auth_session.user_id}')
        
        return user
    