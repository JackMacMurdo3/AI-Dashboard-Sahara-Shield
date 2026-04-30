'''
Service layer in MVC architecture.
'''

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, Result
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
from sahara_shield.app.model.orm import (
    User, AuthSession, ProtectedApp, 
    AppSecurityPolicy, FlaggedRequest, SecurityEvent,
)
from sahara_shield.app.core.security import password_sec_measure

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

class CreateProtectedAppService(Service):
    '''
    Asynchronously create new protected apps in the database
    '''

    async def create(self, owner_user_id: int, name: str, url: str) -> ProtectedApp:
        '''
        Asynchronously create a new protected app for a user
        '''
        
        try:
            protected_app = ProtectedApp(owner_user_id=owner_user_id, name=name, url=url)
            self.db_session.add(protected_app)
            await self.save_changes()
            return protected_app
        
        except IntegrityError:
            await self.discard_changes()
            raise Exception(f'Creation failed! A protected app with name "{name}" and URL "{url}" already exists for user {owner_user_id}.')
    
class ReadAppSecurityPoliciesService(Service):
    '''
    Asynchronously retrieve app security policies from the database
    '''

    async def read_by_user_id(self, user_id:int):
        stmt = (
            # SELECT * FROM app_security_policies (only keep rows from left table, none from right table)
            select(AppSecurityPolicy)
            # app_security_policies = left table, protected_apps = right table
            # LEFT JOIN protected_apps ON app_security_policies.protected_app_id = protected_apps.id
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            # WHERE protected_apps.user_id = user_id
            .where(ProtectedApp.owner_user_id == user_id)
            )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

class ReadFlaggedRequestsService(Service):
    '''
    Asynchronously retrieve flagged requests from the database.
    '''

    async def read_by_user_id(self, user_id: int):
        stmt = (
            # SELECT * FROM flagged_requests
            select(FlaggedRequest)
            # flagged_requests = left table, app_security_policies = right table
            # LEFT JOIN app_security_policies ON flagged_requests.app_security_policy_id = app_security_policies.id
            .join(
                AppSecurityPolicy,
                FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id,
            )
            # result of prior join (prior_join) = left table, protected_apps = right table
            # LEFT JOIN protected_apps ON prior_join.protected_app_id = protected_apps.id
            .join(ProtectedApp, AppSecurityPolicy.protected_app_id == ProtectedApp.id)
            # WHERE protected_apps.owner_user_id = user_id
            .where(ProtectedApp.owner_user_id == user_id)
        )

        res: Result = await self.db_session.execute(stmt)

        rows = res.scalars().all()

        return rows

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
    