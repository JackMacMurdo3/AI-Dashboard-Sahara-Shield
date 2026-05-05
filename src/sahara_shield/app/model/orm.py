'''
ORM (Object-relational Mapping) is a method/pattern for converting data between database (rows) and in-memory (objects) storage.

This module defines the SQLAlchemy mapped classes which are used for persisting to/retrieving from the relational database.
'''

import uuid
from urllib.parse import urlsplit
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, 
    Mapper, column_property, validates,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy import JSON
from sqlalchemy import (
    Integer, String, Enum, 
    DateTime, ForeignKey, Float,
    Boolean, Text, Index,
    select, func, text, 
    CheckConstraint, UniqueConstraint, 
)
from sahara_shield.app.model.enums import (
    UserRoles, HTTPMethods, PolicyModes, 
    ThreatSeverities, SecurityActions, ThreatTypes,
    DecisionEngineKeys, AnalysisEngineKeys
)
from datetime import datetime, timezone
from sqlalchemy.inspection import inspect
from sqlalchemy import event

def set_default_values(target, args, kwargs):
    # see https://stackoverflow.com/questions/13384996/how-do-i-set-attribute-default-values-in-sqlalchemy-declarative  
    # see https://stackoverflow.com/questions/14002631/why-isnt-sqlalchemy-default-column-value-available-before-object-is-committed
    for key, column in inspect(target.__class__).columns.items(): 
        if (key not in kwargs and hasattr(column, 'default') and column.default is not None): 
            if callable(column.default.arg): 
                kwargs[key] = column.default.arg(target) 
            else: 
                kwargs[key] = column.default.arg

# this ensures the set_default_values function is run on mapped class instantiation as desired
event.listen(Mapper, 'init', set_default_values)

class Base(DeclarativeBase, AsyncAttrs):
    '''
    Base mapped class. All subsequent mapped classes should be derived from this one.
    This way, they will automatically be added to the database metadata and can therefore be handled by Alembic for migrations.
    '''
    
    def __repr__(self):
        attrs = inspect(self.__class__).mapper.column_attrs
        values = ', '.join(f'{attr.key} = {getattr(self, attr.key)}' for attr in attrs)
        return f'{self.__class__.__name__}({values})'


# we need this so alembic can understand the schema of our database when performing migrations
# see https://docs.sqlalchemy.org/en/20/tutorial/metadata.html
db_metadata = Base.metadata
db_metadata.naming_convention = { # see https://docs.sqlalchemy.org/en/21/core/constraints.html#configuring-constraint-naming-conventions
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

class User(Base):
    '''
    Represents a user of the system.
    '''

    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False) # see https://stackoverflow.com/questions/247304/what-data-type-to-use-for-hashed-password-field-and-what-length
    role: Mapped[UserRoles] = mapped_column(Enum(UserRoles), nullable=False, default=UserRoles.STANDARD) # see https://docs.sqlalchemy.org/en/21/orm/declarative_tables.html#using-python-enum-or-pep-586-literal-types-in-the-type-map
    verified: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

class AuthSession(Base):
    '''
    Represents an authentication session for a user.
     - Temporary - automatically expire after a set period of time, after which user is no longer authenticated.
     - Server is responsible for revocation.

    See https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
    '''

    __tablename__ = 'auth_sessions'

    id: Mapped[str] = mapped_column(String(length=96), primary_key=True, default=lambda: str(uuid.uuid4())) # synonymous with session token
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

    def is_expired(self) -> bool:
        '''
        Checks whether authentication session for user has expired based on current time.
        '''
        return self.expires_at < datetime.now(tz=self.expires_at.tzinfo) # see https://stackoverflow.com/questions/15307623/cant-compare-naive-and-aware-datetime-now-challenge-datetime-end

class ProtectedApp(Base):
    '''
    Represents a web app the system is intended to protect/monitor.
    '''

    __tablename__ = 'protected_apps'
    __table_args__ = (
        UniqueConstraint('owner_user_id', 'name', 'url'),
    )

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(255), nullable=False)
    live: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

    def is_live(self) -> bool:
        return self.live

    @validates('url')
    def validate_url(self, key, value):
        url = (value or '').strip()

        if not url:
            raise ValueError('URL must not be empty')

        parsed = urlsplit(url)

        if not parsed.scheme or parsed.scheme not in {'http', 'https'}:
            raise ValueError('Missing/bad URL scheme, must be http or https')

        if not parsed.netloc:
            raise ValueError(f'Invalid URL: {value}')

        return url
    
    @classmethod
    def __declare_last__(cls):
        # configure correlated subquery derived field after all mappers are ready so all mappers are defined w/o reordering
        # otherwise e.g. AppSecurityPolicy hasn't been defined yet and we get an error
        # see https://docs.sqlalchemy.org/en/21/orm/mapped_sql_expr.html#using-column-property
        
        cls.app_security_policies_count = column_property(
            select(func.count(AppSecurityPolicy.id))
            .select_from(AppSecurityPolicy)
            .where(AppSecurityPolicy.protected_app_id == cls.id)
            .correlate_except(AppSecurityPolicy)
            .scalar_subquery()
        )

        cls.flagged_requests_count = column_property(
            select(func.count(FlaggedRequest.id))
            .select_from(FlaggedRequest)
            .join(AppSecurityPolicy, FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id)
            .where(AppSecurityPolicy.protected_app_id == cls.id)
            .correlate_except(FlaggedRequest, AppSecurityPolicy)
            .scalar_subquery()
        )

        cls.security_events_count = column_property(
            select(func.count(SecurityEvent.id))
            .select_from(SecurityEvent)
            .join(FlaggedRequest, SecurityEvent.flagged_request_id == FlaggedRequest.id)
            .join(AppSecurityPolicy, FlaggedRequest.app_security_policy_id == AppSecurityPolicy.id)
            .where(AppSecurityPolicy.protected_app_id == cls.id)
            .correlate_except(SecurityEvent, FlaggedRequest, AppSecurityPolicy)
            .scalar_subquery()
        )
    
class AppSecurityPolicy(Base):
    '''
    Represents the high-level security policy for a specific API route of a protected web app.
    The policy determines which requests are sent to the agent for analysis and controls
    whether the request is blocked/allowed based on a block score threshold.

    The system determines which policy (and subsequent analysis/security controls) to use by
    matching the request to a web app + HTTP method + API endpoint pattern.
    '''

    __tablename__ = 'app_security_policies'
    __table_args__ = (
        UniqueConstraint(
            'protected_app_id',
            'http_method',
            'route_pattern',
        ),
        CheckConstraint(
            'priority >= 0 AND priority <= 100',
            name='priority_range',
        ),
        CheckConstraint(
            'action_score_threshold >= 0 AND action_score_threshold <= 100',
            name='action_score_threshold_range',
        ),
    )

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    protected_app_id: Mapped[int] = mapped_column(ForeignKey('protected_apps.id'))
    name: Mapped[str] = mapped_column(String(255), nullable=False, default=lambda: f'New Policy {datetime.now(tz=timezone.utc)}')
    http_method: Mapped[HTTPMethods] = mapped_column(Enum(HTTPMethods), nullable=False)
    route_pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[PolicyModes] = mapped_column(Enum(PolicyModes), nullable=False, default=PolicyModes.MONITOR)
    analysis_engine_key: Mapped[AnalysisEngineKeys] = mapped_column(
        Enum(AnalysisEngineKeys),
        nullable=False,
        default=AnalysisEngineKeys.OPTIMIST,
    )
    decision_engine_key: Mapped[DecisionEngineKeys] = mapped_column(
        Enum(DecisionEngineKeys),
        nullable=False,
        default=DecisionEngineKeys.RANDOM,
    )
    active: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=True)
    active_status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    priority: Mapped[int] = mapped_column(Integer(), nullable=False, default=100)
    action_score_threshold: Mapped[int] = mapped_column(Integer(), nullable=False, default=70)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

    @validates('priority')
    def validate_priority(self, key, value):
        if value < 0 or value > 100:
            raise ValueError('priority must be within [0, 100]')

        return value

    @validates('action_score_threshold')
    def validate_action_score_threshold(self, key, value):
        if value < 0 or value > 100:
            raise ValueError('action_score_threshold must be within [0, 100]')

        return value
    
    def should_block(self, risk_score:int):
        return risk_score >= self.action_score_threshold
    
    @classmethod
    def __declare_last__(cls):
        cls.flagged_requests_count = column_property(
            select(func.count(FlaggedRequest.id))
            .select_from(FlaggedRequest)
            .where(FlaggedRequest.app_security_policy_id == cls.id)
            .correlate_except(FlaggedRequest)
            .scalar_subquery()
        )
        cls.security_events_count = column_property(
            select(func.count(SecurityEvent.id))
            .select_from(SecurityEvent)
            .join(FlaggedRequest, SecurityEvent.flagged_request_id == FlaggedRequest.id)
            .where(FlaggedRequest.app_security_policy_id == cls.id)
            .correlate_except(SecurityEvent, FlaggedRequest)
            .scalar_subquery()
        )

class FlaggedRequest(Base):
    '''
    Represents an HTTP request flagged as suspicious/malicious.
    '''

    __tablename__ = 'flagged_requests'

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    app_security_policy_id: Mapped[int] = mapped_column(ForeignKey('app_security_policies.id'), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    http_method: Mapped[HTTPMethods] = mapped_column(Enum(HTTPMethods), nullable=False)
    route_path: Mapped[str] = mapped_column(String(255), nullable=False)
    query_string: Mapped[str] = mapped_column(Text(), nullable=True)
    headers: Mapped[dict | None] = mapped_column(JSON(), nullable=True, default=lambda: {})
    body: Mapped[str | None] = mapped_column(Text(), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

class SecurityEvent(Base):
    '''
    Represents an interaction between the system and an intercepted HTTP request.
    '''

    __tablename__ = 'security_events'
    __table_args__ = (
        CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='risk_score_range'),
    )

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    flagged_request_id: Mapped[int] = mapped_column(ForeignKey('flagged_requests.id'), nullable=False)
    threat_type: Mapped[ThreatTypes] = mapped_column(Enum(ThreatTypes), nullable=False)
    threat_severity: Mapped[ThreatSeverities] = mapped_column(Enum(ThreatSeverities), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer(), nullable=False)
    action: Mapped[SecurityActions] = mapped_column(Enum(SecurityActions), nullable=False)
    reason_desc: Mapped[str] = mapped_column(String(1500), nullable=False, default='No reason given.')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

    @validates('confidence_pct')
    def validate_confidence_pct(self, key, value):
        if value < 0 or value > 100:
            raise ValueError('confidence_pct must be within [0, 100]')

        return value

    @validates('risk_score')
    def validate_risk_score(self, key, value):
        if value < 0 or value > 100:
            raise ValueError('risk_score must be within [0, 100]')

        return value
    