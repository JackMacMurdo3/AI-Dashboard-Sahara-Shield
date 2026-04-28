'''
ORM (Object-relational Mapping) is a method/pattern for converting data between database (rows) and in-memory (objects) storage.

This module defines the SQLAlchemy mapped classes which are used for persisting to/retrieving from the relational database.
'''

import uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Mapper, column_property
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy import Integer, String, Enum, DateTime, ForeignKey, Boolean, select, func, text
from sahara_shield.app.model.enums import UserRoles, EvidenceThreatTypes, EvidenceSeverities
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

    @classmethod
    def __declare_last__(cls):
        # configure correlated subquery derived field after all mappers are ready so all mappers are defined w/o reordering
        # otherwise e.g. Scan hasn't been defined yet and we get an error
        # see https://docs.sqlalchemy.org/en/21/orm/mapped_sql_expr.html#using-column-property
        cls.scans_count = column_property(
            select(func.count(Scan.id))
            .select_from(Scan)
            .where(Scan.user_id == cls.id)
            .correlate_except(Scan)
            .scalar_subquery()
        )

        cls.files_scanned_count = column_property(
            select(func.count(func.distinct(Evidence.filename))) # 4 - remove duplicate rows based on evidence.filename, then count number of remaining rows
            .select_from(Evidence) # 1 - get all evidence rows
            .join(Scan, Evidence.scan_id == Scan.id) # 2 - left join w/ scans on scan id
            .where(Scan.user_id == cls.id) # 3 - filter joined evidence + scan rows where scan.user_id is this user instance's id
            .correlate_except(Evidence, Scan)
            .scalar_subquery()
        )
        
        # count of evidence generated via scan initiated by user where severity type is none
        cls.clean_files_count = column_property(
            select(func.count(Evidence.id))
            .select_from(Evidence)
            .join(Scan, Evidence.scan_id == Scan.id)
            .where(Scan.user_id == cls.id)
            .where(Evidence.severity == EvidenceSeverities.NONE)
            .correlate_except(Evidence, Scan)
            .scalar_subquery()
        )

        # count of evidence generate via scan initiated by user where severity type is NOT none
        # this means a security threat of some kind was detected, regardless of severity
        cls.bad_files_count = column_property(
            select(func.count(Evidence.id))
            .select_from(Evidence)
            .join(Scan, Evidence.scan_id == Scan.id)
            .where(Scan.user_id == cls.id)
            .where(Evidence.severity != EvidenceSeverities.NONE)
            .correlate_except(Evidence, Scan)
            .scalar_subquery()
        )

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
    
class Scan(Base):
    '''
    Represents a security scan of code files in a remote repository by agent, initiated at request of user
    '''

    __tablename__ = 'scans'

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    repository_url: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    duration_secs = column_property(func.timestampdiff(text('SECOND'), started_at, finished_at, type_=Integer)) # have to include type otherwise automatic schema generation fails

    @classmethod
    def __declare_last__(cls):
        cls.evidence_count = column_property(
            select(func.count(Evidence.id))
            .select_from(Evidence)
            .where(Evidence.scan_id == cls.id)
            .correlate_except(Evidence)
            .scalar_subquery()
        )

class Evidence(Base):
    '''
    Represents security vulnerabilities found in a file of a remote repository scanned by agent.
    '''

    __tablename__ = 'evidence'

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey('scans.id'))
    filename: Mapped[str] = mapped_column(String(length=255), nullable=False)
    threat_type: Mapped[EvidenceThreatTypes] = mapped_column(Enum(EvidenceThreatTypes), nullable=False, default=EvidenceThreatTypes.NONE)
    confidence_level: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    severity: Mapped[EvidenceSeverities] = mapped_column(Enum(EvidenceSeverities), nullable=False, default=EvidenceSeverities.NONE)
    
# we need this so alembic can understand the schema of our database when performing migrations
# see https://docs.sqlalchemy.org/en/20/tutorial/metadata.html
db_metadata = Base.metadata
