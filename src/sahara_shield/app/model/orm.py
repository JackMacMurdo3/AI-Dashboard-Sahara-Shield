'''
ORM (Object-relational Mapping) is a method/pattern for converting data between database (rows) and in-memory (objects) storage.

This module defines the SQLAlchemy mapped classes which are used for persisting to/retrieving from the relational database.
'''

import uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Mapper
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy import Integer, String, Enum, DateTime, Float, CheckConstraint, ForeignKey, Boolean
from sahara_shield.app.model.enums import UserRole
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
    Base mapped class. 
    
    All subsequent mapped classes should be derived from this one.
    This way, they will automatically be added to the database metadata and can therefore be handled by Alembic for migrations.
    '''
    
    def __repr__(self):
        return ', '.join([f'{field.name} = {getattr(self, field.name)}' for field in self.__table__.columns])

class User(Base):
    '''
    Represents a user of the system.
    '''

    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(96), nullable=False) # see https://stackoverflow.com/questions/247304/what-data-type-to-use-for-hashed-password-field-and-what-length
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.STANDARD) # see https://docs.sqlalchemy.org/en/21/orm/declarative_tables.html#using-python-enum-or-pep-586-literal-types-in-the-type-map
    verified: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(tz=timezone.utc))

class AuthSession(Base):
    '''
    Represents an authenticated session for a user.

    Temporary - automatically expire after a set period of time, after which user is no longer authenticated.

    Server is responsible for revocation.

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
        Checks whether authenticated session for user has expired based on current time.
        '''
        return self.expires_at < datetime.now(tz=self.expires_at.tzinfo) # see https://stackoverflow.com/questions/15307623/cant-compare-naive-and-aware-datetime-now-challenge-datetime-end
    
# we need this so alembic can understand the schema of our database when performing migrations
# see https://docs.sqlalchemy.org/en/20/tutorial/metadata.html
db_metadata = Base.metadata