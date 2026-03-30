'''
Contains the code responsible for managing connections to the database.

Establishes an app-wide database engine for use in interfacing with the database.

See https://stackoverflow.com/questions/68793314/what-is-the-best-approach-to-hooking-up-database-in-fastapi
'''

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sahara_shield.app.core.config import app_settings

class AsyncDatabaseSessionManager():
    '''
    Manages asynchronous database connections

    See https://docs.sqlalchemy.org/en/21/orm/extensions/asyncio.html
    '''
    
    def __init__(self, engine:AsyncEngine):
        self.engine = engine
        self.session_maker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def __call__(self):
        '''
        Opens a database session, in which queries/commands can be communicated to the database

        See https://docs.sqlalchemy.org/en/21/orm/session_basics.html

        See https://fastapi.tiangolo.com/advanced/advanced-dependencies/#a-callable-instance
        '''

        async with self.session_maker() as session:
            yield session

db_engine = create_async_engine(app_settings.make_mysql_db_url())
db_session_mngr = AsyncDatabaseSessionManager(db_engine)