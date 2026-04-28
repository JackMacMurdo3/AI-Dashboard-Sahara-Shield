'''
Defines the app-wide configuration information.
'''

from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import find_dotenv

class AppSettings(BaseSettings):
    '''
    Contains app-wide configuration information, as stored in environment variables.
    Assumes existence of a .env file in the top-level directory.
    '''

    # see https://fastapi.tiangolo.com/advanced/settings/
    model_config = SettingsConfigDict(
        env_file=find_dotenv(filename='.env'),
        env_ignore_empty=True,
        extra='ignore',
    )

    DBAPI: str = 'aiomysql'

    API_VERSION: int = 1 # increment this after making substantial changes to api
    API_STR_PREFIX: str = f'/api/v{API_VERSION}'

    MYSQL_USERNAME: str
    MYSQL_PASSWORD: str
    MYSQL_HOST: str
    MYSQL_PORT: str
    MYSQL_DB: str

    AUTH_COOKIE_KEY: str = 'session_id' # each cookie is basically just a key-value pair and some other configuration params (like below)
    AUTH_COOKIE_MAX_AGE: int = 86400 # authentication cookies expire after a day
    PASSWORD_MIN_LEN: int = 12
    PASSWORD_MAX_LEN: int = 64
    USER_VERIFICATION_TOKEN_MAX_AGE: int = 300 # verification token for registration/password resets expires after 5 minutes

    def make_mysql_db_url(self) -> str:
        '''
        Creates a MySQL database URL string from configuration information
        
        :return: MySQL database URL string
        :rtype: str
        '''
        return f'mysql+{self.DBAPI}://{self.MYSQL_USERNAME}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}'

app_settings = AppSettings()