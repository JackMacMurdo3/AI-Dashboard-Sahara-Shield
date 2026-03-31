'''
Contains app-wide security measures
'''

from argon2 import PasswordHasher
from sahara_shield.app.core.config import app_settings, AppSettings

class PasswordSecurityMeasure():
    '''
    Security measure for all things passwords.
    '''

    def __init__(self, app_settings:AppSettings):
        self.app_settings = app_settings
        self.password_hasher = PasswordHasher()

    def check_password_len(self, password:str) -> bool:
        """
        Checks if the provided password length falls within the acceptable range
        defined by app configuration.
        Args:
            password (str): The password string to validate.
        Returns:
            bool: True if the password length is within the allowed range,
                    False otherwise.
        """

        l = len(password)

        if l < self.app_settings.PASSWORD_MIN_LEN or l > self.app_settings.PASSWORD_MAX_LEN:
            return False
        
        return True
    
    def hash_password(self, password:str):
        return self.password_hasher.hash(password)
    
    def verify_password(self, password:str, hash:str):
        try:
            self.password_hasher.verify(hash, password)
            return True
        except Exception as e:
            return False
    
password_sec_measure = PasswordSecurityMeasure(app_settings)
