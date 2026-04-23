'''
Contains app-wide security measures
'''

from argon2 import PasswordHasher
from sahara_shield.app.model.enums import SeverityScores, ThreatSeverities
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
        
class RiskScoreCalculator():
    def __init__(self, app_settings:AppSettings):
        self.app_settings = app_settings

    def calc(self, severity:ThreatSeverities, confidence_pct:int) -> int:
        if confidence_pct < 0 or confidence_pct > 100:
            raise ValueError('confidence_pct must be within [0, 100]')

        severity_score = SeverityScores[severity.name].value

        risk_score = (
            (self.app_settings.SEC_POLICY_RISK_SCORE_W1 * severity_score)
            + (self.app_settings.SEC_POLICY_RISK_SCORE_W2 * confidence_pct)
        )

        # keep risk score as an integer in [0, 100] so policy checks are deterministic
        return max(0, min(100, int(round(risk_score))))
    
password_sec_measure = PasswordSecurityMeasure(app_settings)
risk_score_calculator = RiskScoreCalculator(app_settings)
