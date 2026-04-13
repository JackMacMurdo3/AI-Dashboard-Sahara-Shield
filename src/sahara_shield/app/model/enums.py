import enum
from enum import StrEnum

class UserRoles(StrEnum):
    '''
    Stores the roles for user accounts.

    Intended for use as part of a rule-based access control (RBAC) system.
    '''

    SUPERUSER = enum.auto()
    STANDARD = enum.auto()

class EvidenceThreatTypes(StrEnum):
    '''
    Stores the threat types the agent is able to classify
    and provide as evidence after scanning a file.
    '''

    XSS = enum.auto()
    SQLi = enum.auto()
    WEAK_HASH = enum.auto()
    WEAK_PASSWORDS = enum.auto()
    NONE = enum.auto()

class EvidenceSeverities(StrEnum):
    '''
    Stores the severity types the agent is able to classify
    and provide as evidence after scanning a file.
    '''

    CRITICAL = enum.auto()
    HIGH = enum.auto()
    MODERATE = enum.auto()
    LOW = enum.auto()
    NONE = enum.auto()
