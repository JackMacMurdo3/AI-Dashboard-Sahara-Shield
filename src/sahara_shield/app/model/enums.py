import enum

class UserRole(enum.StrEnum):
    '''
    Stores the roles for user accounts.

    Intended for use as part of a rule-based access control (RBAC) system.
    '''

    SUPERUSER = enum.auto()
    STANDARD = enum.auto()