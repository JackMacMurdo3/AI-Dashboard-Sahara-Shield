import enum
from enum import StrEnum

class UserRoles(StrEnum):
    '''
    Stores the roles for user accounts.

    Intended for use as part of a rule-based access control (RBAC) system.
    '''

    SUPERUSER = enum.auto()
    STANDARD = enum.auto()

class HTTPMethods(StrEnum):
    GET = enum.auto()
    POST = enum.auto()
    PUT = enum.auto()
    PATCH = enum.auto()
    DELETE = enum.auto()

class PolicyModes(StrEnum):
    MONITOR = enum.auto()
    ENFORCE = enum.auto()

class RoutePatternDatatypes(StrEnum):
    '''
    Stores the supported Starlette route pattern converter names.

    See https://starlette.dev/routing/#path-parameters
    '''

    INT = enum.auto()
    FLOAT = enum.auto()
    STR = enum.auto()
    PATH = enum.auto()

class AggregationStrategyKeys(StrEnum):
    MAX = enum.auto()

class AnalysisEngineKeys(StrEnum):
    '''
    Identifies which analysis engine to use when processing intercepted HTTP requests like from a reverse proxy.
    '''

    OPTIMISTIC = enum.auto()
    RANDOM = enum.auto()

class DecisionEngineKeys(StrEnum):
    '''
    Identifies which decision engine to use when processing security findings via an analysis engine.
    '''

    PERMISSIVE = enum.auto()
    RANDOM = enum.auto()

class ThreatTypes(StrEnum):
    NONE = enum.auto()
    UNKNOWN = enum.auto()
    SQLi = enum.auto()
    XSS = enum.auto()
    PATH_TRAVERSAL = enum.auto()

class ThreatSeverities(StrEnum):
    '''
    Stores severity classifications returned by threat analysis.
    '''

    NONE = enum.auto()
    LOW = enum.auto()
    MODERATE = enum.auto()
    HIGH = enum.auto()
    CRITICAL = enum.auto()

class SecurityActions(StrEnum):
    '''
    Stores the action taken by the security system for a request.
    '''

    ALLOW = enum.auto()
    BLOCK = enum.auto()
