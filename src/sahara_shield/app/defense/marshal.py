from pydantic import BaseModel, Field
from sahara_shield.app.model.enums import SecurityActions, ThreatSeverities, ThreatTypes

class InterceptedRequest(BaseModel):
    '''
    Represents an HTTP request intercepted prior to reaching its target server.
    Intended to be analyzed by defense system for maliciousness.
    '''

    protected_app_id: int = Field(ge=1)
    http_method: str
    route_path: str
    query_string: str = ''
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ''
    source_ip: str | None = None

class AnalysisFindings(BaseModel):
    '''
    Represents the output of a request analysis engine.
    These findings are the input contract for decision engines.
    '''
    
    upstream_app_id: int
    upstream_app_url: str
    threat_type: ThreatTypes
    threat_severity: ThreatSeverities
    severity_score: int = Field(ge=0, le=100)
    confidence_pct: int = Field(ge=0, le=100)

class SecurityDecision(BaseModel):
    '''
    Represents a security-related decision made by the defense system
    from upstream analysis findings.
    '''

    upstream_app_id: int
    upstream_app_url: str
    action: SecurityActions
    status_code: int
    reason: str
    risk_score: int = Field(ge=0, le=100)
    