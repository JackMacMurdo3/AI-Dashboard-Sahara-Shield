from pydantic import BaseModel, Field

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

class SecurityDecision(BaseModel):
    '''
    Represents a security-related decision made by the defense system
    upon analysis of an intercepted HTTP request.
    '''

    upstream_app_id: int
    upstream_app_url: str
    allow: bool
    action: str
    status_code: int
    reason: str
    risk_score: int = Field(ge=0, le=100)
