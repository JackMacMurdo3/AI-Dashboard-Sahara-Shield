from pydantic import BaseModel, Field

class DefenseCheckRequest(BaseModel):
    '''
    Input payload for a defense decision request.
    '''

    protected_app_id: int = Field(ge=1)
    http_method: str
    route_path: str
    query_string: str = ''
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ''
    source_ip: str | None = None

class DefenseCheckDecision(BaseModel):
    '''
    Decision returned by the defense engine.
    '''

    allow: bool
    action: str
    status_code: int
    reason: str
    upstream_url: str
    risk_score: int = Field(ge=0, le=100)
