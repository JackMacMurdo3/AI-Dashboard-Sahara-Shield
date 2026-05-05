import re
from pydantic import BaseModel, Field, field_validator
from sahara_shield.app.core.enums import (
    SecurityActions, ThreatSeverities, ThreatTypes,
    AnalysisEngineKeys, DecisionEngineKeys,
)

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
    analysis_engine_key: AnalysisEngineKeys
    threat_type: ThreatTypes
    threat_severity: ThreatSeverities
    risk_score: int = Field(ge=0, le=100)
    explanation: str = Field(
        default='',
        description='Up to 100 words explaining what stood out about the request.',
    )

    @field_validator('explanation')
    @classmethod
    def validate_explanation_word_count(cls, value: str) -> str:
        if not value:
            return value

        word_count = len(re.findall(r'\S+', value.strip()))

        if word_count > 100:
            raise ValueError('explanation must be 100 words or fewer')

        return value

class SecurityDecision(BaseModel):
    '''
    Represents a security-related decision made by the defense system
    from upstream analysis findings.
    '''

    upstream_app_id: int
    upstream_app_url: str
    analysis_engine_key: AnalysisEngineKeys
    decision_engine_key: DecisionEngineKeys
    aggregated_threat_type: ThreatTypes
    aggregated_threat_severity: ThreatSeverities
    action: SecurityActions
    status_code: int
    reason: str
    aggregated_risk_score: int = Field(ge=0, le=100)
    