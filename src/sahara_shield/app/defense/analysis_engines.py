import random
from abc import abstractmethod, ABC
from sahara_shield.app.model.orm import ProtectedApp
from sahara_shield.app.defense.marshal import AnalysisFindings, InterceptedRequest
from sahara_shield.app.model.enums import ThreatTypes, ThreatSeverities, AnalysisEngineKeys

analysis_engine_registry: dict[AnalysisEngineKeys, type['AnalysisEngine']] = {}

def register_analysis_engine(name: AnalysisEngineKeys):
    '''
    Automatically registers an AnalysisEngine
    '''

    analysis_engine_key = AnalysisEngineKeys(name)

    def decorator(cls):
        if analysis_engine_key in analysis_engine_registry:
            raise ValueError(f'Engine key {analysis_engine_key} is already registered')

        analysis_engine_registry[analysis_engine_key] = cls
        cls.analysis_engine_key = analysis_engine_key

        return cls

    return decorator

class AnalysisEngine(ABC):
    '''
    Performs security analysis of an intercepted HTTP request.
    '''

    @abstractmethod
    async def analyze(self, req:InterceptedRequest, protected_app:ProtectedApp, **kwargs) -> AnalysisFindings:
        pass

@register_analysis_engine(AnalysisEngineKeys.OPTIMIST)
class OptimistEngine(AnalysisEngine):
    '''
    Optimistic analysis engine. Always assumes the best - nothing is ever a threat, nor is it severe!
    '''

    def __init__(self, min_confidence_pct:int=0, max_confidence_pct:int=100, seed:int|None=None):
        self.min_confidence_pct = min_confidence_pct
        self.max_confidence_pct = max_confidence_pct
        self.rng = random.Random(seed)

    async def analyze(self, req, protected_app):
        return AnalysisFindings(
            upstream_app_id=protected_app.id,
            upstream_app_url=protected_app.url,
            threat_type=ThreatTypes.NONE,
            threat_severity=ThreatSeverities.NONE,
            severity_score=0,
            confidence_pct=self.rng.randint(self.min_confidence_pct, self.max_confidence_pct),
        )
    