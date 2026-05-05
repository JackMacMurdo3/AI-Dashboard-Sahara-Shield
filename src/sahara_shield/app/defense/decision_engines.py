import random
from abc import abstractmethod, ABC
from sahara_shield.app.model.enums import SecurityActions
from sahara_shield.app.defense.marshal import AnalysisFindings, SecurityDecision
from sahara_shield.app.model.enums import DecisionEngineKeys

decision_engine_registry: dict[DecisionEngineKeys, type['DecisionEngine']] = {}

def register_decision_engine(name: DecisionEngineKeys):
    '''
    Automatically registers a DecisionEngine
    '''

    decision_engine_key = DecisionEngineKeys(name)

    def decorator(cls):
        if decision_engine_key in decision_engine_registry:
            raise ValueError(f'Engine key {decision_engine_key} is already registered')

        decision_engine_registry[decision_engine_key] = cls
        cls.decision_engine_key = decision_engine_key

        return cls

    return decorator

class DecisionEngine(ABC):
    @abstractmethod
    async def decide(self, findings: AnalysisFindings) -> SecurityDecision:
        pass

@register_decision_engine(DecisionEngineKeys.PERMISSIVE)
class PermissiveDecisionEngine(DecisionEngine):
    async def decide(self, findings):
        return SecurityDecision(
            upstream_app_id=findings.upstream_app_id,
            upstream_app_url=findings.upstream_app_url,
            action=SecurityActions.ALLOW,
            status_code=200,
            reason=f'Allowed!',
            aggregated_risk_score=0,
        )

@register_decision_engine(DecisionEngineKeys.RANDOM)
class RandomDecisionEngine(DecisionEngine):
    def __init__(self, min_risk_score:int=0, max_risk_score:int=100, seed:int|None=None):
        self.min_risk_score = min_risk_score
        self.max_risk_score = max_risk_score
        self.rng = random.Random(seed)

    async def decide(self, findings: AnalysisFindings) -> SecurityDecision:
        action = self.rng.choice(list(SecurityActions))
        blocked = (action == SecurityActions.BLOCK)
        risk_score = self.rng.randint(self.min_risk_score, self.max_risk_score)

        return SecurityDecision(
            upstream_app_id=findings.upstream_app_id,
            upstream_app_url=findings.upstream_app_url,
            action=action,
            status_code=403 if blocked else 200,
            reason=f'Request was {action} actioned due to {findings.threat_severity} severity {findings.threat_type} threat.',
            aggregated_risk_score=risk_score,
        )
    