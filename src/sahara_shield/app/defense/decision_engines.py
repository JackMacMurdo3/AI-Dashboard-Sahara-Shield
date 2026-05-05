import random
from abc import abstractmethod, ABC
from collections.abc import Sequence
from sahara_shield.app.core.enums import SecurityActions
from sahara_shield.app.defense.aggregation import AggregationStrategy, MaxAggregationStrategy
from sahara_shield.app.defense.marshal import AnalysisFindings, SecurityDecision
from sahara_shield.app.core.enums import DecisionEngineKeys

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

        return cls

    return decorator

class DecisionEngine(ABC):
    def __init__(self, aggregation_strategy:AggregationStrategy):
        self.aggregation_strategy = aggregation_strategy

    @abstractmethod
    async def decide(self, findings: Sequence[AnalysisFindings], **kwargs) -> SecurityDecision:
        pass

@register_decision_engine(DecisionEngineKeys.PERMISSIVE)
class PermissiveDecisionEngine(DecisionEngine):
    async def decide(self, findings: Sequence[AnalysisFindings], **kwargs) -> SecurityDecision:
        if len(findings) == 0:
            raise ValueError('No findings, at least 1 required!')

        first_finding = findings[0]
        aggregated_findings = await self.aggregation_strategy.aggregate(findings)

        return SecurityDecision(
            upstream_app_id=first_finding.upstream_app_id,
            upstream_app_url=first_finding.upstream_app_url,
            analysis_engine_key=aggregated_findings.analysis_engine_key,
            decision_engine_key=DecisionEngineKeys.PERMISSIVE,
            aggregated_threat_type=aggregated_findings.threat_type,
            aggregated_threat_severity=aggregated_findings.threat_severity,
            action=SecurityActions.ALLOW,
            status_code=200,
            reason=(
                'Decision Engine: Allow always. '
                f'Analysis Findings: {aggregated_findings.explanation}'
                ),
            aggregated_risk_score=aggregated_findings.risk_score,
        )

@register_decision_engine(DecisionEngineKeys.RANDOM)
class RandomDecisionEngine(DecisionEngine):
    def __init__(
        self,
        seed: int | None = None,
        aggregation_strategy: AggregationStrategy | None = None,
    ):
        super().__init__(aggregation_strategy)
        self.rng = random.Random(seed)

    async def decide(self, findings: Sequence[AnalysisFindings], **kwargs) -> SecurityDecision:
        if len(findings) == 0:
            raise ValueError('No findings, at least 1 required!')
        
        action = self.rng.choice(list(SecurityActions))
        blocked = (action == SecurityActions.BLOCK)
        aggregated_findings = await self.aggregation_strategy.aggregate(findings)

        return SecurityDecision(
            upstream_app_id=aggregated_findings.upstream_app_id,
            upstream_app_url=aggregated_findings.upstream_app_url,
            analysis_engine_key=aggregated_findings.analysis_engine_key,
            decision_engine_key=DecisionEngineKeys.RANDOM,
            aggregated_threat_type=aggregated_findings.threat_type,
            aggregated_threat_severity=aggregated_findings.threat_severity,
            action=action,
            status_code=403 if blocked else 200,
            reason=(
                'Decision Engine: Action randomly decided. '
                f'Analysis Findings: {aggregated_findings.explanation}'
                ),
            aggregated_risk_score=aggregated_findings.risk_score,
        )
    