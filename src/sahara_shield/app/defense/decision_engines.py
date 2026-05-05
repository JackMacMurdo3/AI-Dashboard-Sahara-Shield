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
    def __init__(self, aggregation_strategy: AggregationStrategy | None = None):
        self.aggregation_strategy = aggregation_strategy or MaxAggregationStrategy()

    @abstractmethod
    async def decide(self, findings: Sequence[AnalysisFindings]) -> SecurityDecision:
        pass

@register_decision_engine(DecisionEngineKeys.PERMISSIVE)
class PermissiveDecisionEngine(DecisionEngine):
    async def decide(self, findings: Sequence[AnalysisFindings]) -> SecurityDecision:
        if len(findings) == 0:
            raise ValueError('No findings, at least 1 required!')

        first_finding = findings[0]
        aggregated_findings = await self.aggregation_strategy.aggregate(findings)

        return SecurityDecision(
            upstream_app_id=first_finding.upstream_app_id,
            upstream_app_url=first_finding.upstream_app_url,
            decided_threat_type=aggregated_findings[1],
            decided_threat_severity=aggregated_findings[2],
            action=SecurityActions.ALLOW,
            status_code=200,
            reason=f'Allowed!',
            aggregated_risk_score=aggregated_findings[0],
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

    async def decide(self, findings: Sequence[AnalysisFindings]) -> SecurityDecision:
        if len(findings) == 0:
            raise ValueError('No findings, at least 1 required!')

        first_finding = findings[0]

        action = self.rng.choice(list(SecurityActions))
        blocked = (action == SecurityActions.BLOCK)
        aggregated_findings = await self.aggregation_strategy.aggregate(findings)

        return SecurityDecision(
            upstream_app_id=first_finding.upstream_app_id,
            upstream_app_url=first_finding.upstream_app_url,
            decided_threat_type=aggregated_findings[1],
            decided_threat_severity=aggregated_findings[2],
            action=action,
            status_code=403 if blocked else 200,
            reason=(
                f'Request was {action} actioned due to '
                f'{aggregated_findings[2]} severity {aggregated_findings[1]} threat.'
            ),
            aggregated_risk_score=aggregated_findings[0],
        )
    