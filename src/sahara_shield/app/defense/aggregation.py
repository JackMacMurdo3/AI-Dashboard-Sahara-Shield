from abc import ABC, abstractmethod
from collections.abc import Sequence
from sahara_shield.app.defense.marshal import AnalysisFindings
from sahara_shield.app.core.enums import AggregationStrategyKeys, ThreatSeverities, ThreatTypes

aggregation_strategies_registry: dict[AggregationStrategyKeys, type['AggregationStrategy']] = {}

def register_aggregation_strategy(name: AggregationStrategyKeys):
    '''
    Automatically registers an AggregationStrategy
    '''

    aggregation_strategy_key = AggregationStrategyKeys(name)

    def decorator(cls):
        if aggregation_strategy_key in aggregation_strategies_registry:
            raise ValueError(f'Aggregation key {aggregation_strategy_key} is already registered')

        aggregation_strategies_registry[aggregation_strategy_key] = cls

        return cls

    return decorator

class AggregationStrategy(ABC):
	'''
	Aggregates one or more analysis findings into one.
	'''

	@abstractmethod
	async def aggregate(self, findings: Sequence[AnalysisFindings]) -> AnalysisFindings:
		pass

@register_aggregation_strategy(AggregationStrategyKeys.MAX)
class MaxAggregationStrategy(AggregationStrategy):
	'''
	Uses the highest risk score across all findings.
	'''

	async def aggregate(self, findings: Sequence[AnalysisFindings]):
		if len(findings) == 0:
			raise ValueError('No findings, at least 1 required!')

		max_finding: AnalysisFindings|None = None
		for finding in findings:
			if max_finding is None or finding.risk_score > max_finding.risk_score:
				max_finding = finding

		return max_finding