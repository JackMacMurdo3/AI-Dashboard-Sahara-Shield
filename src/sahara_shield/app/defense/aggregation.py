from abc import ABC, abstractmethod
from collections.abc import Sequence
from sahara_shield.app.defense.marshal import AnalysisFindings
from sahara_shield.app.core.enums import AggregationStrategyKeys

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
	Aggregates one or more analysis findings into a single risk score.
	'''

	@abstractmethod
	async def aggregate(self, findings: Sequence[AnalysisFindings]) -> int:
		'''
		Computes a risk score from validated findings.
		'''
		pass

@register_aggregation_strategy(AggregationStrategyKeys.MAX)
class MaxAggregationStrategy(AggregationStrategy):
	'''
	Uses the highest engine risk score across all findings.
	'''

	async def aggregate(self, findings: Sequence[AnalysisFindings]) -> int:
		if len(findings) == 0:
			raise ValueError('No findings, at least 1 required!')

		return max(finding.risk_score for finding in findings)