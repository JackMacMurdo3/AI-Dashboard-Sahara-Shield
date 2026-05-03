from __future__ import annotations

import random
from abc import abstractmethod, ABC
from sahara_shield.app.model.enums import SecurityActions
from sahara_shield.app.model.orm import ProtectedApp
from sahara_shield.app.defense.marshal import SecurityDecision, InterceptedRequest
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
    async def decide(self, req:InterceptedRequest, protected_app:ProtectedApp) -> SecurityDecision:
        pass

@register_decision_engine(DecisionEngineKeys.RANDOM)
class RandomDecisionEngine(DecisionEngine):
    async def decide(self, req: InterceptedRequest, protected_app: ProtectedApp) -> SecurityDecision:
        should_block = bool(random.randint(0,1))

        return SecurityDecision(
            upstream_app_id=protected_app.id,
            upstream_app_url=protected_app.url,
            allow=not should_block,
            action=SecurityActions.BLOCK.value if should_block else SecurityActions.ALLOW.value,
            status_code=403 if should_block else 200,
            reason='Blocked!' if should_block else 'Allowed!',
            risk_score=100 if should_block else 0,
        )
    