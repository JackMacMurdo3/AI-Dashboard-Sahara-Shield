import random
from abc import abstractmethod, ABC
from sahara_shield.app.model.enums import SecurityActions
from sahara_shield.app.model.orm import ProtectedApp
from sahara_shield.app.defense.marshal import SecurityDecision, InterceptedRequest

class DecisionEngine(ABC):
    @abstractmethod
    async def decide(self, req:InterceptedRequest, protected_app:ProtectedApp, **kwargs) -> SecurityDecision:
        pass

class RandomDecisionEngine(DecisionEngine):
    async def decide(self, req, protected_app, **kwargs):
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
    