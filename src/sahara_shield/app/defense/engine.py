from sahara_shield.app.model.enums import SecurityActions
from sahara_shield.app.model.orm import ProtectedApp
from sahara_shield.app.defense.marshal import DefenseCheckDecision, DefenseCheckRequest

def make_decision(req: DefenseCheckRequest, protected_app: ProtectedApp) -> DefenseCheckDecision:
    '''
    Return allow/block decision.
    '''

    should_block = False

    if should_block:
        return DefenseCheckDecision(
            allow=False,
            action=SecurityActions.BLOCK.value,
            status_code=403,
            reason='Blocked!',
            upstream_url=protected_app.url,
            risk_score=100,
        )

    return DefenseCheckDecision(
        allow=True,
        action=SecurityActions.ALLOW.value,
        status_code=200,
        reason='Allowed!',
        upstream_url=protected_app.url,
        risk_score=0,
    )
