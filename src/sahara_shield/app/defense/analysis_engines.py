import asyncio
import json
import random
from abc import abstractmethod, ABC
import httpx
from google import genai
from google.genai import types
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.core.enums import ThreatTypes, ThreatSeverities, AnalysisEngineKeys
from sahara_shield.app.defense.marshal import AnalysisFindings, InterceptedRequest
from sahara_shield.app.model.orm import ProtectedApp

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
        
        return cls

    return decorator

class AnalysisEngine(ABC):
    '''
    Performs security analysis of an intercepted HTTP request.
    '''

    @abstractmethod
    async def analyze(self, req:InterceptedRequest, protected_app:ProtectedApp, **kwargs) -> AnalysisFindings:
        pass

@register_analysis_engine(AnalysisEngineKeys.OPTIMISTIC)
class OptimisticAnalysisEngine(AnalysisEngine):
    '''
    Always assumes the best - nothing is ever a threat, nor is it severe!
    '''

    def __init__(self, seed:int|None=None):
        self.rng = random.Random(seed)

    async def analyze(self, req, protected_app, **kwargs):
        return AnalysisFindings(
            upstream_app_id=protected_app.id,
            upstream_app_url=protected_app.url,
            analysis_engine_key=AnalysisEngineKeys.OPTIMISTIC,
            threat_type=ThreatTypes.NONE,
            threat_severity=ThreatSeverities.NONE,
            risk_score=0,
        )
    
@register_analysis_engine(AnalysisEngineKeys.RANDOM)
class RandomAnalysisEngine(AnalysisEngine):
    def __init__(self, seed:int|None=None):
        self.rng = random.Random(seed)

    async def analyze(self, req, protected_app, **kwargs):
        return AnalysisFindings(
            upstream_app_id=protected_app.id,
            upstream_app_url=protected_app.url,
            analysis_engine_key=AnalysisEngineKeys.RANDOM,
            threat_type=self.rng.choice(list(ThreatTypes)),
            threat_severity=self.rng.choice(list(ThreatSeverities)),
            risk_score=self.rng.randint(0, 100),
        )

@register_analysis_engine(AnalysisEngineKeys.LLM_GEMINI)
class GeminiLLMAnalysisEngine(AnalysisEngine):
    '''
    Uses a Google Gemini chat completion endpoint to classify the request.
    '''

    def __init__(
        self,
        api_key:str,
        model:str,
    ):
        self.api_key = api_key
        self.client = genai.Client(api_key=self.api_key)
        self.model = model
        self.output_json_schema = AnalysisFindings.model_json_schema()

    def _build_prompt(self, req: InterceptedRequest, protected_app: ProtectedApp) -> str:
        return (
            'Analyze the following HTTP request for suspicious or malicious behavior.'
            '\n\n'
            f'URL: {protected_app.url}\n'
            f'Request method: {req.http_method}\n'
            f'Request path: {req.route_path}\n'
            f'Query string: {req.query_string}\n'
            f'Headers: {json.dumps(req.headers)}\n'
            f'Body: {req.body}\n'
        )

    def _coerce_threat_type(self, value: object) -> ThreatTypes:
        normalized = str(value).strip().lower()

        for threat_type in ThreatTypes:
            if threat_type.name.lower() == normalized or threat_type.value.lower() == normalized:
                return threat_type

        return ThreatTypes.UNKNOWN

    def _coerce_threat_severity(self, value: object) -> ThreatSeverities:
        normalized = str(value).strip().lower()

        for severity in ThreatSeverities:
            if severity.name.lower() == normalized or severity.value.lower() == normalized:
                return severity

        return ThreatSeverities.MODERATE

    def _coerce_risk_score(self, value: object) -> int:
        try:
            risk_score = int(value)
        except (TypeError, ValueError):
            return 0

        return max(0, min(100, risk_score))

    def _analyze(self, req: InterceptedRequest, protected_app: ProtectedApp) -> AnalysisFindings:
        response = self.client.models.generate_content(
            model=self.model,
            contents=self._build_prompt(req, protected_app),
            config=types.GenerateContentConfig(
                systemInstruction=(
                    'You are a senior network security analyst. '
                    'Use only the supplied request data '
                    'and return only valid JSON according to the provided schema. '
                    'Include an explanation of 100 words or fewer in the output JSON. '
                    'Explanation should include risk score and how you determined its value. '
                    ),
                temperature=1.0,
                responseMimeType='application/json',
                response_json_schema=self.output_json_schema,
            ),
        )

        parsed = response.parsed
        if parsed is None:
            content = response.text or ''
            if not content.strip():
                raise ValueError('Gemini returned an empty response')

            parsed = json.loads(content)

        threat_type = self._coerce_threat_type(parsed.get('threat_type', 'UNKNOWN'))
        threat_severity = self._coerce_threat_severity(parsed.get('threat_severity', 'MODERATE'))
        risk_score = self._coerce_risk_score(parsed.get('risk_score', 0))
        explanation = str(parsed.get('explanation', '')).strip()

        return AnalysisFindings(
            upstream_app_id=protected_app.id,
            upstream_app_url=protected_app.url,
            analysis_engine_key=AnalysisEngineKeys.LLM_GEMINI,
            threat_type=threat_type,
            threat_severity=threat_severity,
            risk_score=risk_score,
            explanation=explanation,
        )

    async def analyze(self, req, protected_app, **kwargs):
        '''
        Uses the Gemini API to send the request to a Gemini text generation model for analysis.
        See https://ai.google.dev/gemini-api/docs

        Note - this runs in a separate thread, since the API call is technically synchronous (blocking).
        '''

        try:
            return await asyncio.to_thread(self._analyze, req, protected_app)
        except Exception as e:
            return AnalysisFindings(
                upstream_app_id=protected_app.id,
                upstream_app_url=protected_app.url,
                analysis_engine_key=AnalysisEngineKeys.LLM_GEMINI,
                threat_type=ThreatTypes.UNKNOWN,
                threat_severity=ThreatSeverities.UNKNOWN,
                risk_score=0,
                explanation=f'Analysis failed due to an internal error. {e}',
            )
        