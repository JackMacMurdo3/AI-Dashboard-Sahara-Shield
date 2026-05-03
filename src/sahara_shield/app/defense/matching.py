from functools import lru_cache
from starlette.routing import compile_path
from sahara_shield.app.model.orm import AppSecurityPolicy

def normalize_route_path(route_path: str) -> str:
	'''Normalize request paths/patterns for matching.'''

	normalized = (route_path or '').strip()
	if not normalized:
		return '/'

	if not normalized.startswith('/'):
		normalized = f'/{normalized}'

	if normalized != '/' and normalized.endswith('/'):
		normalized = normalized.rstrip('/')

	return normalized

@lru_cache(maxsize=1024)
def compile_starlette_route_pattern(route_pattern: str):
	'''Compile a Starlette-style route pattern into a cached matcher.'''

	return compile_path(normalize_route_path(route_pattern))

def match_starlette_route_pattern(
	route_pattern: str,
	request_path: str,
) -> dict[str, object] | None:
	'''Return extracted Starlette params when a pattern matches a request path.'''

	regex, _, param_convertors = compile_starlette_route_pattern(route_pattern)
	match = regex.match(normalize_route_path(request_path))
	if match is None:
		return None

	return {
		param_name: param_convertors[param_name].convert(param_value)
		for param_name, param_value in match.groupdict().items()
	}

def match_route_pattern(route_pattern: str, route_path: str) -> bool:
	'''Return True when a pattern matches a request path.'''

	return match_starlette_route_pattern(route_pattern, route_path) is not None

def match_app_security_policies(
	app_security_policies: list[AppSecurityPolicy],
	http_method: str,
	route_path: str,
	) -> list[AppSecurityPolicy]:
	'''
	Return all active policies that match the request, ordered by priority.
	'''

	normalized_method = (http_method or '').strip().upper()

	matching_policies = [
		policy
		for policy in app_security_policies
		if policy.active
		and policy.http_method.value.upper() == normalized_method
		and match_route_pattern(policy.route_pattern, route_path)
	]

	return sorted(
		matching_policies,
		key=lambda policy: (
			policy.priority,
			policy.id,
		),
		reverse=True,
	)
