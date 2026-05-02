'''Tiny reverse proxy for Option 3b (one proxy process per protected app).'''

import argparse
import argparse
import httpx
import tomllib
import uvicorn
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from argparse import Namespace

HOP_BY_HOP_HEADERS = {
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
}

DEFAULT_REQUEST_TIMEOUT = 15.0

@dataclass
class ProxyConfig:
    proxy_name: str
    listen_host: str
    listen_port: int
    protected_app_id: int
    shield_host: str
    shield_port: int
    shield_defense_api: str
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT

    @property
    def defense_check_url(self) -> str:
        base = f'http://{self.shield_host}:{self.shield_port}'
        return _build_upstream_url(base, self.shield_defense_api, '')

def make_args_parser():
    parser = argparse.ArgumentParser(description='Run one reverse proxy instance for a protected app.')
    parser.add_argument(
        '--config',
        required=True,
        help='Path to TOML config file for this proxy instance.',
    )
    return parser

def load_config(path: Path) -> ProxyConfig:
    with path.open('rb') as f:
        data = tomllib.load(f)

    return ProxyConfig(
        proxy_name=str(data['proxy_name']),
        listen_host=str(data['listen_host']),
        listen_port=int(data['listen_port']),
        protected_app_id=int(data['protected_app_id']),
        shield_host=str(data['shield_host']),
        shield_port=int(data['shield_port']),
        shield_defense_api=str(data['shield_defense_api']),
        request_timeout_seconds=float(data.get('request_timeout_seconds', DEFAULT_REQUEST_TIMEOUT)),
    )

def _strip_hop_by_hop_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        header: val
        for header, val in headers.items()
        if header.lower() not in HOP_BY_HOP_HEADERS and header.lower() != 'host'
    }

def _build_upstream_url(base_url: str, path: str, query: str) -> str:
    base = base_url.rstrip('/')
    full = f"{base}/{path.lstrip('/')}"

    parts = urlsplit(full)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

def _rewrite_location_header(location: str, upstream_base: str, proxy_base: str) -> str:
    '''Rewrite redirect Location from upstream URL to proxy URL.'''
    if not location:
        return location

    loc_parts = urlsplit(location)
    upstream_parts = urlsplit(upstream_base)

    if loc_parts.scheme == upstream_parts.scheme and loc_parts.netloc == upstream_parts.netloc:
        proxy_parts = urlsplit(proxy_base)
        return urlunsplit((
            proxy_parts.scheme,
            proxy_parts.netloc,
            loc_parts.path,
            loc_parts.query,
            loc_parts.fragment,
        ))

    return location

def create_app(cfg: ProxyConfig) -> FastAPI:
    app = FastAPI(title=f'{cfg.proxy_name}-reverse-proxy')
    logger = logging.getLogger('sahara_shield.proxy')
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    @app.api_route('/{proxy_path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    async def proxy_all(request: Request, proxy_path: str):
        body = await request.body()
        query_string = request.url.query
        incoming_headers = dict(request.headers)
        payload = {
            'protected_app_id': cfg.protected_app_id,
            'http_method': request.method,
            'route_path': f"/{proxy_path}",
            'query_string': query_string,
            'headers': incoming_headers,
            'body': body.decode('utf-8', errors='replace'),
            'source_ip': request.client.host if request.client else None,
        }

        timeout = httpx.Timeout(cfg.request_timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            try:
                defense_resp = await client.post(cfg.defense_check_url, json=payload)
            except Exception as e:
                return JSONResponse(
                    status_code=502,
                    content={
                        'detail': f'Defense service unavailable: {e}',
                    },
                )

            if defense_resp.status_code != 200:
                return JSONResponse(
                    status_code=502,
                    content={
                        'detail': 'Defense service returned non-200 status',
                        'defense_status_code': defense_resp.status_code,
                        'defense_body': defense_resp.text,
                    },
                )

            decision = defense_resp.json()
            logger.debug('Defense decision: %s', decision)

            if not bool(decision.get('allow')):
                status_code = int(decision.get('status_code', 403))
                reason = str(decision.get('reason', 'Blocked by defense decision'))
                return JSONResponse(status_code=status_code, content={'detail': reason})
            
            upstream_base_url = decision.get('upstream_url')

            upstream_url = _build_upstream_url(
                upstream_base_url,
                path=proxy_path,
                query=query_string,
            )

            upstream_headers = _strip_hop_by_hop_headers(incoming_headers)

            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url,
                content=body,
                headers=upstream_headers,
            )

        response_headers = _strip_hop_by_hop_headers(dict(upstream_resp.headers))

        # rewrite redirect Location headers to keep requests within the proxy
        if 300 <= upstream_resp.status_code < 400 and 'location' in response_headers:
            proxy_base = f'http://{cfg.listen_host}:{cfg.listen_port}'
            response_headers['location'] = _rewrite_location_header(
                response_headers['location'],
                upstream_base_url,
                proxy_base,
            )

        # send response from upstream protected app back to the client
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=response_headers,
            media_type=upstream_resp.headers.get('content-type'),
        )

    return app

def main(args:Namespace) -> None:
    cfg = load_config(Path(args.config))
    app = create_app(cfg)

    uvicorn.run(app, host=cfg.listen_host, port=cfg.listen_port)

if __name__ == '__main__':
    args = make_args_parser().parse_args()
    main(args)
