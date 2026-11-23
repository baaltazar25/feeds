#!/usr/bin/env python3
"""Collect VLESS public subscriptions and verify them through Xray-core."""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import tempfile
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID

import httpx

ROOT = Path(__file__).resolve().parent
SOURCES_PATH = ROOT / 'sources.json'
OUTPUT = ROOT / 'feeds'
XRAY_BIN = os.environ.get('XRAY_BIN', str(ROOT / 'bin' / 'xray'))
MAX_CANDIDATES = max(1, min(2000, int(os.environ.get('MAX_CANDIDATES', '240'))))
MAX_WORKERS = max(1, min(32, int(os.environ.get('MAX_WORKERS', '12'))))
PROBE_TIMEOUT = max(2.0, min(25.0, float(os.environ.get('PROBE_TIMEOUT', '9'))))
SOURCE_TIMEOUT = 18.0
MAX_SOURCE_BYTES = 5 * 1024 * 1024
TEST_URLS = (
    'https://www.gstatic.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
)
GROUPS = ('ru_whitelist', 'ru_general', 'global')
LINK_PATTERN = re.compile(r'vless://[^\s<>"\'`\]\[]+', re.IGNORECASE)
LOG = logging.getLogger('vless-feed')


@dataclass
class Node:
    uri: str
    host: str
    port: int
    user_id: str
    query: dict[str, str]
    security: str
    transport: str
    source: str
    groups: set[str] = field(default_factory=set)
    latency_ms: float | None = None

    @property
    def dedupe_key(self) -> str:
        # Ignore friendly name and browser fingerprint variants.
        important = (
            'sni', 'host', 'path', 'pbk', 'password', 'sid', 'spx',
            'flow', 'alpn', 'serviceName', 'mode', 'extra', 'encryption',
        )
        raw = json.dumps(
            [self.host.lower(), self.port, self.user_id.lower(),
             self.security, self.transport,
             [(k, self.query.get(k, '')) for k in important]],
            ensure_ascii=False, separators=(',', ':')
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def tag(self) -> str:
        return self.dedupe_key[:12]


def is_public_ip_literal(host: str) -> bool:
    """Reject literal local/private/reserved destinations, including IPv6."""
    try:
        address = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        # Domain names are allowed; dynamic DNS cannot be pinned here.
        return True
    return address.is_global


def parse_uri(uri: str, source: str, group: str) -> Node | None:
    uri = html.unescape(uri.strip().rstrip('.,;)'))
    try:
        parsed = urlsplit(uri)
        if parsed.scheme.lower() != 'vless' or not parsed.hostname or not parsed.port:
            return None
        host, port = parsed.hostname, parsed.port
        if not 1 <= port <= 65535 or not is_public_ip_literal(host):
            return None
        user_id = str(UUID(unquote(parsed.username or '')))
        q = {k: v[-1] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        transport = q.get('type', 'tcp').lower()
        if transport == 'splithttp':
            transport = 'xhttp'
        if transport not in ('tcp', 'raw', 'ws', 'grpc', 'xhttp', 'httpupgrade'):
            return None
        security = q.get('security', 'none').lower()
        if security not in ('reality', 'tls'):
            return None
        if security == 'reality' and not (q.get('pbk') or q.get('password')):
            return None
        if q.get('allowInsecure', '0').lower() in ('1', 'true') or q.get('insecure', '0').lower() in ('1', 'true'):
            # Do not make verified output depend on disabled certificate validation.
            return None
        if group not in GROUPS:
            return None
        return Node(uri=uri, host=host, port=port, user_id=user_id,
                    query=q, security=security, transport=transport,
                    source=source, groups={group})
    except (ValueError, TypeError):
        return None


def extract_vless(text: str) -> list[str]:
    """Handle plain URI lines, HTML/markdown snippets, and Base64 subscriptions."""
    cleaned = html.unescape(text.lstrip('\ufeff'))
    found = LINK_PATTERN.findall(cleaned)
    # Base64 may contain long plain lines or a single encoded blob.
    if len(found) == 0:
        compact = ''.join(cleaned.split())
        if len(compact) > 24 and re.fullmatch(r'[A-Za-z0-9_+/=\-]+', compact):
            try:
                decoded = base64.b64decode(
                    compact.replace('-', '+').replace('_', '/') + '=' * (-len(compact) % 4),
                    validate=True,
                ).decode('utf-8', errors='replace')
                found = LINK_PATTERN.findall(decoded)
            except (ValueError, UnicodeError):
                pass
    return found


async def fetch_source(client: httpx.AsyncClient, item: dict[str, str]) -> tuple[dict[str, str], list[str], str | None]:
    try:
        async with client.stream('GET', item['url'], timeout=SOURCE_TIMEOUT) as response:
            response.raise_for_status()
            parts: list[bytes] = []
            size = 0
            async for part in response.aiter_bytes():
                size += len(part)
                if size > MAX_SOURCE_BYTES:
                    raise ValueError('source exceeds 5 MiB')
                parts.append(part)
        text = b''.join(parts).decode('utf-8', errors='replace')
        links = extract_vless(text)
        if not links:
            raise ValueError('no VLESS URIs found')
        return item, links, None
    except (httpx.HTTPError, ValueError) as exc:
        return item, [], f'{type(exc).__name__}: {str(exc)[:160]}'


def build_xray_config(node: Node, port: int) -> dict[str, Any]:
    q = node.query
    user: dict[str, Any] = {'id': node.user_id, 'encryption': q.get('encryption') or 'none'}
    if q.get('flow'):
        user['flow'] = q['flow']

    network = 'raw' if node.transport in ('tcp', 'raw') else node.transport
    stream: dict[str, Any] = {'network': network, 'security': node.security}
    sni = q.get('sni') or q.get('serverName') or q.get('host') or node.host
    fingerprint = q.get('fp') or 'chrome'
    if fingerprint in ('random', 'randomized'):
        fingerprint = 'chrome'
    if node.security == 'reality':
        stream['realitySettings'] = {
            'serverName': sni, 'fingerprint': fingerprint,
            'publicKey': q.get('pbk') or q['password'],
            'shortId': q.get('sid', ''), 'spiderX': q.get('spx') or '/',
        }
    else:
        tls: dict[str, Any] = {
            'serverName': sni, 'allowInsecure': False,
            'fingerprint': fingerprint,
        }
        if q.get('alpn'):
            tls['alpn'] = [entry.strip() for entry in q['alpn'].split(',') if entry.strip()]
        stream['tlsSettings'] = tls

    if network == 'ws':
        ws: dict[str, Any] = {'path': q.get('path') or '/'}
        if q.get('host'):
            ws['headers'] = {'Host': q['host']}
        stream['wsSettings'] = ws
    elif network == 'grpc':
        grpc: dict[str, Any] = {'serviceName': q.get('serviceName') or ''}
        if q.get('authority'):
            grpc['authority'] = q['authority']
        if q.get('mode') == 'multi':
            grpc['multiMode'] = True
        stream['grpcSettings'] = grpc
    elif network == 'xhttp':
        xhttp: dict[str, Any] = {'path': q.get('path') or '/'}
        if q.get('host'):
            xhttp['host'] = q['host']
        if q.get('mode'):
            xhttp['mode'] = q['mode']
        if q.get('extra'):
            extra = json.loads(q['extra'])
            if not isinstance(extra, dict):
                raise ValueError('xhttp extra must be an object')
            xhttp['extra'] = extra
        stream['xhttpSettings'] = xhttp
    elif network == 'httpupgrade':
        upgrade: dict[str, Any] = {'path': q.get('path') or '/'}
        if q.get('host'):
            upgrade['host'] = q['host']
        stream['httpupgradeSettings'] = upgrade

    return {
        'log': {'loglevel': 'error'},
        'inbounds': [{
            'tag': 'local-socks', 'listen': '127.0.0.1', 'port': port,
            'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False},
        }],
        'outbounds': [{
            'tag': 'vless', 'protocol': 'vless',
            'settings': {'vnext': [{
                'address': node.host, 'port': node.port, 'users': [user],
            }]}, 'streamSettings': stream,
        }, {'tag': 'blocked', 'protocol': 'blackhole'}],
        'routing': {'rules': [{
            'type': 'field', 'inboundTag': ['local-socks'], 'outboundTag': 'vless',
        }]},
    }


def unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


async def await_proxy(port: int, proc: asyncio.subprocess.Process, deadline: float = 2.5) -> bool:
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        if proc.returncode is not None:
            return False
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', port), timeout=0.3,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.12)
    return False


async def check_node(node: Node, sem: asyncio.Semaphore) -> float | None:
    async with sem:
        port = unused_local_port()
        try:
            config = build_xray_config(node, port)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
        with tempfile.TemporaryDirectory(prefix='vless-check-') as tmp:
            config_path = Path(tmp) / 'config.json'
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
            try:
                proc = await asyncio.create_subprocess_exec(
                    XRAY_BIN, 'run', '-c', str(config_path),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except (OSError, ValueError) as exc:
                raise RuntimeError(f'cannot start Xray at {XRAY_BIN}: {exc}') from exc
            try:
                if not await await_proxy(port, proc):
                    return None
                async with httpx.AsyncClient(
                    proxy=f'socks5://127.0.0.1:{port}',
                    timeout=httpx.Timeout(PROBE_TIMEOUT),
                    trust_env=False, follow_redirects=False,
                ) as client:
                    start = time.monotonic()
                    for url in TEST_URLS:
                        try:
                            # This verifies VLESS transport plus real HTTPS via the tunnel.
                            response = await client.get(url)
                            if response.status_code == 204:
                                return round((time.monotonic() - start) * 1000, 1)
                        except httpx.HTTPError:
                            continue
                return None
            finally:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                else:
                    await proc.wait()


def select_candidates(nodes: list[Node], limit: int) -> list[Node]:
    """Interleave Russian-targeted and global pools so no single feed starves others."""
    pools: dict[str, list[Node]] = {name: [] for name in GROUPS}
    for node in nodes:
        # A candidate can have multiple group tags; count it only once.
        group = next(grp for grp in GROUPS if grp in node.groups)
        pools[group].append(node)
    # 2 : 2 : 1 favors sources focused on Russian networks.
    order = ('ru_whitelist', 'ru_general', 'ru_whitelist', 'ru_general', 'global')
    selected: list[Node] = []
    indexes = {name: 0 for name in GROUPS}
    while len(selected) < limit:
        advanced = False
        for group in order:
            if indexes[group] < len(pools[group]):
                selected.append(pools[group][indexes[group]])
                indexes[group] += 1
                advanced = True
                if len(selected) >= limit:
                    break
        if not advanced:
            break
    return selected


def write_text(name: str, content: str) -> None:
    destination = OUTPUT / name
    destination.write_text(content, encoding='utf-8', newline='\n')


def as_lines(nodes: list[Node]) -> str:
    return '\n'.join(node.uri for node in nodes) + ('\n' if nodes else '')


def html_index(stats: dict[str, Any]) -> str:
    date = html.escape(stats['updated_utc'])
    entries = [
        ('vless.txt', 'All verified VLESS (plain URI)'),
        ('vless_base64.txt', 'All verified VLESS (Base64)'),
        ('vless_reality.txt', 'Verified VLESS + REALITY'),
        ('ru_verified.txt', 'Verified nodes from RU-focused sources'),
        ('ru_whitelist_verified.txt', 'Verified RU whitelist candidates'),
        ('ru_candidates_unverified.txt', 'RU candidates: NOT verified'),
        ('status.json', 'Collection status and statistics'),
    ]
    links = '\n'.join(
        f'<li><a href="{html.escape(p)}">{html.escape(label)}</a></li>'
        for p, label in entries
    )
    return f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS Personal Feed</title><style>
body{{font:16px/1.6 system-ui,sans-serif;background:#101827;color:#ecf2ff;max-width:840px;margin:3rem auto;padding:0 1rem}}
a{{color:#80c9ff}}code{{color:#c4ebc0}}small{{color:#b9c3d4}}</style></head>
<body><h1>VLESS Personal Feed</h1><p>Last refresh: <code>{date}</code></p>
<p>Checked: <strong>{stats['tested']}</strong>, verified: <strong>{stats['verified']}</strong>,
RU-focused verified: <strong>{stats['ru_verified']}</strong>.</p><ul>{links}</ul>
<small>Verification location: GitHub-hosted runner, not a Russian ISP. A successful connection does not prove bypass capability inside Russia. Never use unverified feed for sensitive traffic.</small>
</body></html>'''


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    if not Path(XRAY_BIN).exists():
        raise RuntimeError(f'Xray binary not found: {XRAY_BIN}')
    sources = json.loads(SOURCES_PATH.read_text(encoding='utf-8'))
    if not isinstance(sources, list) or not sources:
        raise ValueError('sources.json must be a nonempty list')
    for item in sources:
        if item['group'] not in GROUPS or not item['url'].startswith('https://'):
            raise ValueError(f'Invalid source entry: {item.get("name", "unknown")}')

    async with httpx.AsyncClient(
        headers={'User-Agent': 'VLESS-Personal-Feed/1.0'},
        trust_env=False, follow_redirects=True,
        limits=httpx.Limits(max_connections=12),
    ) as client:
        results = await asyncio.gather(*(fetch_source(client, item) for item in sources))

    by_key: dict[str, Node] = {}
    source_status = []
    available_sources = 0
    for item, links, error in results:
        if error is None:
            available_sources += 1
        accepted = 0
        for uri in links:
            node = parse_uri(uri, item['name'], item['group'])
            if node is None:
                continue
            accepted += 1
            key = node.dedupe_key
            if key in by_key:
                by_key[key].groups.add(item['group'])
            else:
                by_key[key] = node
        source_status.append({
            'name': item['name'], 'group': item['group'],
            'fetched_links': len(links), 'parsed_links': accepted,
            'error': error,
        })
        LOG.info('Source %-24s fetched=%5d valid=%5d error=%s',
                 item['name'], len(links), accepted, error or '-')

    if not available_sources or not by_key:
        raise RuntimeError('All sources unavailable or no valid VLESS nodes; retaining prior feeds')

    nodes = select_candidates(list(by_key.values()), MAX_CANDIDATES)
    LOG.info('Unique nodes=%d; testing=%d; workers=%d', len(by_key), len(nodes), MAX_WORKERS)
    sem = asyncio.Semaphore(MAX_WORKERS)
    # No credentials or connection URIs in logs.
    latencies = await asyncio.gather(*(check_node(node, sem) for node in nodes))
    passed = []
    for node, latency in zip(nodes, latencies):
        if latency is not None:
            node.latency_ms = latency
            passed.append(node)

    if not passed:
        raise RuntimeError('No nodes passed HTTPS-through-Xray verification; retaining prior feeds')

    order = {'ru_whitelist': 0, 'ru_general': 1, 'global': 2}
    passed.sort(key=lambda n: (min(order[g] for g in n.groups), n.latency_ms or 999999))
    ru_verified = [n for n in passed if n.groups & {'ru_general', 'ru_whitelist'}]
    ru_white_verified = [n for n in passed if 'ru_whitelist' in n.groups]
    ru_candidates = [n for n in nodes if n.groups & {'ru_general', 'ru_whitelist'}]
    reality_verified = [n for n in passed if n.security == 'reality']

    OUTPUT.mkdir(exist_ok=True)
    plain = as_lines(passed)
    write_text('vless.txt', plain)
    write_text('vless_base64.txt', base64.b64encode(plain.encode()).decode() + '\n')
    write_text('vless_reality.txt', as_lines(reality_verified))
    write_text('ru_verified.txt', as_lines(ru_verified))
    write_text('ru_whitelist_verified.txt', as_lines(ru_white_verified))
    write_text('ru_candidates_unverified.txt', as_lines(ru_candidates))
    status = {
        'updated_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'runner_location': 'GitHub-hosted runner (not guaranteed Russia)',
        'unique_collected': len(by_key),
        'tested': len(nodes),
        'verified': len(passed),
        'ru_verified': len(ru_verified),
        'ru_whitelist_verified': len(ru_white_verified),
        'reality_verified': len(reality_verified),
        'verified_by_transport': dict(Counter(n.transport for n in passed)),
        'sources': source_status,
    }
    write_text('status.json', json.dumps(status, indent=2, ensure_ascii=False) + '\n')
    write_text('index.html', html_index(status))
    LOG.info('Verified=%d RU=%d REALITY=%d', len(passed), len(ru_verified), len(reality_verified))


if __name__ == '__main__':
    asyncio.run(main())
