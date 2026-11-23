#!/usr/bin/env python3
"""Install official Linux Xray release with GitHub-provided SHA256 verification."""
from __future__ import annotations

from hashlib import sha256
import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile


RELEASE_API = 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'
ASSET_NAME = 'Xray-linux-64.zip'
DEST = Path(__file__).resolve().parent.parent / 'bin' / 'xray'


def retrieve(url: str) -> bytes:
    headers = {'User-Agent': 'Personal-VLESS-Collector/1.0', 'Accept': 'application/vnd.github+json'}
    if url.startswith('https://api.github.com/') and (token := os.environ.get('GITHUB_TOKEN')):
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as response:
        return response.read()


def main() -> None:
    release = json.loads(retrieve(RELEASE_API))
    asset = next((item for item in release.get('assets', []) if item.get('name') == ASSET_NAME), None)
    if not asset:
        raise RuntimeError(f'Xray release asset not found: {ASSET_NAME}')
    expected = asset.get('digest', '')
    if not expected.startswith('sha256:'):
        raise RuntimeError('GitHub API returned no asset SHA256 digest; refusing unchecked binary')
    blob = retrieve(asset['browser_download_url'])
    actual = sha256(blob).hexdigest()
    if actual.lower() != expected.split(':', 1)[1].lower():
        raise RuntimeError('Xray archive SHA256 verification FAILED')
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        data = archive.read('xray')
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_bytes(data)
    DEST.chmod(0o755)
    print(f'Xray installed: {DEST} (release: {release.get("tag_name")}, SHA256 verified)')


if __name__ == '__main__':
    main()
