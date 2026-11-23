"""Offline smoke tests for the collector."""
import base64
import json
import unittest

from collector import build_xray_config, extract_vless, parse_uri, select_candidates


REALITY = (
    'vless://11111111-2222-4333-8444-555555555555@example.org:443?'
    'type=tcp&security=reality&pbk=abc123&sid=deaf&fp=chrome&'
    'flow=xtls-rprx-vision&sni=www.example.com#RU'
)
TLS_WS = (
    'vless://11111111-2222-4333-8444-555555555555@192.0.2.2:443?'
    'type=ws&security=tls&host=example.org&sni=example.org&path=%2Fws'
)


class CollectorTests(unittest.TestCase):
    def test_parse_reality(self):
        node = parse_uri(REALITY, 'test', 'ru_whitelist')
        self.assertIsNotNone(node)
        config = build_xray_config(node, 39001)
        self.assertEqual(config['outbounds'][0]['streamSettings']['realitySettings']['publicKey'], 'abc123')
        self.assertEqual(config['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')

    def test_base64_extraction(self):
        payload = base64.b64encode((REALITY + '\n').encode()).decode()
        self.assertEqual(extract_vless(payload), [REALITY])

    def test_local_blocked(self):
        bad = REALITY.replace('example.org:443', '127.0.0.1:443')
        self.assertIsNone(parse_uri(bad, 'test', 'global'))
        self.assertIsNone(parse_uri(TLS_WS, 'test', 'global'))

    def test_dedupe_ignores_fragment(self):
        first = parse_uri(REALITY, 'a', 'ru_whitelist')
        second = parse_uri(REALITY.replace('#RU', '#Another'), 'b', 'global')
        self.assertEqual(first.dedupe_key, second.dedupe_key)

    def test_round_robin(self):
        first = parse_uri(REALITY, 'a', 'ru_whitelist')
        second = parse_uri(REALITY.replace('example.org', 'example.net'), 'b', 'global')
        nodes = select_candidates([first, second], 2)
        self.assertEqual(len(nodes), 2)


if __name__ == '__main__':
    unittest.main()
