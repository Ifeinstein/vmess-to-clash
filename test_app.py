import base64
import json
import unittest
from urllib.parse import parse_qs, quote

import app


def encode_vmess(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return f"vmess://{encoded}"


SAMPLE_LINK = encode_vmess(
    {
        "v": "2",
        "ps": "demo-node",
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/websocket",
        "tls": "tls",
        "sni": "sni.example.com",
    }
)

SAMPLE_VLESS_LINK = (
    "vless://22222222-2222-2222-2222-222222222222@example.org:8443"
    "?type=ws&security=tls&sni=sni.example.org&host=cdn.example.org&path=%2Fvless&fp=chrome"
    "#vless-node"
)

SAMPLE_VLESS_REALITY_LINK = (
    "vless://33333333-3333-3333-3333-333333333333@reality.example.org:443"
    "?type=tcp&security=reality&sni=www.example.org&fp=chrome"
    "&flow=xtls-rprx-vision&pbk=public-key-value&sid=abcd&spx=%2F"
    "#reality-node"
)


class ConverterTests(unittest.TestCase):
    def test_decode_and_convert_vmess(self) -> None:
        decoded = app.decode_vmess_link(SAMPLE_LINK)
        proxy = app.vmess_to_clash_proxy(decoded, 1)

        self.assertEqual(proxy["name"], "demo-node")
        self.assertEqual(proxy["server"], "example.com")
        self.assertEqual(proxy["network"], "ws")
        self.assertFalse(proxy["udp"])
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cdn.example.com")

    def test_decode_and_convert_vless(self) -> None:
        decoded = app.decode_vless_link(SAMPLE_VLESS_LINK)
        proxy = app.vless_to_clash_proxy(decoded, 1)

        self.assertEqual(proxy["name"], "vless-node")
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["server"], "example.org")
        self.assertEqual(proxy["port"], 8443)
        self.assertEqual(proxy["uuid"], "22222222-2222-2222-2222-222222222222")
        self.assertEqual(proxy["network"], "ws")
        self.assertFalse(proxy["udp"])
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["servername"], "sni.example.org")
        self.assertEqual(proxy["client-fingerprint"], "chrome")
        self.assertEqual(proxy["ws-opts"]["path"], "/vless")
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cdn.example.org")

    def test_build_clash_config_supports_mixed_links(self) -> None:
        config = app.build_clash_config([SAMPLE_LINK, SAMPLE_VLESS_LINK], "Demo")
        rendered = app.config_to_yaml(config)

        self.assertIn('name: "demo-node"', rendered)
        self.assertIn('type: "vmess"', rendered)
        self.assertIn('name: "vless-node"', rendered)
        self.assertIn('type: "vless"', rendered)
        self.assertIn('server: "example.org"', rendered)

    def test_convert_vless_reality_options(self) -> None:
        proxy = app.link_to_clash_proxy(SAMPLE_VLESS_REALITY_LINK, 1)

        self.assertEqual(proxy["name"], "reality-node")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(proxy["reality-opts"]["public-key"], "public-key-value")
        self.assertEqual(proxy["reality-opts"]["short-id"], "abcd")
        self.assertEqual(proxy["reality-opts"]["spider-x"], "/")

    def test_sub_query_rebuilds_unencoded_vless_params(self) -> None:
        query = parse_qs(
            "url=vless://33333333-3333-3333-3333-333333333333@reality.example.org:443?type=tcp"
            "&encryption=none&security=reality&sni=www.example.org&fp=chrome"
            "&flow=xtls-rprx-vision&pbk=public-key-value&sid=abcd&spx=%2F"
            "&default_rules=1"
        )
        links = app.links_from_sub_query(query)
        proxy = app.link_to_clash_proxy(links[0], 1)

        self.assertTrue(app.truthy(query["default_rules"][-1]))
        self.assertEqual(proxy["reality-opts"]["public-key"], "public-key-value")
        self.assertEqual(proxy["reality-opts"]["spider-x"], "/")

    def test_encoded_sub_query_with_default_rules(self) -> None:
        encoded_link = quote(SAMPLE_VLESS_REALITY_LINK, safe="")
        query = parse_qs(f"url={encoded_link}&default_rules=1")
        config = app.build_clash_config(
            app.links_from_sub_query(query),
            use_default_rules=app.truthy(query["default_rules"][-1]),
        )
        rendered = app.config_to_yaml(config)

        self.assertIn("rule-providers:", rendered)
        self.assertIn("RULE-SET,proxy,Proxy Subscription", rendered)

    def test_direct_subscription_path_encodes_links(self) -> None:
        path = app.direct_subscription_path([SAMPLE_VLESS_REALITY_LINK], use_default_rules=True)

        self.assertTrue(path.startswith("/sub?url=vless%3A%2F%2F"))
        self.assertIn("%23reality-node", path)
        self.assertTrue(path.endswith("&default_rules=1"))

    def test_direct_subscription_path_includes_udp_when_enabled(self) -> None:
        path = app.direct_subscription_path([SAMPLE_LINK], use_udp=True)

        self.assertTrue(path.endswith("&udp=1"))

    def test_one_time_subscription_response_does_not_store_links(self) -> None:
        response = app.one_time_subscription_response(
            [SAMPLE_VLESS_REALITY_LINK],
            "Demo",
            use_default_rules=True,
            use_udp=True,
            base_url="https://example.test:8443",
        )

        self.assertNotIn("id", response)
        self.assertNotIn("links", response)
        self.assertEqual(response["links_count"], 1)
        self.assertTrue(response["use_udp"])
        self.assertTrue(response["subscription_url"].startswith("https://example.test:8443/sub?url="))
        self.assertIn("%23reality-node", response["subscription_url"])
        self.assertTrue(response["subscription_url"].endswith("&default_rules=1&udp=1"))

    def test_build_clash_config_enables_udp_when_requested(self) -> None:
        config = app.build_clash_config([SAMPLE_LINK, SAMPLE_VLESS_LINK], use_udp=True)

        for proxy in config["proxies"]:
            self.assertTrue(proxy["udp"])

    def test_build_clash_config_contains_group(self) -> None:
        config = app.build_clash_config([SAMPLE_LINK], "Demo")
        rendered = app.config_to_yaml(config)

        self.assertIn('name: "Demo"', rendered)
        self.assertIn('server: "example.com"', rendered)
        self.assertIn('MATCH,Demo', rendered)
        self.assertNotIn("rule-providers:", rendered)

    def test_build_clash_config_with_default_rules(self) -> None:
        config = app.build_clash_config([SAMPLE_LINK], "Demo", use_default_rules=True)
        rendered = app.config_to_yaml(config)

        self.assertIn("rule-providers:", rendered)
        self.assertIn("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt", rendered)
        self.assertIn("RULE-SET,proxy,Demo", rendered)
        self.assertIn("MATCH,Demo", rendered)

if __name__ == "__main__":
    unittest.main()
