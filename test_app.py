import base64
import json
import tempfile
import unittest
from pathlib import Path

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


class ConverterTests(unittest.TestCase):
    def test_decode_and_convert_vmess(self) -> None:
        decoded = app.decode_vmess_link(SAMPLE_LINK)
        proxy = app.vmess_to_clash_proxy(decoded, 1)

        self.assertEqual(proxy["name"], "demo-node")
        self.assertEqual(proxy["server"], "example.com")
        self.assertEqual(proxy["network"], "ws")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cdn.example.com")

    def test_build_clash_config_contains_group(self) -> None:
        config = app.build_clash_config([SAMPLE_LINK], "Demo")
        rendered = app.config_to_yaml(config)

        self.assertIn('name: "Demo"', rendered)
        self.assertIn('server: "example.com"', rendered)
        self.assertIn('MATCH,Demo', rendered)


class StoreTests(unittest.TestCase):
    def test_store_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = app.SubscriptionStore(Path(temp_dir) / "subscriptions.json")
            created = store.upsert(None, "Demo", [SAMPLE_LINK])
            fetched = store.get(created.id)

            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.name, "Demo")
            self.assertEqual(fetched.links, [SAMPLE_LINK])


if __name__ == "__main__":
    unittest.main()
