import argparse
import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
STORE_PATH = DATA_DIR / "subscriptions.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def decode_vmess_link(link: str) -> dict[str, Any]:
    if not link.startswith("vmess://"):
        raise ValueError("Only vmess:// links are supported")

    encoded = link[len("vmess://") :].strip()
    padding = "=" * (-len(encoded) % 4)
    try:
        payload = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        data = json.loads(payload)
    except Exception as exc:
        raise ValueError("Invalid vmess link payload") from exc

    return data


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "tls"}


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def clean_host_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        values = raw
    else:
        text = str(raw).strip()
        if not text:
            return []
        values = [part.strip() for part in text.split(",")]
    return [item for item in values if item]


def pick_name(vmess: dict[str, Any], index: int) -> str:
    return (
        str(vmess.get("ps") or "").strip()
        or f'{vmess.get("add", "node")}:{vmess.get("port", "") or index}'
    )


def vmess_to_clash_proxy(vmess: dict[str, Any], index: int) -> dict[str, Any]:
    server = str(vmess.get("add") or "").strip()
    uuid = str(vmess.get("id") or "").strip()
    port = as_int(vmess.get("port"), 443)

    if not server or not uuid:
        raise ValueError("vmess entry is missing add or id")

    network = str(vmess.get("net") or "tcp").strip().lower() or "tcp"
    tls_enabled = truthy(vmess.get("tls"))
    host = str(vmess.get("host") or "").strip()
    path = str(vmess.get("path") or "").strip()
    sni = str(vmess.get("sni") or "").strip()
    alpn = clean_host_list(vmess.get("alpn"))
    fingerprint = str(vmess.get("fp") or "").strip()

    proxy: dict[str, Any] = {
        "name": pick_name(vmess, index),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": as_int(vmess.get("aid"), 0),
        "cipher": str(vmess.get("scy") or "auto").strip() or "auto",
        "udp": True,
        "tls": tls_enabled,
        "network": network,
    }

    if tls_enabled:
        proxy["servername"] = sni or host or server
    if alpn:
        proxy["alpn"] = alpn
    if truthy(vmess.get("allowInsecure")):
        proxy["skip-cert-verify"] = True
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint

    if network == "ws":
        ws_opts: dict[str, Any] = {}
        if path:
            ws_opts["path"] = path
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif network == "http":
        http_opts: dict[str, Any] = {}
        if path:
            http_opts["path"] = [path]
        if host:
            http_opts["headers"] = {"Host": [host]}
        if http_opts:
            proxy["http-opts"] = http_opts
    elif network == "h2":
        h2_opts: dict[str, Any] = {}
        hosts = clean_host_list(host)
        if hosts:
            h2_opts["host"] = hosts
        if path:
            h2_opts["path"] = path
        if h2_opts:
            proxy["h2-opts"] = h2_opts
    elif network == "grpc":
        grpc_opts: dict[str, Any] = {}
        service_name = path.lstrip("/")
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts

    return proxy


def extract_vmess_links(text: str) -> list[str]:
    links: list[str] = []
    for line in text.replace("\r", "\n").split("\n"):
        candidate = line.strip()
        if candidate.startswith("vmess://"):
            links.append(candidate)
    return links


def build_clash_config(links: list[str], subscription_name: str = "VMess Subscription") -> dict[str, Any]:
    if not links:
        raise ValueError("No vmess links supplied")

    proxies = [vmess_to_clash_proxy(decode_vmess_link(link), index) for index, link in enumerate(links, start=1)]
    proxy_names = [proxy["name"] for proxy in proxies]

    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": subscription_name,
                "type": "select",
                "proxies": proxy_names + ["DIRECT"],
            }
        ],
        "rules": [
            f"MATCH,{subscription_name}",
        ],
    }


def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def dump_yaml(value: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)

    if isinstance(value, list):
        if not value:
            return f"{prefix}[]"
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                rendered = dump_yaml(item, indent + 2).splitlines()
                first, *rest = rendered
                lines.append(f"{prefix}- {first.strip()}")
                lines.extend(rest)
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return "\n".join(lines)

    return f"{prefix}{yaml_scalar(value)}"


def config_to_yaml(config: dict[str, Any]) -> str:
    return dump_yaml(config) + "\n"


@dataclass
class Subscription:
    id: str
    name: str
    links: list[str]
    created_at: str
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "links": self.links,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subscription":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            links=[str(link) for link in data.get("links", [])],
            created_at=str(data["created_at"]),
            updated_at=str(data["updated_at"]),
        )


class SubscriptionStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}", encoding="utf-8")

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save(self, payload: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def all(self) -> list[Subscription]:
        raw = self._load()
        return [Subscription.from_dict(item) for item in raw.values()]

    def get(self, subscription_id: str) -> Subscription | None:
        raw = self._load().get(subscription_id)
        if not raw:
            return None
        return Subscription.from_dict(raw)

    def upsert(self, subscription_id: str | None, name: str, links: list[str]) -> Subscription:
        payload = self._load()
        now = utc_now_iso()
        if subscription_id and subscription_id in payload:
            created_at = payload[subscription_id]["created_at"]
            actual_id = subscription_id
        else:
            created_at = now
            actual_id = subscription_id or secrets.token_urlsafe(8)

        item = Subscription(
            id=actual_id,
            name=name,
            links=links,
            created_at=created_at,
            updated_at=now,
        )
        payload[actual_id] = item.as_dict()
        self._save(payload)
        return item


class AppHandler(BaseHTTPRequestHandler):
    store = SubscriptionStore(STORE_PATH)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_html(self.render_index())
            return

        if parsed.path == "/health":
            self._send_json({"status": "ok", "time": utc_now_iso()})
            return

        if parsed.path == "/api/subscriptions":
            subscriptions = [self.subscription_to_response(item) for item in self.store.all()]
            self._send_json({"items": subscriptions})
            return

        if parsed.path.startswith("/api/subscriptions/"):
            subscription_id = parsed.path.rsplit("/", 1)[-1]
            subscription = self.store.get(subscription_id)
            if not subscription:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Subscription not found")
                return
            self._send_json(self.subscription_to_response(subscription))
            return

        if parsed.path.startswith("/subscriptions/"):
            subscription_id = parsed.path.rsplit("/", 1)[-1]
            subscription = self.store.get(subscription_id)
            if not subscription:
                self._send_error_yaml(HTTPStatus.NOT_FOUND, "Subscription not found")
                return
            self._send_yaml(config_to_yaml(build_clash_config(subscription.links, subscription.name)))
            return

        if parsed.path == "/sub":
            query = parse_qs(parsed.query)
            links = [item for item in query.get("url", []) if item.strip()]
            if not links and "text" in query:
                links = extract_vmess_links("\n".join(query["text"]))
            try:
                config = build_clash_config(links)
            except ValueError as exc:
                self._send_error_yaml(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_yaml(config_to_yaml(config))
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        payload = self.read_json_body()
        if payload is None:
            return

        if parsed.path == "/convert":
            links = self.links_from_payload(payload)
            name = str(payload.get("name") or "VMess Subscription")
            try:
                config = build_clash_config(links, name)
            except ValueError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_yaml(config_to_yaml(config))
            return

        if parsed.path == "/api/subscriptions":
            links = self.links_from_payload(payload)
            name = str(payload.get("name") or "VMess Subscription").strip() or "VMess Subscription"
            try:
                build_clash_config(links, name)
            except ValueError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return

            subscription = self.store.upsert(None, name, links)
            self._send_json(self.subscription_to_response(subscription), status=HTTPStatus.CREATED)
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found")

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/subscriptions/"):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found")
            return

        subscription_id = parsed.path.rsplit("/", 1)[-1]
        if not self.store.get(subscription_id):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Subscription not found")
            return

        payload = self.read_json_body()
        if payload is None:
            return

        links = self.links_from_payload(payload)
        name = str(payload.get("name") or "VMess Subscription").strip() or "VMess Subscription"
        try:
            build_clash_config(links, name)
        except ValueError as exc:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        subscription = self.store.upsert(subscription_id, name, links)
        self._send_json(self.subscription_to_response(subscription))

    def read_json_body(self) -> dict[str, Any] | None:
        length = as_int(self.headers.get("Content-Length"), 0)
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Body must be valid JSON")
            return None

    def links_from_payload(self, payload: dict[str, Any]) -> list[str]:
        urls = payload.get("urls")
        if isinstance(urls, list):
            links = [str(item).strip() for item in urls if str(item).strip()]
        else:
            links = []
        if not links and payload.get("text"):
            links = extract_vmess_links(str(payload["text"]))
        return links

    def render_index(self) -> str:
        subscriptions = self.store.all()
        rows = "".join(
            f"""
            <tr>
              <td>{self.escape_html(item.name)}</td>
              <td><code>/subscriptions/{self.escape_html(item.id)}</code></td>
              <td>{len(item.links)}</td>
              <td>{self.escape_html(item.updated_at)}</td>
            </tr>
            """
            for item in subscriptions
        )
        if not rows:
            rows = '<tr><td colspan="4">还没有订阅，先在上面的表单里粘贴 vmess 链接。</td></tr>'

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VMess 转 Clash 订阅</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f1e8;
      --card: #fffaf2;
      --text: #1f2937;
      --line: #d5c6ad;
      --accent: #b45309;
      --accent-soft: #fde7c1;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "PingFang SC", sans-serif;
      background:
        radial-gradient(circle at top left, #ffe7ba 0, transparent 34%),
        linear-gradient(180deg, #f6f1e8 0%, #efe6d8 100%);
      color: var(--text);
    }}
    main {{
      max-width: 920px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .hero {{
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: rgba(255, 250, 242, 0.88);
      backdrop-filter: blur(8px);
      box-shadow: 0 20px 40px rgba(95, 63, 24, 0.08);
    }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .grid {{
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 20px;
      margin-top: 20px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 20px;
      background: var(--card);
    }}
    textarea, input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 14px;
      font: inherit;
      background: white;
    }}
    textarea {{ min-height: 220px; resize: vertical; }}
    button {{
      border: none;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      background: var(--accent);
      color: white;
    }}
    .hint {{
      margin: 10px 0 0;
      color: #6b7280;
      font-size: 0.94rem;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      border-radius: 16px;
      padding: 16px;
      background: #2a2114;
      color: #fef3c7;
      min-height: 220px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 14px;
      font-size: 0.95rem;
    }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
    }}
    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 0.85rem;
      font-weight: 700;
    }}
    @media (max-width: 760px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <span class="pill">Zero dependency service</span>
      <h1>VMess 地址转 Clash 订阅</h1>
      <p>把一个或多个 <code>vmess://</code> 链接粘进来，服务会生成可持久访问的 Clash 订阅地址，也支持直接用接口调用。</p>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>创建订阅</h2>
        <form id="create-form">
          <label for="name">订阅名称</label>
          <input id="name" name="name" value="My VMess Subscription">
          <p class="hint">每行一个 vmess 链接。</p>
          <textarea id="text" name="text" placeholder="vmess://..."></textarea>
          <button type="submit">生成订阅链接</button>
        </form>
      </div>

      <div class="panel">
        <h2>结果</h2>
        <pre id="result">提交后会在这里显示 JSON 响应和订阅地址。</pre>
      </div>
    </section>

    <section class="panel" style="margin-top: 20px;">
      <h2>已有订阅</h2>
      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>订阅路径</th>
            <th>节点数</th>
            <th>更新时间</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
  </main>
  <script>
    const form = document.getElementById('create-form');
    const result = document.getElementById('result');
    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      const payload = {{
        name: form.name.value,
        text: form.text.value
      }};
      const response = await fetch('/api/subscriptions', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      const text = await response.text();
      result.textContent = text;
      if (response.ok) {{
        setTimeout(() => window.location.reload(), 500);
      }}
    }});
  </script>
</body>
</html>"""

    def subscription_to_response(self, item: Subscription) -> dict[str, Any]:
        return {
            "id": item.id,
            "name": item.name,
            "links_count": len(item.links),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
            "subscription_path": f"/subscriptions/{item.id}",
            "subscription_url": self.absolute_url(f"/subscriptions/{item.id}"),
        }

    def absolute_url(self, path: str) -> str:
        host = self.headers.get("Host", "127.0.0.1:8000")
        return f"http://{host}{path}"

    def escape_html(self, text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_yaml(self, text: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _send_error_yaml(self, status: HTTPStatus, message: str) -> None:
        self._send_yaml(f"error: {yaml_scalar(message)}\n", status=status)


def run_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"VMess to Clash service listening on http://{host}:{port}")
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VMess link to Clash subscription service")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_server(args.host, args.port)
