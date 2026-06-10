import argparse
import base64
import json
import os
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse


DEFAULT_RULE_BASE_URL = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release"
DEFAULT_RULE_PROVIDER_SPECS = {
    "reject": "domain",
    "icloud": "domain",
    "apple": "domain",
    "google": "domain",
    "proxy": "domain",
    "direct": "domain",
    "private": "domain",
    "gfw": "domain",
    "tld-not-cn": "domain",
    "telegramcidr": "ipcidr",
    "cncidr": "ipcidr",
    "lancidr": "ipcidr",
    "applications": "classical",
}


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


def decode_vless_link(link: str) -> dict[str, Any]:
    parsed = urlparse(link.strip())
    if parsed.scheme != "vless":
        raise ValueError("Only vless:// links are supported")

    uuid = parsed.username or ""
    server = parsed.hostname or ""
    if not uuid or not server:
        raise ValueError("vless link is missing uuid or server")

    query = {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}
    query.update(
        {
            "id": unquote(uuid),
            "add": server,
            "port": parsed.port or 443,
            "ps": unquote(parsed.fragment) if parsed.fragment else "",
        }
    )
    return query


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


def vmess_to_clash_proxy(vmess: dict[str, Any], index: int, udp_enabled: bool = False) -> dict[str, Any]:
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
        "udp": udp_enabled,
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


def vless_to_clash_proxy(vless: dict[str, Any], index: int, udp_enabled: bool = False) -> dict[str, Any]:
    server = str(vless.get("add") or "").strip()
    uuid = str(vless.get("id") or "").strip()
    port = as_int(vless.get("port"), 443)

    if not server or not uuid:
        raise ValueError("vless entry is missing add or id")

    network = str(vless.get("type") or vless.get("net") or "tcp").strip().lower() or "tcp"
    security = str(vless.get("security") or "").strip().lower()
    tls_enabled = security in {"tls", "reality"} or truthy(vless.get("tls"))
    host = str(vless.get("host") or "").strip()
    path = str(vless.get("path") or "").strip()
    sni = str(vless.get("sni") or "").strip()
    alpn = clean_host_list(vless.get("alpn"))
    fingerprint = str(vless.get("fp") or "").strip()
    flow = str(vless.get("flow") or "").strip()

    proxy: dict[str, Any] = {
        "name": pick_name(vless, index),
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "udp": udp_enabled,
        "tls": tls_enabled,
        "network": network,
    }

    if tls_enabled:
        proxy["servername"] = sni or host or server
    if alpn:
        proxy["alpn"] = alpn
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    if flow:
        proxy["flow"] = flow
    if truthy(vless.get("allowInsecure")):
        proxy["skip-cert-verify"] = True
    if security == "reality":
        reality_opts: dict[str, Any] = {}
        public_key = str(vless.get("pbk") or vless.get("public-key") or "").strip()
        short_id = str(vless.get("sid") or vless.get("short-id") or "").strip()
        spider_x = str(vless.get("spx") or vless.get("spider-x") or "").strip()
        if public_key:
            reality_opts["public-key"] = public_key
        if short_id:
            reality_opts["short-id"] = short_id
        if spider_x:
            reality_opts["spider-x"] = spider_x
        if reality_opts:
            proxy["reality-opts"] = reality_opts

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
        service_name = str(vless.get("serviceName") or "").strip() or path.lstrip("/")
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts

    return proxy


def link_to_clash_proxy(link: str, index: int, udp_enabled: bool = False) -> dict[str, Any]:
    if link.startswith("vmess://"):
        return vmess_to_clash_proxy(decode_vmess_link(link), index, udp_enabled)
    if link.startswith("vless://"):
        return vless_to_clash_proxy(decode_vless_link(link), index, udp_enabled)
    raise ValueError("Only vmess:// and vless:// links are supported")


def extract_links(text: str) -> list[str]:
    links: list[str] = []
    for line in text.replace("\r", "\n").split("\n"):
        candidate = line.strip()
        if candidate.startswith(("vmess://", "vless://")):
            links.append(candidate)
    return links


def extract_vmess_links(text: str) -> list[str]:
    return extract_links(text)


def links_from_sub_query(query: dict[str, list[str]]) -> list[str]:
    links = [item for item in query.get("url", []) if item.strip()]
    if links and links[-1].startswith("vless://"):
        vless_params = [
            "type",
            "encryption",
            "security",
            "pbk",
            "fp",
            "sni",
            "sid",
            "spx",
            "flow",
            "host",
            "path",
            "serviceName",
            "alpn",
            "allowInsecure",
        ]
        extra_params = [
            f"{key}={value}"
            for key in vless_params
            for value in query.get(key, [])
            if value
        ]
        if extra_params:
            separator = "&" if "?" in links[-1] else "?"
            links[-1] = f"{links[-1]}{separator}{'&'.join(extra_params)}"
    if not links and "text" in query:
        links = extract_links("\n".join(query["text"]))
    return links


def direct_subscription_path(
    links: list[str],
    use_default_rules: bool = False,
    use_udp: bool = False,
) -> str:
    params: list[tuple[str, str]] = [("url", link) for link in links]
    if use_default_rules:
        params.append(("default_rules", "1"))
    if use_udp:
        params.append(("udp", "1"))
    return f"/sub?{urlencode(params, quote_via=quote)}"


def one_time_subscription_response(
    links: list[str],
    name: str,
    use_default_rules: bool,
    use_udp: bool = False,
    base_url: str = "",
) -> dict[str, Any]:
    path = direct_subscription_path(links, use_default_rules, use_udp)
    url = f"{base_url}{path}" if base_url else path
    return {
        "name": name,
        "links_count": len(links),
        "use_default_rules": use_default_rules,
        "use_udp": use_udp,
        "subscription_path": path,
        "subscription_url": url,
        "direct_subscription_path": path,
        "direct_subscription_url": url,
    }


def default_rule_providers() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "type": "http",
            "behavior": behavior,
            "url": f"{DEFAULT_RULE_BASE_URL}/{name}.txt",
            "path": f"./ruleset/{name}.yaml",
            "interval": 86400,
        }
        for name, behavior in DEFAULT_RULE_PROVIDER_SPECS.items()
    }


def default_rules(proxy_policy: str) -> list[str]:
    return [
        "RULE-SET,applications,DIRECT",
        "DOMAIN,clash.razord.top,DIRECT",
        "DOMAIN,yacd.haishan.me,DIRECT",
        "RULE-SET,private,DIRECT",
        "RULE-SET,reject,REJECT",
        "RULE-SET,icloud,DIRECT",
        "RULE-SET,apple,DIRECT",
        f"RULE-SET,google,{proxy_policy}",
        f"RULE-SET,proxy,{proxy_policy}",
        "RULE-SET,direct,DIRECT",
        "RULE-SET,lancidr,DIRECT",
        "RULE-SET,cncidr,DIRECT",
        f"RULE-SET,telegramcidr,{proxy_policy}",
        "GEOIP,LAN,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,DIRECT",
    ]


def build_clash_config(
    links: list[str],
    subscription_name: str = "Proxy Subscription",
    use_default_rules: bool = False,
    use_udp: bool = False,
) -> dict[str, Any]:
    if not links:
        raise ValueError("No vmess or vless links supplied")

    proxies = [link_to_clash_proxy(link, index, use_udp) for index, link in enumerate(links, start=1)]
    proxy_names = [proxy["name"] for proxy in proxies]

    config: dict[str, Any] = {
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
    if use_default_rules:
        config["rule-providers"] = default_rule_providers()
        config["rules"] = default_rules(subscription_name)
    return config


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


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_html(self.render_index())
            return

        if parsed.path == "/health":
            self._send_json({"status": "ok", "time": utc_now_iso()})
            return

        if parsed.path == "/api/subscriptions":
            self._send_json({"items": []})
            return

        if parsed.path.startswith("/api/subscriptions/"):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Subscription history is disabled")
            return

        if parsed.path.startswith("/subscriptions/"):
            self._send_error_yaml(HTTPStatus.NOT_FOUND, "Subscription history is disabled")
            return

        if parsed.path == "/sub":
            query = parse_qs(parsed.query)
            links = links_from_sub_query(query)
            use_default_rules = truthy(query.get("default_rules", [""])[-1])
            use_udp = truthy(query.get("udp", [""])[-1])
            try:
                config = build_clash_config(links, use_default_rules=use_default_rules, use_udp=use_udp)
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
            name = str(payload.get("name") or "Proxy Subscription")
            use_default_rules = truthy(payload.get("use_default_rules"))
            use_udp = truthy(payload.get("use_udp"))
            try:
                config = build_clash_config(links, name, use_default_rules, use_udp)
            except ValueError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_yaml(config_to_yaml(config))
            return

        if parsed.path == "/api/subscriptions":
            links = self.links_from_payload(payload)
            name = str(payload.get("name") or "Proxy Subscription").strip() or "Proxy Subscription"
            use_default_rules = truthy(payload.get("use_default_rules"))
            use_udp = truthy(payload.get("use_udp"))
            try:
                build_clash_config(links, name, use_default_rules, use_udp)
            except ValueError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return

            response = one_time_subscription_response(
                links,
                name,
                use_default_rules,
                use_udp,
                self.absolute_url(""),
            )
            self._send_json(response, status=HTTPStatus.CREATED)
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found")

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/subscriptions/"):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found")
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Subscription history is disabled")

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
            links = extract_links(str(payload["text"]))
        return links

    def render_index(self) -> str:
        rows = '<tr><td colspan="5">历史记录已关闭。订阅地址只会在创建成功后显示一次，服务器不会保存节点原始地址。</td></tr>'

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VMess/VLESS 转 Clash 订阅</title>
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
    textarea, input:not([type="checkbox"]) {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 14px;
      font: inherit;
      background: white;
    }}
    textarea {{ min-height: 220px; resize: vertical; }}
    .check-row {{
      display: flex;
      align-items: flex-start;
      gap: 10px;
      margin: 14px 0;
      line-height: 1.45;
    }}
    .check-row input {{
      margin-top: 4px;
      accent-color: var(--accent);
    }}
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
    .result-block {{
      margin-top: 14px;
    }}
    .result-block:first-of-type {{
      margin-top: 0;
    }}
    .result-block h3 {{
      margin: 0 0 8px;
      font-size: 1rem;
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
    #subscription-url {{
      min-height: auto;
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
      <h1>VMess/VLESS 地址转 Clash 订阅</h1>
      <p>把一个或多个 <code>vmess://</code> 或 <code>vless://</code> 链接粘进来，服务会生成可直接使用的 Clash 订阅地址，也支持直接用接口调用。</p>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>创建订阅</h2>
        <form id="create-form">
          <label for="name">订阅名称</label>
          <input id="name" name="name" value="My Proxy Subscription">
          <p class="hint">每行一个 vmess 或 vless 链接。</p>
          <textarea id="text" name="text" placeholder="vmess://...&#10;vless://..."></textarea>
          <label class="check-row">
            <input id="use-default-rules" name="use_default_rules" type="checkbox" checked>
            <span>使用 Loyalsoldier/clash-rules 默认规则</span>
          </label>
          <label class="check-row">
            <input id="use-udp" name="use_udp" type="checkbox" checked>
            <span>启用 UDP</span>
          </label>
          <button type="submit">生成订阅链接</button>
        </form>
      </div>

      <div class="panel">
        <h2>结果与预览</h2>
        <div class="result-block">
          <h3>订阅地址</h3>
          <pre id="subscription-url">提交后会在这里显示订阅地址。</pre>
        </div>
        <div class="result-block">
          <h3>YAML 预览</h3>
          <pre id="yaml-preview">提交后会在这里显示 YAML 预览。</pre>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top: 20px;">
      <h2>历史记录</h2>
      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>订阅路径</th>
            <th>节点数</th>
            <th>默认规则</th>
            <th>更新时间</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
  </main>
  <script>
    const form = document.getElementById('create-form');
    const subscriptionUrlOutput = document.getElementById('subscription-url');
    const yamlPreviewOutput = document.getElementById('yaml-preview');
    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      const payload = {{
        name: form.name.value,
        text: form.text.value,
        use_default_rules: form.use_default_rules.checked,
        use_udp: form.use_udp.checked
      }};
      const response = await fetch('/api/subscriptions', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      const text = await response.text();
      if (response.ok) {{
        const data = JSON.parse(text);
        const previewResponse = await fetch(data.subscription_path);
        const preview = await previewResponse.text();
        const subscriptionUrl = new URL(data.subscription_path, window.location.origin).href;
        subscriptionUrlOutput.textContent = subscriptionUrl;
        yamlPreviewOutput.textContent = preview;
      }} else {{
        subscriptionUrlOutput.textContent = '';
        yamlPreviewOutput.textContent = text;
      }}
    }});
  </script>
</body>
</html>"""

    def absolute_url(self, path: str) -> str:
        host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", "127.0.0.1:8000"))
        host = host.split(",", 1)[0].strip() or "127.0.0.1:8000"
        proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip() or "http"
        return f"{proto}://{host}{path}"

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
    print(f"VMess/VLESS to Clash service listening on http://{host}:{port}")
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VMess/VLESS link to Clash subscription service")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_server(args.host, args.port)
