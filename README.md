# VMess/VLESS 转 Clash 订阅服务

一个基于 Python 标准库的轻量服务，用来把一个或多个 `vmess://` / `vless://` 链接转换成 Clash 可用的 YAML 订阅。

不依赖第三方包，适合直接在本机跑，也方便后续部署到服务器。

## 功能

- 支持单个或多个 `vmess://` / `vless://` 链接转换为 Clash 配置
- 支持直接返回 YAML
- 支持创建不落库的一次性订阅链接
- 自带一个简单网页，可直接粘贴链接生成订阅
- 默认不在服务器保存节点原始地址

## 启动

```bash
python app.py
```

默认监听：

- `http://127.0.0.1:8000`

自定义地址：

```bash
python app.py --host 0.0.0.0 --port 8080
```

## 页面入口

启动后打开：

- `http://127.0.0.1:8000/`

页面里可以直接填写订阅名称和多条 `vmess://` / `vless://` 链接，提交后会返回一个可用于 Clash 的订阅地址。
网页会在创建成功后一次性显示已经 URL 编码处理过的订阅地址，带 `#节点名` 的 `vless://` 链接也可以直接粘贴。服务器不会把节点原始地址写入历史记录。

## API

### 1. 临时转换

`GET /sub?url=vmess://...`

可重复传多个 `url` 参数：

```bash
curl "http://127.0.0.1:8000/sub?url=vmess://xxx&url=vmess://yyy"
```

也可以传入 `vless://` 链接，或与 `vmess://` 混用：

```bash
curl "http://127.0.0.1:8000/sub?url=vless://xxx"
```

如果 `vless://` 链接包含 `?type=...&security=...` 这类查询参数，推荐把整个链接 URL 编码后放进 `url` 参数；或者直接使用 `text`、`POST /convert`、网页表单粘贴原始链接。

注意：节点名里的 `#` 是 URL fragment，浏览器不会把它后面的内容发送给服务端，所以 `&default_rules=1` 不能放在 `#节点名` 后面。推荐写法：

```bash
curl "http://127.0.0.1:8000/sub?url=<URL编码后的vless链接>&default_rules=1"
```

也支持用 `text` 传换行分隔的多条链接。

开启默认规则：

```bash
curl "http://127.0.0.1:8000/sub?url=vmess://xxx&default_rules=1"
```

`default_rules` 支持 `1`、`true`、`yes`。开启后会把 Loyalsoldier/clash-rules 的 `rule-providers` 和 `RULE-SET` 写入返回的 Clash YAML。

### 2. 直接 POST 转换

`POST /convert`

请求体示例：

```json
{
  "name": "My Nodes",
  "urls": [
    "vmess://xxxx",
    "vless://yyyy"
  ]
}
```

或者：

```json
{
  "name": "My Nodes",
  "text": "vmess://xxxx\nvless://yyyy"
}
```

返回内容是 Clash YAML。

### 3. 创建一次性订阅地址

`POST /api/subscriptions`

请求体：

```json
{
  "name": "My Nodes",
  "text": "vmess://xxxx\nvless://yyyy"
}
```

返回示例：

```json
{
  "name": "My Nodes",
  "links_count": 2,
  "use_default_rules": true,
  "subscription_path": "/sub?url=...",
  "subscription_url": "http://127.0.0.1:8000/sub?url=..."
}
```

然后把 `subscription_url` 填到 Clash 客户端即可。

服务端只返回处理好的订阅 URL，不会保存这次提交的节点原始地址。

### 4. 更新订阅

`PUT /api/subscriptions/{id}`

历史订阅已关闭，这个接口会返回 404。

### 5. 查看订阅列表

`GET /api/subscriptions`

历史记录已关闭，这个接口返回空列表。

### 6. 健康检查

`GET /health`

## 测试

```bash
python -m unittest -v
```

## 当前支持的 VMess 字段

已处理常见字段：

- `ps`
- `add`
- `port`
- `id`
- `aid`
- `scy`
- `net`
- `host`
- `path`
- `tls`
- `sni`
- `alpn`
- `fp`

其中 `ws`、`http`、`h2`、`grpc` 等常见传输方式都做了基础映射。

## 当前支持的 VLESS 参数

已处理常见 URL 参数：

- `type`
- `security`
- `sni`
- `alpn`
- `fp`
- `flow`
- `pbk`
- `sid`
- `spx`
- `host`
- `path`
- `serviceName`
- `allowInsecure`

其中 `ws`、`http`、`h2`、`grpc` 等常见传输方式都做了基础映射。

## 注意

- 这个服务只处理 `vmess://` 和 `vless://` 链接，不包含 `trojan`、`ss` 等协议。
- 输出的是一个最小可用 Clash 配置，复杂规则和 DNS 配置可以按你自己的环境继续扩展。
