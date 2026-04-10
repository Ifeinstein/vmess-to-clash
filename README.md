# VMess 转 Clash 订阅服务

一个基于 Python 标准库的轻量服务，用来把一个或多个 `vmess://` 链接转换成 Clash 可用的 YAML 订阅。

不依赖第三方包，适合直接在本机跑，也方便后续部署到服务器。

## 功能

- 支持单个或多个 `vmess://` 链接转换为 Clash 配置
- 支持直接返回 YAML
- 支持创建可持久访问的订阅链接
- 自带一个简单网页，可直接粘贴链接生成订阅
- 订阅信息默认保存在 `data/subscriptions.json`

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

页面里可以直接填写订阅名称和多条 `vmess://` 链接，提交后会返回一个可用于 Clash 的订阅地址。

## API

### 1. 临时转换

`GET /sub?url=vmess://...`

可重复传多个 `url` 参数：

```bash
curl "http://127.0.0.1:8000/sub?url=vmess://xxx&url=vmess://yyy"
```

也支持用 `text` 传换行分隔的多条链接。

### 2. 直接 POST 转换

`POST /convert`

请求体示例：

```json
{
  "name": "My Nodes",
  "urls": [
    "vmess://xxxx",
    "vmess://yyyy"
  ]
}
```

或者：

```json
{
  "name": "My Nodes",
  "text": "vmess://xxxx\nvmess://yyyy"
}
```

返回内容是 Clash YAML。

### 3. 创建持久订阅

`POST /api/subscriptions`

请求体：

```json
{
  "name": "My Nodes",
  "text": "vmess://xxxx\nvmess://yyyy"
}
```

返回示例：

```json
{
  "id": "abc123",
  "name": "My Nodes",
  "links_count": 2,
  "created_at": "2026-04-10T03:00:00+00:00",
  "updated_at": "2026-04-10T03:00:00+00:00",
  "subscription_path": "/subscriptions/abc123",
  "subscription_url": "http://127.0.0.1:8000/subscriptions/abc123"
}
```

然后把 `subscription_url` 填到 Clash 客户端即可。

### 4. 更新订阅

`PUT /api/subscriptions/{id}`

请求体与创建时相同。

### 5. 查看订阅列表

`GET /api/subscriptions`

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

## 注意

- 这个服务只处理 `vmess://` 链接，不包含 `vless`、`trojan`、`ss` 等协议。
- 输出的是一个最小可用 Clash 配置，复杂规则和 DNS 配置可以按你自己的环境继续扩展。
