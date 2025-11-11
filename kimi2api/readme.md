# Kimi API Proxy

一个基于 Deno 的 Moonshot Kimi 智能模型 API 代理服务，提供 OpenAI 兼容的 API 接口。

## 功能特性

- 🚀 **OpenAI 兼容 API** - 完全兼容 OpenAI Chat Completions API
- 🔄 **流式响应** - 支持 Server-Sent Events (SSE) 流式输出
- 🔑 **多 Token 支持** - 支持多个 Kimi API Token 轮询使用
- 💾 **会话状态** - 支持有状态的对话会话
- 🔒 **认证灵活** - 支持默认认证密钥和自定义 Token
- 🌐 **CORS 支持** - 完整的跨域资源共享支持
- 📊 **详细日志** - 可配置的调试日志系统

## 快速开始

### 环境要求

- [Deno](https://deno.land/) 1.30.0 或更高版本

### 环境变量配置

```bash
# Kimi API Tokens (必需，多个token用逗号分隔)
export KIMI_TOKENS="your-token-1,your-token-2,your-token-3"

# 默认认证密钥 (可选，默认: "sk-default,sk-false")
export DEFAULT_AUTHKEYS="sk-default,sk-your-key"

# 调试模式 (可选，默认: true)
export DEBUG="true"
```
### 获取认证token
- 登录 [Kimi Chat](https://www.kimi.com/) 官网。
- 打开浏览器开发者工具（通常是按 F12）。
- 切换到 “应用程序” 选项栏
- 在cookie内找到kimi-auth值并复制


### 启动服务

```bash
deno run --allow-net --allow-env kimi-proxy.ts
```

服务默认启动在 `http://localhost:8000`

## API 使用

### 1. 获取模型列表

```bash
curl http://localhost:8000/v1/models
```

响应示例：
```json
{
  "object": "list",
  "data": [
    {
      "id": "k2",
      "object": "model",
      "created": 1690000000,
      "owned_by": "kimi.ai"
    },
    {
      "id": "k1.5",
      "object": "model",
      "created": 1690000000,
      "owned_by": "kimi.ai"
    }
  ]
}
```

### 2. 创建聊天补全 (无状态)

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-default" \
  -d '{
    "model": "k2",
    "messages": [
      {"role": "user", "content": "你好，请介绍一下你自己"}
    ],
    "stream": false
  }'
```

### 3. 创建流式聊天补全

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-default" \
  -d '{
    "model": "k2",
    "messages": [
      {"role": "user", "content": "写一个关于人工智能的短故事"}
    ],
    "stream": true
  }'
```

### 4. 有状态对话会话

```bash
# 第一次对话
curl -X POST http://localhost:8000/v1/chat/completions/your-conversation-id \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-default" \
  -d '{
    "model": "k2",
    "messages": [
      {"role": "user", "content": "你好，我是小明"}
    ],
    "stream": false
  }'

# 后续对话（保持上下文）
curl -X POST http://localhost:8000/v1/chat/completions/your-conversation-id \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-default" \
  -d '{
    "model": "k2",
    "messages": [
      {"role": "user", "content": "你还记得我是谁吗？"}
    ],
    "stream": false
  }'
```

## 认证方式

### 使用默认认证密钥

```bash
Authorization: Bearer sk-default
# 或
Authorization: Bearer sk-your-custom-key
```

这种方式会使用环境变量 `KIMI_TOKENS` 中配置的 tokens。

### 使用自定义 Kimi Tokens

```bash
Authorization: Bearer your-kimi-token-1,your-kimi-token-2
```

直接在 Authorization 头中提供 Kimi API Tokens，用逗号分隔多个 token。

## 可用模型

- `k2` - Kimi 最新模型，支持联网搜索
- `k1.5` - Kimi 标准模型，支持联网搜索

## 请求参数

### Chat Completion 请求体

| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `model` | string | 是 | 模型标识 (k2, k1.5) |
| `messages` | array | 是 | 消息对象数组 |
| `stream` | boolean | 否 | 是否使用流式输出 |

### Message 对象

```typescript
{
  role: "user" | "assistant" | "system";
  content: string;
}
```

## 响应格式

### 非流式响应

```json
{
  "id": "chatcmpl-123",
  "object": "chat.completion",
  "created": 1677652288,
  "model": "k2",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "你好！我是Kimi智能助手..."
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 9,
    "completion_tokens": 12,
    "total_tokens": 21
  }
}
```

### 流式响应

SSE 格式，每个 chunk：

```json
data: {
  "id": "chatcmpl-123",
  "object": "chat.completion.chunk",
  "created": 1677652288,
  "model": "k2",
  "choices": [{
    "index": 0,
    "delta": {
      "content": "你好"
    },
    "finish_reason": null
  }]
}
```

以 `data: [DONE]` 结束。

## 错误处理

常见错误响应：

```json
{
  "error": {
    "message": "错误描述",
    "type": "error_type"
  }
}
```

常见错误码：
- `401` - 认证失败或无可用 token
- `404` - 模型未找到或路由不存在
- `500` - 服务器内部错误

## 部署说明

### 本地开发

```bash
deno run --allow-net --allow-env kimi-proxy.ts
```

### 生产部署

建议使用 PM2 或 systemd 管理进程：

```bash
# 使用 PM2
pm2 start --interpreter="deno" --name="kimi-proxy" -- run --allow-net --allow-env kimi-proxy.ts

# 使用 systemd
sudo nano /etc/systemd/system/kimi-proxy.service
```

### Docker 部署

```dockerfile
FROM denoland/deno:alpine

WORKDIR /app
COPY kimi-proxy.ts .

EXPOSE 8000

CMD ["run", "--allow-net", "--allow-env", "kimi-proxy.ts"]
```

## 故障排除

### 常见问题

1. **无可用 tokens 错误**
   - 检查 `KIMI_TOKENS` 环境变量是否设置正确
   - 确认 tokens 有效且未过期

2. **流式响应中断**
   - 检查网络连接稳定性
   - 确认客户端正确处理 SSE 协议

3. **会话状态丢失**
   - 确保使用相同的 conversation ID
   - 检查服务是否重启导致内存存储丢失

### 日志调试

设置 `DEBUG=true` 查看详细日志：

```bash
export DEBUG=true
deno run --allow-net --allow-env kimi-proxy.ts
```
