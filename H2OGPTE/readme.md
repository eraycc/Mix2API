## 环境变量配置说明

在 Deno Deploy 控制台中配置以下环境变量：

### 基本配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `H2OGPTE_BASE_URL` | `https://h2ogpte.genai.h2o.ai` | H2OGPTE 服务地址 |
| `IS_GUEST` | `true` | 是否使用 Guest 模式（自动获取凭证） |
| `API_KEY` | `sk-false,sk-default` | API 密钥（多个用逗号分隔） |

### 多账号配置（IS_GUEST=false 时使用）

| 变量名 | 说明 |
|--------|------|
| `H2OGPTE_ACCOUNTS` | JSON 格式的多账号配置 |
| `ACCOUNT_MODE` | 账号选择模式：`random`（随机）或 `round-robin`（轮询，默认） |

**H2OGPTE_ACCOUNTS 格式示例：**

```json
[
  {
    "H2OGPTE_SESSION": "账户1session",
    "H2OGPTE_CSRF_TOKEN": "账户1token",
    "H2OGPTE_WORKSPACE_ID": "workspaces/uuid1",
    "H2OGPTE_PROMPT_TEMPLATE_ID": ""
  },
  {
    "H2OGPTE_SESSION": "账户2session",
    "H2OGPTE_CSRF_TOKEN": "账户2token",
    "H2OGPTE_WORKSPACE_ID": "workspaces/uuid2",
    "H2OGPTE_PROMPT_TEMPLATE_ID": ""
  }
]
```

### 单账号配置（如果不使用多账号）

| 变量名 | 说明 |
|--------|------|
| `H2OGPTE_SESSION` | 单账号 Session |
| `H2OGPTE_CSRF_TOKEN` | 单账号 CSRF Token |
| `H2OGPTE_WORKSPACE_ID` | 工作区 ID（默认：`workspaces/h2ogpte-guest`） |
| `H2OGPTE_PROMPT_TEMPLATE_ID` | 提示模板 ID（可选） |

## 功能特性

1. **✅ /v1/models** - 获取可用模型列表
2. **✅ /v1/chat/completions** - 聊天补全接口（支持流式和非流式）
3. **✅ 会话池 (Session Pool)** - 后台自动管理和预热会话，提升响应速度
4. **✅ 自动凭据管理** - 支持 Guest 用户自动获取和续期凭据
5. **✅ 标准 OpenAI API 格式响应**
6. **✅ CORS 支持**
7. **✅ 多账号支持** - 支持随机或轮询选择账号
8. **✅ 多 API Key 支持** - 使用逗号分隔多个 API Key

## 部署方式

1. 在 [Deno Deploy](https://dash.deno.com) 创建新项目
2. 将 `main.ts` 文件推送到 GitHub 仓库
3. 连接 GitHub 仓库到 Deno Deploy 项目
4. 在项目设置中配置环境变量
5. 部署完成后即可使用
