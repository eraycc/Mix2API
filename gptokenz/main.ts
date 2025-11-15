// OpenAI兼容的GPT-4o-mini API代理，翻译小模型
// 部署到Deno Deploy

// ==================== 环境变量配置 ====================
const CHAT_URL = Deno.env.get("CHAT_URL") || "https://app.gptokenz.com";
const DEBUG = Deno.env.get("DEBUG") !== "false"; // 默认开启调试
const DEFAULT_AUTH_KEYS = "sk-default,sk-false";
const AUTH_KEYS = (Deno.env.get("AUTH_KEYS") || DEFAULT_AUTH_KEYS).split(",");

// 默认User-Agent列表
const DEFAULT_USER_AGENTS = [
  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
];

const USER_AGENTS = Deno.env.get("USER_AGENTS") 
  ? Deno.env.get("USER_AGENTS")!.split(",") 
  : DEFAULT_USER_AGENTS;

// ==================== 日志工具 ====================
function log(...args: unknown[]) {
  if (DEBUG) {
    console.log(`[${new Date().toISOString()}]`, ...args);
  }
}

function error(...args: unknown[]) {
  console.error(`[${new Date().toISOString()}]`, ...args);
}

// ==================== 加密工具 ====================
// 生成SHA256哈希
async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// 生成幂等性密钥
async function generateIdempotencyKey(): Promise<string> {
  const random = crypto.randomUUID();
  const timestamp = Date.now().toString();
  return await sha256(`${random}${timestamp}`);
}

// 生成客户端标签ID
function generateClientTab(): string {
  return crypto.randomUUID();
}

// ==================== 认证工具 ====================
// 检查API密钥
function checkAuth(request: Request): boolean {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) {
    return false;
  }
  const token = authHeader.substring(7);
  return AUTH_KEYS.includes(token);
}

// 返回认证错误
function authErrorResponse(): Response {
  return new Response(
    JSON.stringify({
      error: {
        message: "Invalid API key",
        type: "invalid_request_error",
        code: "invalid_api_key"
      }
    }),
    {
      status: 401,
      headers: { "Content-Type": "application/json" }
    }
  );
}

// ==================== 模型列表 ====================
// 支持的模型
const SUPPORTED_MODELS = ["gpt-4o-mini"];

// 获取模型列表
function getModelsResponse(): Response {
  const models = SUPPORTED_MODELS.map(model => ({
    id: model,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "gptokenz"
  }));

  return new Response(
    JSON.stringify({
      object: "list",
      data: models
    }),
    {
      headers: { "Content-Type": "application/json" }
    }
  );
}

// ==================== 消息转换 ====================
// 将OpenAI messages格式转换为prompt
function convertMessagesToPrompt(messages: Array<{role: string; content: string}>): string {
  return messages
    .map(msg => `${msg.role}:${msg.content}`)
    .join(";");
}

// ==================== 流式响应转换 ====================
// 将目标API响应转换为OpenAI流式格式
async function* convertToOpenAIStream(
  targetStream: ReadableStream<Uint8Array>,
  model: string
): AsyncGenerator<string> {
  const reader = targetStream.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  try {
    // 发送起始块
    yield `data: ${JSON.stringify({
      id: `chatcmpl-${crypto.randomUUID().split("-")[0]}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: model,
      choices: [
        {
          index: 0,
          delta: {
            role: "assistant",
            content: null
          },
          finish_reason: null
        }
      ]
    })}\n\n`;

    // 读取并转换数据
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      if (DEBUG) {
        log("Received chunk:", chunk);
      }

      // 解析JSON数据
      try {
        const data = JSON.parse(chunk);
        
        // 提取内容
        const content = data.answer || data.content || "";
        if (content) {
          yield `data: ${JSON.stringify({
            id: `chatcmpl-${crypto.randomUUID().split("-")[0]}`,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
              {
                index: 0,
                delta: {
                  content: content
                },
                finish_reason: null
              }
            ]
          })}\n\n`;
        }

        // 如果有usage信息，在最后一个块发送
        if (data.usage) {
          yield `data: ${JSON.stringify({
            id: `chatcmpl-${crypto.randomUUID().split("-")[0]}`,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
              {
                index: 0,
                delta: {},
                finish_reason: "stop"
              }
            ],
            usage: {
              prompt_tokens: data.usage.prompt_tokens || 0,
              completion_tokens: data.usage.completion_tokens || 0,
              total_tokens: data.usage.total_tokens || 0
            }
          })}\n\n`;
        }
      } catch (e) {
        // 如果无法解析为JSON，可能纯文本
        log("Failed to parse JSON:", e);
      }
    }

    // 发送结束标记
    yield `data: ${JSON.stringify({
      id: `chatcmpl-${crypto.randomUUID().split("-")[0]}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: model,
      choices: [
        {
          index: 0,
          delta: {},
          finish_reason: "stop"
        }
      ]
    })}\n\n`;
    yield "data: [DONE]\n\n";

  } catch (err) {
    error("Stream error:", err);
    yield `data: ${JSON.stringify({
      error: {
        message: "Stream processing error",
        type: "stream_error",
        code: "stream_error"
      }
    })}\n\n`;
  } finally {
    reader.releaseLock();
  }
}

// ==================== OpenAI响应转换 ====================
// 将目标API响应转换为OpenAI非流式格式
function convertToOpenAIResponse(targetResponse: any, model: string): object {
  return {
    id: `chatcmpl-${crypto.randomUUID().split("-")[0]}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: targetResponse.answer || ""
        },
        finish_reason: "stop"
      }
    ],
    usage: {
      prompt_tokens: targetResponse.usage?.prompt_tokens || 0,
      completion_tokens: targetResponse.usage?.completion_tokens || 0,
      total_tokens: targetResponse.usage?.total_tokens || 0
    }
  };
}

// ==================== 主请求处理 ====================
async function handleChatCompletions(request: Request): Promise<Response> {
  try {
    // 解析请求体
    const body = await request.json();
    log("Received request:", JSON.stringify(body, null, 2));

    const { messages, model = "gpt-4o-mini", stream = false } = body;

    // 验证参数
    if (!messages || !Array.isArray(messages)) {
      return new Response(
        JSON.stringify({
          error: {
            message: "Missing or invalid 'messages' parameter",
            type: "invalid_request_error",
            code: "invalid_request"
          }
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // 检查是否支持该模型
    if (!SUPPORTED_MODELS.includes(model)) {
      return new Response(
        JSON.stringify({
          error: {
            message: `Model '${model}' is not supported. Supported models: ${SUPPORTED_MODELS.join(", ")}`,
            type: "invalid_request_error",
            code: "model_not_supported"
          }
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // 转换消息格式
    const prompt = convertMessagesToPrompt(messages);
    log("Converted prompt:", prompt);

    // 构造目标API请求头
    const headers = new Headers({
      "Content-Type": "application/json",
      "X-Client-Tab": generateClientTab(),
      "X-Client-Attempt": "1",
      "X-Client-Time": Date.now().toString(),
      "Idempotency-Key": await generateIdempotencyKey(),
      "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
      "Referer": "https://app.gptokenz.com/",
      "Accept": "*/*",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
      "DNT": "1",
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin"
    });

    const targetUrl = `${CHAT_URL}/api/chat-anon`;
    log("Proxying to:", targetUrl);

    // 发送请求到目标API
    const response = await fetch(targetUrl, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        prompt: prompt,
        model: model
      })
    });

    if (!response.ok) {
      throw new Error(`Target API returned ${response.status}: ${response.statusText}`);
    }

    // 处理流式响应
    if (stream) {
      log("Streaming response enabled");
      
      const stream = convertToOpenAIStream(response.body!, model);
      const readableStream = new ReadableStream({
        async start(controller) {
          try {
            for await (const chunk of stream) {
              controller.enqueue(new TextEncoder().encode(chunk));
            }
            controller.close();
          } catch (err) {
            error("Stream generation error:", err);
            controller.error(err);
          }
        }
      });

      return new Response(readableStream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive"
        }
      });
    }

    // 处理非流式响应
    log("Non-streaming response");
    const targetResponse = await response.json();
    log("Target response:", JSON.stringify(targetResponse, null, 2));

    const openaiResponse = convertToOpenAIResponse(targetResponse, model);
    return new Response(JSON.stringify(openaiResponse), {
      headers: { "Content-Type": "application/json" }
    });

  } catch (err) {
    error("Error handling chat completions:", err);
    return new Response(
      JSON.stringify({
        error: {
          message: `Internal server error: ${err instanceof Error ? err.message : String(err)}`,
          type: "internal_error",
          code: "internal_error"
        }
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

// ==================== 主路由 ====================
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    
    if (DEBUG) {
      log(`${request.method} ${path}`);
    }

    // 处理模型列表请求
    if (request.method === "GET" && path === "/v1/models") {
      if (!checkAuth(request)) {
        return authErrorResponse();
      }
      return getModelsResponse();
    }

    // 处理聊天完成请求
    if (request.method === "POST" && path === "/v1/chat/completions") {
      if (!checkAuth(request)) {
        return authErrorResponse();
      }
      return handleChatCompletions(request);
    }

    // 处理健康检查
    if (request.method === "GET" && path === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          timestamp: new Date().toISOString()
        }),
        {
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // 根路径
    if (request.method === "GET" && path === "/") {
      return new Response(
        JSON.stringify({
          message: "GPT-4o-mini Free API",
          endpoints: {
            models: "/v1/models",
            chat: "/v1/chat/completions",
            health: "/health"
          },
          debug: DEBUG,
          auth_keys_count: AUTH_KEYS.length
        }),
        {
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // 404
    return new Response(
      JSON.stringify({
        error: {
          message: "Not found",
          type: "invalid_request_error",
          code: "not_found"
        }
      }),
      {
        status: 404,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
