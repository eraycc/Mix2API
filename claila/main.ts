// Deno Deploy Script for Claila API Proxy
// 部署到 Deno Deploy 边缘网络

// ==================== 配置变量 ====================

// 环境变量
const AUTH_KEYS = (Deno.env.get("AUTH_KEYS") || "sk-default,sk-false").split(",").map(k => k.trim());
const DEBUG = (Deno.env.get("DEBUG") || "true") === "true";

// 目标地址
const BASE_URL = "https://app.claila.com";

// User-Agent 列表
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
];

// 模型列表
const BASE_MODELS = [
  "grok-4-1-fast-non-reasoning",
  "grok-4-fast-non-reasoning",
  "gpt-5-mini",
  "gpt-4.1-mini",
  "claude-3-5-haiku-20241022",
  "gemini-2.5-flash",
  "grok-3-mini-latest",
  "mistral-small-latest",
  "codestral-latest",
  "gpt-5.2",
  "gpt-5.1",
  "gpt-5-chat-latest",
  "gpt-4.1",
  "gpt-4o",
  "claude-sonnet-4-5-20250929",
  "claude-sonnet-4-20250514",
  "claude-3-7-sonnet-20250219",
  "grok-4-latest",
  "grok-3-latest",
  "mistral-medium-latest",
  "grok-4-1-fast-reasoning",
  "gemini-3-pro-preview",
  "grok-4-fast-reasoning",
  "o3-mini",
  "o3",
  "gemini-2.5-pro",
  "o3-pro",
  "o4-mini",
  "magistral-medium-latest",
  "mistral-large-latest",
  "claude-opus-4-20250514",
];

// ==================== 工具函数 ====================

function log(...args: unknown[]) {
  if (DEBUG) {
    console.log(`[${new Date().toISOString()}]`, ...args);
  }
}

function logError(...args: unknown[]) {
  if (DEBUG) {
    console.error(`[${new Date().toISOString()}] [ERROR]`, ...args);
  }
}

function getRandomUserAgent(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function generateUUID(): string {
  return crypto.randomUUID();
}

// ==================== API 鉴权 ====================

function authenticateRequest(request: Request): { success: boolean; error?: string } {
  const authHeader = request.headers.get("Authorization");
  
  if (!authHeader) {
    return { success: false, error: "Missing Authorization header" };
  }
  
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return { success: false, error: "Invalid Authorization header format. Expected: Bearer <token>" };
  }
  
  const token = parts[1];
  if (!AUTH_KEYS.includes(token)) {
    return { success: false, error: "Invalid API key" };
  }
  
  return { success: true };
}

function createErrorResponse(status: number, message: string, type: string = "invalid_request_error"): Response {
  return new Response(JSON.stringify({
    error: {
      message,
      type,
      param: null,
      code: null
    }
  }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    }
  });
}

// ==================== 模型列表处理 ====================

function handleModelsRequest(): Response {
  const timestamp = Math.floor(Date.now() / 1000);
  
  const models: Array<{ id: string; object: string; created: number; owned_by: string }> = [];
  
  // 添加基础模型
  for (const model of BASE_MODELS) {
    models.push({
      id: model,
      object: "model",
      created: timestamp,
      owned_by: "claila"
    });
  }
  
  // 添加带 -search 后缀的模型
  for (const model of BASE_MODELS) {
    models.push({
      id: `${model}-search`,
      object: "model",
      created: timestamp,
      owned_by: "claila"
    });
  }
  
  return new Response(JSON.stringify({
    object: "list",
    data: models
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    }
  });
}

// ==================== 消息格式化 ====================

interface Message {
  role: string;
  content: string | Array<{ type: string; text?: string; image_url?: { url: string } }>;
}

function formatMessages(messages: Message[]): string {
  return messages.map(msg => {
    let content: string;
    if (typeof msg.content === "string") {
      content = msg.content;
    } else if (Array.isArray(msg.content)) {
      // 处理多模态内容，提取文本部分
      content = msg.content
        .filter(item => item.type === "text" && item.text)
        .map(item => item.text)
        .join(" ");
    } else {
      content = "";
    }
    // 转义分隔符
    content = content.replace(/;/g, "；").replace(/:/g, "：");
    return `${msg.role}:${content}`;
  }).join(";");
}

// ==================== CSRF Token 获取 ====================

async function getCSRFToken(userAgent: string): Promise<string> {
  log("Fetching CSRF token...");
  
  const response = await fetch(`${BASE_URL}/api/v2/getcsrftoken`, {
    method: "GET",
    headers: {
      "Accept": "*/*",
      "X-Requested-With": "XMLHttpRequest",
      "User-Agent": userAgent,
      "Referer": `${BASE_URL}/chat`,
    }
  });
  
  if (!response.ok) {
    throw new Error(`Failed to get CSRF token: ${response.status} ${response.statusText}`);
  }
  
  const token = await response.text();
  log("CSRF token obtained:", token.substring(0, 16) + "...");
  return token.trim();
}

// ==================== 聊天请求处理 ====================

interface ChatRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
}

async function handleChatCompletions(request: Request): Promise<Response> {
  let requestBody: ChatRequest;
  
  try {
    requestBody = await request.json();
  } catch {
    return createErrorResponse(400, "Invalid JSON in request body");
  }
  
  const { model, messages, stream = false } = requestBody;
  
  if (!model) {
    return createErrorResponse(400, "Missing 'model' field");
  }
  
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return createErrorResponse(400, "Missing or invalid 'messages' field");
  }
  
  // 解析模型名和 websearch 参数
  let baseModel = model;
  let websearch = false;
  
  if (model.endsWith("-search")) {
    baseModel = model.slice(0, -7); // 去掉 "-search" 后缀
    websearch = true;
  }
  
  log(`Model: ${model}, Base Model: ${baseModel}, WebSearch: ${websearch}, Stream: ${stream}`);
  
  // 格式化消息
  const formattedMessages = formatMessages(messages);
  log("Formatted messages:", formattedMessages.substring(0, 100) + "...");
  
  // 获取随机 UA（整个请求过程使用同一个）
  const userAgent = getRandomUserAgent();
  log("Using User-Agent:", userAgent);
  
  try {
    // 获取 CSRF token
    const csrfToken = await getCSRFToken(userAgent);
    
    // 构造请求体
    const sessionId = Date.now().toString();
    const formData = new URLSearchParams({
      model: baseModel,
      calltype: "completion",
      message: formattedMessages,
      sessionId: sessionId,
      chat_mode: "chat",
      websearch: websearch.toString(),
      tmp_enabled: "0"
    });
    
    log("Sending chat request to Claila...");
    
    // 发送聊天请求
    const chatResponse = await fetch(`${BASE_URL}/api/v2/unichat4`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "*/*",
        "X-CSRF-Token": csrfToken,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": userAgent,
        "Referer": `${BASE_URL}/chat`,
      },
      body: formData.toString()
    });
    
    if (!chatResponse.ok) {
      const errorText = await chatResponse.text();
      logError("Claila API error:", chatResponse.status, errorText);
      return createErrorResponse(502, `Upstream API error: ${chatResponse.status}`);
    }
    
    const responseText = await chatResponse.text();
    log("Claila response received, length:", responseText.length);
    
    // 根据 stream 参数返回不同格式
    if (stream) {
      return createStreamResponse(responseText, model);
    } else {
      return createNonStreamResponse(responseText, model);
    }
    
  } catch (error) {
    logError("Error processing chat request:", error);
    return createErrorResponse(500, `Internal server error: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}

// ==================== 流式响应 ====================

function createStreamResponse(content: string, model: string): Response {
  const responseId = `chatcmpl-${generateUUID()}`;
  const timestamp = Math.floor(Date.now() / 1000);
  
  const encoder = new TextEncoder();
  
  const stream = new ReadableStream({
    async start(controller) {
      try {
        // 首个块：角色声明
        const firstChunk = {
          id: responseId,
          object: "chat.completion.chunk",
          created: timestamp,
          model: model,
          choices: [{
            index: 0,
            delta: {
              role: "assistant",
              content: ""
            },
            logprobs: null,
            finish_reason: null
          }]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(firstChunk)}\n\n`));
        
        // 将内容分块发送（模拟流式输出）
        const chunkSize = 10; // 每次发送的字符数
        for (let i = 0; i < content.length; i += chunkSize) {
          const chunk = content.slice(i, i + chunkSize);
          const dataChunk = {
            id: responseId,
            object: "chat.completion.chunk",
            created: timestamp,
            model: model,
            choices: [{
              index: 0,
              delta: {
                content: chunk
              },
              logprobs: null,
              finish_reason: null
            }]
          };
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(dataChunk)}\n\n`));
          
          // 添加小延迟使流式效果更自然
          await new Promise(resolve => setTimeout(resolve, 10));
        }
        
        // 结束块
        const finishChunk = {
          id: responseId,
          object: "chat.completion.chunk",
          created: timestamp,
          model: model,
          choices: [{
            index: 0,
            delta: {},
            logprobs: null,
            finish_reason: "stop"
          }],
          usage: {
            prompt_tokens: 0,
            completion_tokens: content.length,
            total_tokens: content.length
          }
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(finishChunk)}\n\n`));
        
        // [DONE] 标志
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        
        controller.close();
      } catch (error) {
        logError("Stream error:", error);
        controller.error(error);
      }
    }
  });
  
  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": "*",
    }
  });
}

// ==================== 非流式响应 ====================

function createNonStreamResponse(content: string, model: string): Response {
  const responseId = `chatcmpl-${generateUUID()}`;
  const timestamp = Math.floor(Date.now() / 1000);
  
  const response = {
    id: responseId,
    object: "chat.completion",
    created: timestamp,
    model: model,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: content
      },
      logprobs: null,
      finish_reason: "stop"
    }],
    usage: {
      prompt_tokens: 0,
      completion_tokens: content.length,
      total_tokens: content.length
    }
  };
  
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    }
  });
}

// ==================== CORS 预检处理 ====================

function handleCORS(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "Access-Control-Max-Age": "86400",
    }
  });
}

// ==================== 主路由处理 ====================

async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
  log(`${method} ${path}`);
  
  // 处理 CORS 预检请求
  if (method === "OPTIONS") {
    return handleCORS();
  }
  
  // 根路径 - 返回服务信息
  if (path === "/" || path === "") {
    return new Response(JSON.stringify({
      service: "Claila OpenAI Compatible API Proxy",
      version: "1.0.0",
      endpoints: {
        models: "/v1/models",
        chat: "/v1/chat/completions"
      },
      debug: DEBUG
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      }
    });
  }
  
  // 健康检查
  if (path === "/health") {
    return new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      }
    });
  }
  
  // API 路由 - 需要鉴权
  if (path === "/v1/models" && method === "GET") {
    const auth = authenticateRequest(request);
    if (!auth.success) {
      return createErrorResponse(401, auth.error!, "authentication_error");
    }
    return handleModelsRequest();
  }
  
  if (path === "/v1/chat/completions" && method === "POST") {
    const auth = authenticateRequest(request);
    if (!auth.success) {
      return createErrorResponse(401, auth.error!, "authentication_error");
    }
    return await handleChatCompletions(request);
  }
  
  // 404 - 路由不存在
  return createErrorResponse(404, `Endpoint not found: ${method} ${path}`, "not_found");
}

// ==================== Deno Deploy 入口 ====================

Deno.serve({
  port: 8000,
  onListen({ port, hostname }) {
    console.log(`Server running at http://${hostname}:${port}/`);
    console.log(`Debug mode: ${DEBUG}`);
    console.log(`Configured API keys: ${AUTH_KEYS.length}`);
  }
}, handleRequest);
