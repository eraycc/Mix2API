// Deno Deploy Script for OpenAI-compatible API Proxy
// 环境变量配置
const AUTH_KEYS = (Deno.env.get("AUTH_KEYS") || "sk-default,sk-false").split(",").map(k => k.trim());
const DEBUG = (Deno.env.get("DEBUG") || "true").toLowerCase() === "true";
const BASE_URL = Deno.env.get("BASE_URL") || "http://xiamenlabs.com";

// 模型映射
const MODEL_MAPPING: Record<string, string> = {
  "Unity": "x",
  "gpt-4": "x",
  "gpt-4o": "x",
  "gpt-4o-mini": "x",
  "gpt-5": "x",
  "gpt-5.1": "x",
  "gpt-5.2": "x",
  "gemini-2.5-pro": "x",
  "gemini-2.5-flash": "x",
  "gemini-3-pro": "x",
  "gemini-3-flash": "x",
  "deepseek-r1": "x",
  "deepseek-v3": "x",
  "claude-4-sonnet": "x",
  "claude-4-opus": "x",
  "claude-4.5-sonnet": "x",
  "claude-4.5-opus": "x",
  "claude-3.7-sonnet": "x",
};

// 常用浏览器 User-Agent 列表
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
];

// 调试日志函数
function debugLog(...args: unknown[]) {
  if (DEBUG) {
    console.log(`[DEBUG ${new Date().toISOString()}]`, ...args);
  }
}

// 获取随机 User-Agent
function getRandomUserAgent(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

// 生成 UUID
function generateUUID(): string {
  return crypto.randomUUID();
}

// 验证 API 鉴权
function validateAuth(request: Request): boolean {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) {
    debugLog("No Authorization header found");
    return false;
  }
  
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    debugLog("Invalid Authorization header format");
    return false;
  }
  
  const token = match[1];
  const isValid = AUTH_KEYS.includes(token);
  debugLog(`Token validation: ${isValid ? "passed" : "failed"}`);
  return isValid;
}

// 返回未授权响应
function unauthorizedResponse(): Response {
  return new Response(JSON.stringify({
    error: {
      message: "Invalid API key",
      type: "invalid_request_error",
      code: "invalid_api_key"
    }
  }), {
    status: 401,
    headers: { "Content-Type": "application/json" }
  });
}

// 处理模型列表请求
function handleModelsRequest(): Response {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const models = Object.keys(MODEL_MAPPING).map(modelId => ({
    id: modelId,
    object: "model",
    created: currentTimestamp,
    owned_by: "xiamen"
  }));
  
  const response = {
    object: "list",
    data: models
  };
  
  debugLog("Returning models list:", response);
  
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// 处理消息格式
interface Message {
  role: string;
  content: string;
}

function processMessages(messages: Message[]): Message[] {
  const processed = [...messages];
  const systemMessage: Message = { role: "system", content: "Be a helpful assistant" };
  
  if (processed.length === 0) {
    return [systemMessage];
  }
  
  const firstMessage = processed[0];
  
  if (firstMessage.role !== "system") {
    // 第一个消息不是 system，在开头添加默认 system 消息
    processed.unshift(systemMessage);
  } else if (firstMessage.content !== "Be a helpful assistant") {
    // 第一个消息是 system 但 content 不是默认值，将其改为 user 并在前面添加默认 system
    firstMessage.role = "user";
    processed.unshift(systemMessage);
  }
  
  debugLog("Processed messages:", processed);
  return processed;
}

// 解析目标响应的 SSE 数据
interface TargetChunk {
  id: string;
  model: string;
  reasoning?: string;
  content?: string;
  isFinished: boolean;
}

function parseTargetSSELine(line: string): TargetChunk | null {
  if (!line.startsWith("data: ")) return null;
  const data = line.slice(6);
  if (data === "[DONE]") return { id: "", model: "", isFinished: true };
  
  try {
    const parsed = JSON.parse(data);
    const choice = parsed.choices?.[0];
    if (!choice) return null;
    
    return {
      id: parsed.id || "",
      model: parsed.model || "",
      reasoning: choice.delta?.reasoning,
      content: choice.delta?.content,
      isFinished: choice.finish_reason === "stop"
    };
  } catch {
    debugLog("Failed to parse SSE line:", line);
    return null;
  }
}

// 创建 OpenAI 格式的流式响应块
function createStreamChunk(
  id: string,
  model: string,
  content: string | null,
  reasoningContent: string | null,
  finishReason: string | null,
  isFirst: boolean = false,
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number; reasoning_tokens: number }
): string {
  const chunk: Record<string, unknown> = {
    id,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      delta: isFirst
        ? { role: "assistant", content: null, reasoning_content: "" }
        : { content, reasoning_content: reasoningContent },
      logprobs: null,
      finish_reason: finishReason
    }]
  };
  
  if (usage) {
    chunk.usage = {
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
      completion_tokens_details: {
        reasoning_tokens: usage.reasoning_tokens
      }
    };
  }
  
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

// 处理流式聊天请求
async function handleStreamingChat(
  targetResponse: Response,
  requestModel: string,
  responseId: string
): Promise<Response> {
  const reader = targetResponse.body?.getReader();
  if (!reader) {
    throw new Error("No response body");
  }
  
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  
  let buffer = "";
  let isFirstChunk = true;
  let totalReasoningContent = "";
  let totalContent = "";
  
  const stream = new ReadableStream({
    async start(controller) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          
          if (done) {
            debugLog("Stream ended");
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
            break;
          }
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine || trimmedLine === ": connected") continue;
            
            if (trimmedLine === "data: [DONE]") {
              // 发送最终块
              const finalChunk = createStreamChunk(
                responseId,
                requestModel,
                "",
                null,
                "stop",
                false,
                {
                  prompt_tokens: 10,
                  completion_tokens: totalReasoningContent.length + totalContent.length,
                  total_tokens: 10 + totalReasoningContent.length + totalContent.length,
                  reasoning_tokens: totalReasoningContent.length
                }
              );
              controller.enqueue(encoder.encode(finalChunk));
              controller.enqueue(encoder.encode("data: [DONE]\n\n"));
              controller.close();
              return;
            }
            
            const parsed = parseTargetSSELine(trimmedLine);
            if (!parsed) continue;
            
            if (isFirstChunk) {
              // 发送首个块
              const firstChunk = createStreamChunk(responseId, requestModel, null, "", null, true);
              controller.enqueue(encoder.encode(firstChunk));
              isFirstChunk = false;
            }
            
            if (parsed.reasoning) {
              totalReasoningContent += parsed.reasoning;
              const chunk = createStreamChunk(responseId, requestModel, null, parsed.reasoning, null);
              controller.enqueue(encoder.encode(chunk));
            }
            
            if (parsed.content) {
              totalContent += parsed.content;
              const chunk = createStreamChunk(responseId, requestModel, parsed.content, null, null);
              controller.enqueue(encoder.encode(chunk));
            }
          }
        }
      } catch (error) {
        debugLog("Stream error:", error);
        controller.error(error);
      }
    }
  });
  
  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive"
    }
  });
}

// 处理非流式聊天请求
async function handleNonStreamingChat(
  targetResponse: Response,
  requestModel: string,
  responseId: string
): Promise<Response> {
  const reader = targetResponse.body?.getReader();
  if (!reader) {
    throw new Error("No response body");
  }
  
  const decoder = new TextDecoder();
  let buffer = "";
  let reasoningContent = "";
  let content = "";
  
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine || trimmedLine === ": connected" || trimmedLine === "data: [DONE]") continue;
      
      const parsed = parseTargetSSELine(trimmedLine);
      if (!parsed) continue;
      
      if (parsed.reasoning) {
        reasoningContent += parsed.reasoning;
      }
      if (parsed.content) {
        content += parsed.content;
      }
    }
  }
  
  debugLog("Non-streaming response - Reasoning:", reasoningContent.slice(0, 100) + "...");
  debugLog("Non-streaming response - Content:", content.slice(0, 100) + "...");
  
  const response = {
    id: responseId,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: requestModel,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content,
        reasoning_content: reasoningContent || null
      },
      finish_reason: "stop"
    }],
    usage: {
      prompt_tokens: 10,
      completion_tokens: reasoningContent.length + content.length,
      total_tokens: 10 + reasoningContent.length + content.length,
      completion_tokens_details: {
        reasoning_tokens: reasoningContent.length
      }
    }
  };
  
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// 处理聊天完成请求
async function handleChatCompletions(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    debugLog("Received chat request:", JSON.stringify(body).slice(0, 500));
    
    const { messages, stream = false, model } = body;
    
    if (!messages || !Array.isArray(messages)) {
      return new Response(JSON.stringify({
        error: {
          message: "messages is required and must be an array",
          type: "invalid_request_error"
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // 获取映射后的模型名
    const mappedModel = MODEL_MAPPING[model] || model;
    debugLog(`Model mapping: ${model} -> ${mappedModel}`);
    
    // 处理消息
    const processedMessages = processMessages(messages);
    
    // 构造转发请求
    const targetUrl = `${BASE_URL}/api/chat/`;
    const targetBody = {
      model: mappedModel,
      messages: processedMessages,
      stream: true  // 目标请求始终使用 stream: true
    };
    
    const userAgent = getRandomUserAgent();
    debugLog(`Using User-Agent: ${userAgent}`);
    debugLog(`Target URL: ${targetUrl}`);
    debugLog(`Target body: ${JSON.stringify(targetBody)}`);
    
    const targetResponse = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": userAgent,
        "Referer": `${BASE_URL}/`
      },
      body: JSON.stringify(targetBody)
    });
    
    if (!targetResponse.ok) {
      debugLog(`Target response error: ${targetResponse.status}`);
      return new Response(JSON.stringify({
        error: {
          message: `Upstream server error: ${targetResponse.status}`,
          type: "upstream_error"
        }
      }), {
        status: targetResponse.status,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    const responseId = `chatcmpl-${generateUUID()}`;
    
    if (stream) {
      return handleStreamingChat(targetResponse, model, responseId);
    } else {
      return handleNonStreamingChat(targetResponse, model, responseId);
    }
    
  } catch (error) {
    debugLog("Chat completion error:", error);
    return new Response(JSON.stringify({
      error: {
        message: error instanceof Error ? error.message : "Internal server error",
        type: "internal_error"
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

// 处理 CORS 预检请求
function handleCors(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400"
    }
  });
}

// 添加 CORS 头
function addCorsHeaders(response: Response): Response {
  const newHeaders = new Headers(response.headers);
  newHeaders.set("Access-Control-Allow-Origin", "*");
  newHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  newHeaders.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

// 主处理函数
async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
  debugLog(`${method} ${path}`);
  
  // 处理 CORS 预检
  if (method === "OPTIONS") {
    return handleCors();
  }
  
  // 处理模型列表请求
  if (path === "/v1/models" && method === "GET") {
    if (!validateAuth(request)) {
      return addCorsHeaders(unauthorizedResponse());
    }
    return addCorsHeaders(handleModelsRequest());
  }
  
  // 处理聊天完成请求
  if (path === "/v1/chat/completions" && method === "POST") {
    if (!validateAuth(request)) {
      return addCorsHeaders(unauthorizedResponse());
    }
    const response = await handleChatCompletions(request);
    return addCorsHeaders(response);
  }
  
  // 根路径返回简单信息
  if (path === "/" && method === "GET") {
    return addCorsHeaders(new Response(JSON.stringify({
      message: "OpenAI Compatible API Proxy",
      endpoints: ["/v1/models", "/v1/chat/completions"]
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
  }
  
  // 404
  return addCorsHeaders(new Response(JSON.stringify({
    error: {
      message: "Not found",
      type: "not_found"
    }
  }), {
    status: 404,
    headers: { "Content-Type": "application/json" }
  }));
}

// Deno.serve 入口
Deno.serve(handleRequest);
