// deno

/**
 * MiMoCode Free API 代理 - 支持多种 API 格式
 * 适配 Deno Deploy 边缘环境
 */

// ============================================================
// 配置
// ============================================================

const MIMO_BASE_URL = "https://api.xiaomimimo.com/api/free-ai";
const JWT_CACHE_TTL = 50 * 60; // 50 秒（提前刷新）

// ============================================================
// 类型定义
// ============================================================

interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  name?: string;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

interface ToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

interface Tool {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
}

interface ChatCompletionRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  tools?: Tool[];
  tool_choice?: "auto" | "none" | { type: "function"; function: { name: string } };
  temperature?: number;
  max_tokens?: number;
}

interface ResponsesRequest {
  model: string;
  input: string | Message[];
  stream?: boolean;
  tools?: Tool[];
  tool_choice?: "auto" | "none" | { type: "function"; function: { name: string } };
  temperature?: number;
  max_output_tokens?: number;
}

interface MessagesRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  tools?: Tool[];
  tool_choice?: "auto" | "any" | { type: "function"; function: { name: string } };
  max_tokens: number;
  temperature?: number;
  system?: string;
}

// ============================================================
// 设备指纹（异步）
// ============================================================

async function getDeviceFingerprint(): Promise<string> {
  const hostname = Deno.env.get("HOSTNAME") || "unknown";
  const os = Deno.build.os;
  const arch = Deno.build.arch;
  const username = Deno.env.get("USER") || Deno.env.get("USERNAME") || "unknown";
  
  const raw = `${hostname}|${os}|${arch}|unknown|${username}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================
// JWT 缓存（内存）
// ============================================================

let cachedJwt: string | null = null;
let jwtExpiry: number = 0;

async function getJwt(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cachedJwt && now < jwtExpiry) {
    return cachedJwt;
  }
  
  const fingerprint = await getDeviceFingerprint();
  const response = await fetch(`${MIMO_BASE_URL}/bootstrap`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client: fingerprint }),
  });
  
  if (!response.ok) {
    throw new Error(`Bootstrap failed: ${response.status}`);
  }
  
  const data = await response.json();
  cachedJwt = data.jwt;
  
  // 解析 JWT 过期时间
  try {
    const parts = cachedJwt.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(atob(parts[1]));
      jwtExpiry = payload.exp || now + 3600;
    } else {
      jwtExpiry = now + 3600;
    }
  } catch {
    jwtExpiry = now + 3600;
  }
  
  // 提前 10 分钟刷新
  jwtExpiry -= 600;
  
  return cachedJwt;
}

// ============================================================
// 工具函数
// ============================================================

function getRandomSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return "ses_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateId(prefix: string): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.getRandomValues(new Uint8Array(8));
  const randomStr = Array.from(random).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${timestamp}_${randomStr}`;
}

function createErrorResponse(message: string, status: number = 400, type: string = "invalid_request_error"): Response {
  return new Response(JSON.stringify({
    error: { message, type, param: null, code: status }
  }), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

function createStreamingResponse(stream: ReadableStream): Response {
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": "*",
    }
  });
}

function createJsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

// ============================================================
// 模型列表
// ============================================================

const SUPPORTED_MODELS = ["mimo-auto"];

function getModelsList(): Response {
  const now = Math.floor(Date.now() / 1000);
  const models = SUPPORTED_MODELS.map(id => ({
    id,
    object: "model",
    created: now,
    owned_by: "xiaomi-mimo",
  }));
  
  return createJsonResponse({
    object: "list",
    data: models,
  });
}

// ============================================================
// 核心：调用 MiMoCode API
// ============================================================

async function callMimoAPI(
  messages: Message[],
  stream: boolean,
  tools?: Tool[],
  tool_choice?: "auto" | "none" | { type: "function"; function: { name: string } }
): Promise<Response> {
  // 确保系统消息包含 Anti-Abuse 标记
  const hasSystem = messages.some(m => m.role === "system");
  let finalMessages = [...messages];
  
  if (!hasSystem) {
    finalMessages.unshift({
      role: "system",
      content: "You are MiMoCode, an interactive CLI tool that helps users with software engineering tasks.",
    });
  } else {
    const sysMsg = finalMessages.find(m => m.role === "system");
    if (sysMsg && sysMsg.content && !sysMsg.content.includes("MiMoCode")) {
      sysMsg.content = `You are MiMoCode, an interactive CLI tool that helps users with software engineering tasks.\n\n${sysMsg.content}`;
    }
  }
  
  const jwt = await getJwt();
  const sessionId = getRandomSessionId();
  
  const requestBody: Record<string, unknown> = {
    model: "mimo-auto",
    stream: true, // 始终使用流式
    messages: finalMessages.map(m => ({
      role: m.role,
      content: m.content,
      ...(m.tool_calls ? { tool_calls: m.tool_calls } : {}),
      ...(m.tool_call_id ? { tool_call_id: m.tool_call_id } : {}),
      ...(m.name ? { name: m.name } : {}),
    })),
  };
  
  if (tools && tools.length > 0) {
    requestBody.tools = tools;
  }
  if (tool_choice) {
    requestBody.tool_choice = tool_choice;
  }
  
  const response = await fetch(`${MIMO_BASE_URL}/openai/chat`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${jwt}`,
      "X-Mimo-Source": "mimocode-cli-free",
      "x-session-affinity": sessionId,
    },
    body: JSON.stringify(requestBody),
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`MiMo API error: ${response.status} - ${errorText}`);
  }
  
  if (stream) {
    return createStreamingResponse(transformMimoStreamToOpenAI(response, tools));
  } else {
    const content = await collectNonStreamResponse(response, tools);
    return createJsonResponse(content);
  }
}

// ============================================================
// 流式响应转换：MiMo -> OpenAI SSE
// ============================================================

function transformMimoStreamToOpenAI(
  response: Response,
  _tools?: Tool[]
): ReadableStream {
  const reader = response.body?.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  
  if (!reader) {
    throw new Error("No response body");
  }
  
  const chatId = generateId("chatcmpl");
  const created = Math.floor(Date.now() / 1000);
  const model = "mimo-auto";
  
  let buffer = "";
  let hasSentRole = false;
  const toolCalls: Map<string, { id: string; name: string; arguments: string }> = new Map();
  let currentToolCallId: string | null = null;
  
  return new ReadableStream({
    async start(controller) {
      try {
        // 发送初始 chunk
        const initChunk = {
          id: chatId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [{
            index: 0,
            delta: { role: "assistant" },
            finish_reason: null,
          }],
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(initChunk)}\n\n`));
        hasSentRole = true;
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const dataStr = line.slice(6);
            if (dataStr === "[DONE]") continue;
            
            try {
              const data = JSON.parse(dataStr);
              const choice = data.choices?.[0];
              if (!choice) continue;
              
              const delta = choice.delta || {};
              
              // 推理内容
              if (delta.reasoning_content) {
                const chunk = {
                  id: chatId,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  choices: [{
                    index: 0,
                    delta: { reasoning_content: delta.reasoning_content },
                    finish_reason: null,
                  }],
                };
                controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
              }
              
              // 普通内容
              if (delta.content) {
                const chunk = {
                  id: chatId,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  choices: [{
                    index: 0,
                    delta: { content: delta.content },
                    finish_reason: null,
                  }],
                };
                controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
              }
              
              // 工具调用
              if (delta.tool_calls) {
                for (const tc of delta.tool_calls) {
                  if (tc.id) {
                    currentToolCallId = tc.id;
                    toolCalls.set(tc.id, { id: tc.id, name: "", arguments: "" });
                  }
                  if (tc.function?.name) {
                    const existing = toolCalls.get(currentToolCallId || tc.id);
                    if (existing) {
                      existing.name = tc.function.name;
                    }
                  }
                  if (tc.function?.arguments) {
                    const existing = toolCalls.get(currentToolCallId || tc.id);
                    if (existing) {
                      existing.arguments += tc.function.arguments;
                    }
                  }
                }
              }
              
              // 结束
              if (choice.finish_reason) {
                if (toolCalls.size > 0) {
                  for (const [, tc] of toolCalls) {
                    const toolChunk = {
                      id: chatId,
                      object: "chat.completion.chunk",
                      created,
                      model,
                      choices: [{
                        index: 0,
                        delta: {
                          tool_calls: [{
                            id: tc.id,
                            type: "function",
                            function: {
                              name: tc.name,
                              arguments: tc.arguments,
                            },
                          }],
                        },
                        finish_reason: null,
                      }],
                    };
                    controller.enqueue(encoder.encode(`data: ${JSON.stringify(toolChunk)}\n\n`));
                  }
                }
                
                const finalChunk = {
                  id: chatId,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  choices: [{
                    index: 0,
                    delta: {},
                    finish_reason: choice.finish_reason,
                  }],
                };
                controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
              }
            } catch {
              // 忽略解析错误
            }
          }
        }
        
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
    cancel() {
      reader.cancel();
    },
  });
}

// ============================================================
// 非流式响应收集
// ============================================================

async function collectNonStreamResponse(
  response: Response,
  _tools?: Tool[]
): Promise<Record<string, unknown>> {
  const reader = response.body?.getReader();
  const decoder = new TextDecoder();
  
  if (!reader) {
    throw new Error("No response body");
  }
  
  let buffer = "";
  let fullContent = "";
  let reasoningContent = "";
  const toolCalls: ToolCall[] = [];
  let finishReason: string | null = null;
  
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";
    
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const dataStr = line.slice(6);
      if (dataStr === "[DONE]") continue;
      
      try {
        const data = JSON.parse(dataStr);
        const choice = data.choices?.[0];
        if (!choice) continue;
        
        const delta = choice.delta || {};
        
        if (delta.reasoning_content) {
          reasoningContent += delta.reasoning_content;
        }
        if (delta.content) {
          fullContent += delta.content;
        }
        if (delta.tool_calls) {
          for (const tc of delta.tool_calls) {
            const existing = toolCalls.find(t => t.id === tc.id);
            if (existing) {
              if (tc.function?.arguments) {
                existing.function.arguments += tc.function.arguments;
              }
            } else if (tc.id) {
              toolCalls.push({
                id: tc.id,
                type: "function",
                function: {
                  name: tc.function?.name || "",
                  arguments: tc.function?.arguments || "",
                },
              });
            }
          }
        }
        if (choice.finish_reason) {
          finishReason = choice.finish_reason;
        }
      } catch {
        // 忽略解析错误
      }
    }
  }
  
  const message: Record<string, unknown> = {
    role: "assistant",
    content: fullContent || null,
  };
  
  if (reasoningContent) {
    message.reasoning_content = reasoningContent;
  }
  
  if (toolCalls.length > 0) {
    message.tool_calls = toolCalls;
  }
  
  return {
    id: generateId("chatcmpl"),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "mimo-auto",
    choices: [{
      index: 0,
      message,
      finish_reason: finishReason || "stop",
    }],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

// ============================================================
// 格式转换器：OpenAI Chat Completions
// ============================================================

async function handleChatCompletions(request: Request): Promise<Response> {
  try {
    const body = await request.json() as ChatCompletionRequest;
    
    if (body.model !== "mimo-auto") {
      return createErrorResponse(`Model "${body.model}" not supported. Only "mimo-auto" is available.`, 400);
    }
    if (!body.messages || !Array.isArray(body.messages) || body.messages.length === 0) {
      return createErrorResponse("Messages are required", 400);
    }
    
    return await callMimoAPI(
      body.messages,
      body.stream ?? false,
      body.tools,
      body.tool_choice
    );
  } catch (error) {
    if (error instanceof SyntaxError) {
      return createErrorResponse("Invalid JSON body", 400);
    }
    return createErrorResponse(error.message, 500, "api_error");
  }
}

// ============================================================
// 格式转换器：OpenAI Responses
// ============================================================

async function handleResponses(request: Request): Promise<Response> {
  try {
    const body = await request.json() as ResponsesRequest;
    
    if (body.model !== "mimo-auto") {
      return createErrorResponse(`Model "${body.model}" not supported. Only "mimo-auto" is available.`, 400);
    }
    
    let messages: Message[];
    if (typeof body.input === "string") {
      messages = [{ role: "user", content: body.input }];
    } else if (Array.isArray(body.input)) {
      messages = body.input as Message[];
    } else {
      return createErrorResponse("Input must be a string or array of messages", 400);
    }
    
    return await callMimoAPI(
      messages,
      body.stream ?? false,
      body.tools,
      body.tool_choice
    );
  } catch (error) {
    if (error instanceof SyntaxError) {
      return createErrorResponse("Invalid JSON body", 400);
    }
    return createErrorResponse(error.message, 500, "api_error");
  }
}

// ============================================================
// 格式转换器：Anthropic Messages
// ============================================================

async function handleMessages(request: Request): Promise<Response> {
  try {
    const body = await request.json() as MessagesRequest;
    
    if (body.model !== "mimo-auto") {
      return createErrorResponse(`Model "${body.model}" not supported. Only "mimo-auto" is available.`, 400);
    }
    if (!body.messages || !Array.isArray(body.messages) || body.messages.length === 0) {
      return createErrorResponse("Messages are required", 400);
    }
    if (!body.max_tokens || body.max_tokens < 1) {
      return createErrorResponse("max_tokens is required and must be >= 1", 400);
    }
    
    const messages: Message[] = [];
    if (body.system) {
      messages.push({ role: "system", content: body.system });
    }
    for (const msg of body.messages) {
      messages.push({
        role: msg.role === "tool" ? "tool" : msg.role,
        content: msg.content,
        ...(msg.name ? { name: msg.name } : {}),
        ...(msg.tool_call_id ? { tool_call_id: msg.tool_call_id } : {}),
        ...(msg.tool_calls ? { tool_calls: msg.tool_calls } : {}),
      });
    }
    
    let toolChoice = body.tool_choice;
    if (toolChoice === "any") {
      toolChoice = "auto";
    }
    
    const response = await callMimoAPI(
      messages,
      body.stream ?? false,
      body.tools,
      toolChoice as any
    );
    
    if (!(body.stream ?? false)) {
      const data = await response.json();
      const anthropicResponse = convertOpenAIToAnthropic(data);
      return createJsonResponse(anthropicResponse);
    }
    
    if (response.body) {
      const transformedStream = transformOpenAIStreamToAnthropic(response.body);
      return createStreamingResponse(transformedStream);
    }
    
    return response;
  } catch (error) {
    if (error instanceof SyntaxError) {
      return createErrorResponse("Invalid JSON body", 400);
    }
    return createErrorResponse(error.message, 500, "api_error");
  }
}

// ============================================================
// Anthropic 格式转换器
// ============================================================

function convertOpenAIToAnthropic(openaiData: Record<string, unknown>): Record<string, unknown> {
  const choice = (openaiData.choices as any[])?.[0] || {};
  const message = choice.message || {};
  
  const anthropicMessage: Record<string, unknown> = {
    id: openaiData.id || generateId("msg"),
    type: "message",
    role: "assistant",
    content: [],
    model: openaiData.model || "mimo-auto",
    stop_reason: choice.finish_reason === "stop" ? "end_turn" : 
                 choice.finish_reason === "tool_calls" ? "tool_use" : null,
    stop_sequence: null,
    usage: {
      input_tokens: (openaiData.usage as any)?.prompt_tokens || 0,
      output_tokens: (openaiData.usage as any)?.completion_tokens || 0,
    },
  };
  
  if (message.content) {
    anthropicMessage.content.push({
      type: "text",
      text: message.content,
    });
  }
  
  if (message.tool_calls && Array.isArray(message.tool_calls)) {
    for (const tc of message.tool_calls) {
      anthropicMessage.content.push({
        type: "tool_use",
        id: tc.id,
        name: tc.function?.name || "",
        input: JSON.parse(tc.function?.arguments || "{}"),
      });
    }
    anthropicMessage.stop_reason = "tool_use";
  }
  
  return anthropicMessage;
}

function transformOpenAIStreamToAnthropic(openAIStream: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  const reader = openAIStream.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  
  let buffer = "";
  let messageId = generateId("msg");
  let model = "mimo-auto";
  let fullContent = "";
  const toolUses: Array<{ id: string; name: string; input: string }> = [];
  let currentToolId: string | null = null;
  let currentToolName = "";
  let currentToolInput = "";
  
  return new ReadableStream({
    async start(controller) {
      try {
        controller.enqueue(encoder.encode(`event: message_start\ndata: {"type":"message_start","message":{"id":"${messageId}","type":"message","role":"assistant","content":[],"model":"${model}","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}}\n\n`));
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const dataStr = line.slice(6);
            if (dataStr === "[DONE]") continue;
            
            try {
              const data = JSON.parse(dataStr);
              const choice = data.choices?.[0];
              if (!choice) continue;
              
              const delta = choice.delta || {};
              
              if (delta.content) {
                fullContent += delta.content;
                controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"${delta.content}"}}\n\n`));
              }
              
              if (delta.tool_calls) {
                for (const tc of delta.tool_calls) {
                  if (tc.id) {
                    if (currentToolId) {
                      try {
                        JSON.parse(currentToolInput || "{}");
                        controller.enqueue(encoder.encode(`event: content_block_stop\ndata: {"type":"content_block_stop","index":${toolUses.length}}\n\n`));
                      } catch {}
                    }
                    currentToolId = tc.id;
                    currentToolName = "";
                    currentToolInput = "";
                    toolUses.push({ id: tc.id, name: "", input: "" });
                    
                    controller.enqueue(encoder.encode(`event: content_block_start\ndata: {"type":"content_block_start","index":${toolUses.length - 1},"content_block":{"type":"tool_use","id":"${tc.id}","name":"","input":{}}}\n\n`));
                  }
                  if (tc.function?.name) {
                    currentToolName = tc.function.name;
                    toolUses[toolUses.length - 1].name = currentToolName;
                    controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","index":${toolUses.length - 1},"delta":{"type":"input_json_delta","partial_json":"{\\"name\\":\\"${currentToolName}\\""}}\n\n`));
                  }
                  if (tc.function?.arguments) {
                    currentToolInput += tc.function.arguments;
                    toolUses[toolUses.length - 1].input = currentToolInput;
                    controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","index":${toolUses.length - 1},"delta":{"type":"input_json_delta","partial_json":"${tc.function.arguments}"}}\n\n`));
                  }
                }
              }
              
              if (choice.finish_reason) {
                if (currentToolId) {
                  try {
                    JSON.parse(currentToolInput || "{}");
                    controller.enqueue(encoder.encode(`event: content_block_stop\ndata: {"type":"content_block_stop","index":${toolUses.length - 1}}\n\n`));
                  } catch {}
                }
                
                const stopReason = choice.finish_reason === "stop" ? "end_turn" :
                                   choice.finish_reason === "tool_calls" ? "tool_use" : null;
                controller.enqueue(encoder.encode(`event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"${stopReason}","stop_sequence":null},"usage":{"output_tokens":0}}\n\n`));
              }
            } catch {
              // 忽略解析错误
            }
          }
        }
        
        controller.enqueue(encoder.encode(`event: message_stop\ndata: {"type":"message_stop"}\n\n`));
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
    cancel() {
      reader.cancel();
    },
  });
}

// ============================================================
// CORS 处理
// ============================================================

function handleCORS(request: Request): Response | null {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      },
    });
  }
  return null;
}

// ============================================================
// 主路由
// ============================================================

async function handler(request: Request): Promise<Response> {
  const corsResponse = handleCORS(request);
  if (corsResponse) return corsResponse;
  
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
  try {
    if (path === "/v1/models" && method === "GET") {
      return getModelsList();
    }
    if (path === "/v1/chat/completions" && method === "POST") {
      return await handleChatCompletions(request);
    }
    if (path === "/v1/responses" && method === "POST") {
      return await handleResponses(request);
    }
    if (path === "/v1/messages" && method === "POST") {
      return await handleMessages(request);
    }
    if (path === "/health" || path === "/") {
      return createJsonResponse({
        status: "ok",
        service: "mimo-proxy",
        endpoints: [
          "GET  /v1/models",
          "POST /v1/chat/completions",
          "POST /v1/responses",
          "POST /v1/messages",
        ],
      });
    }
    return new Response("Not Found", { status: 404 });
  } catch (error) {
    console.error("Handler error:", error);
    return createErrorResponse(error.message, 500, "api_error");
  }
}

// ============================================================
// 启动服务
// ============================================================

Deno.serve({ port: 8000 }, handler);

console.log("🚀 MiMoCode Proxy Server running on http://localhost:8000");
console.log("📋 Endpoints:");
console.log("  GET  /v1/models");
console.log("  POST /v1/chat/completions");
console.log("  POST /v1/responses");
console.log("  POST /v1/messages");
