// === 配置与初始化 ===
const API_BASE_URL = "https://typli.ai";
const MODEL_MAP: Record<string, string> = {
  "gpt-4o-mini": "openai/gpt-4o-mini",
  "gpt-4o": "openai/gpt-4o",
  "gpt-5-mini": "openai/gpt-5-mini",
  "gpt-5": "openai/gpt-5",
  "gemini-2.5-flash": "google/gemini-2.5-flash",
  "claude-haiku-4-5": "anthropic/claude-haiku-4-5",
  "grok-4-fast-reasoning": "xai/grok-4-fast-reasoning",
  "grok-4-fast": "xai/grok-4-fast",
  "deepseek-chat": "deepseek/deepseek-chat",
  "deepseek-reasoner": "deepseek/deepseek-reasoner",
};

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
];

// 从环境变量获取鉴权密钥
const AUTH_KEYS = (Deno.env.get("AUTH_KEYS") || "sk-default,sk-false")
  .split(",")
  .map((k) => k.trim())
  .filter(Boolean);

// === 工具函数 ===

/**
 * 生成随机UUID v4
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * 获取当前时间戳（秒）
 */
function getTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * 随机选择User-Agent
 */
function getRandomUserAgent(): string {
  const index = Math.floor(Math.random() * USER_AGENTS.length);
  return USER_AGENTS[index];
}

/**
 * 验证API密钥
 */
function validateAuth(request: Request): boolean {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return false;
  }
  const key = authHeader.substring(7);
  return AUTH_KEYS.includes(key);
}

/**
 * 将OpenAI消息格式转换为typli.ai格式
 */
function formatMessages(messages: Array<{ role: string; content: string }>): string {
  return messages.map((msg) => `${msg.role}:${msg.content}`).join(";");
}

/**
 * CORS响应头
 */
function getCorsHeaders(): Headers {
  const headers = new Headers();
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Allow-Credentials", "true");
  return headers;
}

/**
 * 健康检查响应
 */
function healthCheck(): Response {
  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");
  
  return new Response(
    JSON.stringify({
      status: "healthy",
      service: "typli-ai-proxy",
      timestamp: new Date().toISOString(),
    }),
    {
      status: 200,
      headers,
    }
  );
}

/**
 * 401未授权响应
 */
function unauthorized(): Response {
  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");
  
  return new Response(
    JSON.stringify({
      error: {
        message: "Invalid API key",
        type: "invalid_request_error",
        code: "invalid_api_key",
      },
    }),
    {
      status: 401,
      headers,
    }
  );
}

/**
 * 400错误响应
 */
function badRequest(message: string): Response {
  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");
  
  return new Response(
    JSON.stringify({
      error: {
        message,
        type: "invalid_request_error",
      },
    }),
    {
      status: 400,
      headers,
    }
  );
}

/**
 * 500错误响应
 */
function internalError(message: string): Response {
  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");
  
  return new Response(
    JSON.stringify({
      error: {
        message,
        type: "internal_error",
      },
    }),
    {
      status: 500,
      headers,
    }
  );
}

// === API处理函数 ===

/**
 * 处理GET /v1/models请求
 */
async function handleModelsRequest(request: Request): Promise<Response> {
  if (!validateAuth(request)) {
    return unauthorized();
  }

  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");

  const models = Object.keys(MODEL_MAP).map((id) => ({
    id,
    object: "model",
    created: getTimestamp(),
    owned_by: "typlichat",
  }));

  return new Response(
    JSON.stringify({
      object: "list",
      data: models,
    }),
    {
      status: 200,
      headers,
    }
  );
}

/**
 * 解析typli.ai的SSE响应
 */
async function parseTypliResponse(
  response: Response,
  isStreamMode: boolean,
  openAIId: string,
  model: string
): Promise<Response> {
  if (!response.body) {
    throw new Error("Empty response body");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  // 流式响应处理
  if (isStreamMode) {
    const stream = new ReadableStream({
      async start(controller) {
        let buffer = "";
        let reasoningContent = "";
        let textContent = "";
        let inReasoning = false;
        let inText = false;
        let usage = null;

        try {
          // 发送开始块
          const startChunk = {
            id: openAIId,
            object: "chat.completion.chunk",
            created: getTimestamp(),
            model,
            choices: [
              {
                index: 0,
                delta: {
                  role: "assistant",
                  content: null,
                  reasoning_content: "",
                },
                logprobs: null,
                finish_reason: null,
              },
            ],
          };
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(startChunk)}\n\n`));

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";

            for (const line of lines) {
              if (line.startsWith("data: ")) {
                const data = line.slice(6);

                if (data === "[DONE]") {
                  // 发送使用统计块
                  if (usage) {
                    const usageChunk = {
                      id: openAIId,
                      object: "chat.completion.chunk",
                      created: getTimestamp(),
                      model,
                      choices: [
                        {
                          index: 0,
                          delta: {
                            content: "",
                            reasoning_content: null,
                          },
                          finish_reason: "stop",
                        },
                      ],
                      usage: {
                        prompt_tokens: usage.prompt_tokens || 0,
                        completion_tokens: usage.completion_tokens || 0,
                        total_tokens: usage.total_tokens || 0,
                        completion_tokens_details: {
                          reasoning_tokens: usage.reasoning_tokens || 0,
                        },
                      },
                    };
                    controller.enqueue(encoder.encode(`data: ${JSON.stringify(usageChunk)}\n\n`));
                  }
                  controller.enqueue(encoder.encode("data: [DONE]\n\n"));
                  break;
                }

                try {
                  const parsed = JSON.parse(data);
                  const type = parsed.type;

                  // 处理思考内容
                  if (type === "reasoning-start") {
                    inReasoning = true;
                    reasoningContent = "";
                  } else if (type === "reasoning-delta" && inReasoning) {
                    reasoningContent += parsed.delta || "";
                    const chunk = {
                      id: openAIId,
                      object: "chat.completion.chunk",
                      created: getTimestamp(),
                      model,
                      choices: [
                        {
                          index: 0,
                          delta: {
                            content: null,
                            reasoning_content: parsed.delta || "",
                          },
                          finish_reason: null,
                        },
                      ],
                    };
                    controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                  } else if (type === "reasoning-end") {
                    inReasoning = false;
                  }

                  // 处理文本内容
                  if (type === "text-start") {
                    inText = true;
                    textContent = "";
                  } else if (type === "text-delta" && inText) {
                    textContent += parsed.delta || "";
                    const chunk = {
                      id: openAIId,
                      object: "chat.completion.chunk",
                      created: getTimestamp(),
                      model,
                      choices: [
                        {
                          index: 0,
                          delta: {
                            content: parsed.delta || "",
                            reasoning_content: null,
                          },
                          finish_reason: null,
                        },
                      ],
                    };
                    controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                  } else if (type === "text-end") {
                    inText = false;
                  }

                  // 处理使用统计
                  if (type === "data-session") {
                    const dataSession = parsed.data;
                    if (dataSession && dataSession.usage) {
                      const stdUsage = dataSession.usage.standard || {};
                      usage = {
                        prompt_tokens: 0, // typli.ai不提供此数据
                        completion_tokens: stdUsage.words || 0,
                        total_tokens: (stdUsage.words || 0),
                        reasoning_tokens: 0, // 无法精确获取
                      };
                    }
                  }
                } catch (e) {
                  // 忽略解析失败的行
                  console.error("Parse error:", e);
                }
              }
            }
          }

          controller.close();
        } catch (error) {
          controller.error(error);
        } finally {
          reader.releaseLock();
        }
      },
    });

    const headers = getCorsHeaders();
    headers.set("Content-Type", "text/event-stream");
    headers.set("Cache-Control", "no-cache");
    headers.set("X-Accel-Buffering", "no");

    return new Response(stream, {
      status: 200,
      headers,
    });
  } 
  // 非流式响应处理
  else {
    let buffer = "";
    let reasoningContent = "";
    let textContent = "";
    let inReasoning = false;
    let inText = false;
    let usage = null;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value);
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6);

            if (data === "[DONE]") break;

            try {
              const parsed = JSON.parse(data);
              const type = parsed.type;

              // 处理思考内容
              if (type === "reasoning-start") {
                inReasoning = true;
                reasoningContent = "";
              } else if (type === "reasoning-delta" && inReasoning) {
                reasoningContent += parsed.delta || "";
              } else if (type === "reasoning-end") {
                inReasoning = false;
              }

              // 处理文本内容
              if (type === "text-start") {
                inText = true;
                textContent = "";
              } else if (type === "text-delta" && inText) {
                textContent += parsed.delta || "";
              } else if (type === "text-end") {
                inText = false;
              }

              // 处理使用统计
              if (type === "data-session") {
                const dataSession = parsed.data;
                if (dataSession && dataSession.usage) {
                  const stdUsage = dataSession.usage.standard || {};
                  usage = {
                    prompt_tokens: 0, // typli.ai不提供此数据
                    completion_tokens: stdUsage.words || 0,
                    total_tokens: (stdUsage.words || 0),
                    reasoning_tokens: 0, // 无法精确获取
                  };
                }
              }
            } catch (e) {
              // 忽略解析失败的行
              console.error("Parse error:", e);
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }

    const responseData: any = {
      id: openAIId,
      object: "chat.completion",
      created: getTimestamp(),
      model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: textContent,
            reasoning_content: reasoningContent || null,
          },
          finish_reason: "stop",
        },
      ],
    };

    if (usage) {
      responseData.usage = {
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        total_tokens: usage.total_tokens,
        completion_tokens_details: {
          reasoning_tokens: usage.reasoning_tokens,
        },
      };
    }

    const headers = getCorsHeaders();
    headers.set("Content-Type", "application/json");

    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers,
    });
  }
}

/**
 * 处理POST /v1/chat/completions请求
 */
async function handleChatRequest(request: Request): Promise<Response> {
  if (!validateAuth(request)) {
    return unauthorized();
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  const { messages, stream, model } = body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return badRequest("Missing or invalid messages");
  }

  if (!model || typeof model !== "string") {
    return badRequest("Missing or invalid model");
  }

  const mappedModel = MODEL_MAP[model];
  if (!mappedModel) {
    return badRequest(`Unsupported model: ${model}`);
  }

  // 格式化消息
  const formattedMessages = formatMessages(messages);

  // 构造转发请求
  const typliRequestBody = {
    modelId: mappedModel,
    id: generateUUID(),
    messages: [
      {
        role: "user",
        parts: [
          {
            type: "text",
            text: formattedMessages,
          },
        ],
        id: generateUUID(),
      },
    ],
    trigger: "submit-message",
  };

  const randomUserAgent = getRandomUserAgent();

  try {
    const typliResponse = await fetch(`${API_BASE_URL}/api/chat2`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "user-agent": "ai-sdk/5.0.87 runtime/browser",
        "User-Agent": randomUserAgent,
        "Referer": "https://typli.ai/ai-chat",
      },
      body: JSON.stringify(typliRequestBody),
    });

    if (!typliResponse.ok) {
      return internalError(`Upstream error: ${typliResponse.statusText}`);
    }

    const openAIId = `chatcmpl-${generateUUID()}`;
    return parseTypliResponse(
      typliResponse,
      stream === true,
      openAIId,
      model
    );
  } catch (error) {
    console.error("Fetch error:", error);
    return internalError("Failed to fetch from upstream");
  }
}

// === 主服务器入口 ===

const handler = async (request: Request): Promise<Response> => {
  const url = new URL(request.url);
  const method = request.method;
  const pathname = url.pathname;

  // 全局CORS处理
  if (method === "OPTIONS") {
    const headers = getCorsHeaders();
    return new Response(null, {
      status: 200,
      headers,
    });
  }

  // 健康检查
  if (method === "GET" && pathname === "/") {
    return healthCheck();
  }

  // 模型列表接口
  if (method === "GET" && pathname === "/v1/models") {
    return handleModelsRequest(request);
  }

  // 聊天完成接口
  if (method === "POST" && pathname === "/v1/chat/completions") {
    return handleChatRequest(request);
  }

  // 404未找到
  const headers = getCorsHeaders();
  headers.set("Content-Type", "application/json");
  
  return new Response(
    JSON.stringify({
      error: {
        message: "Not found",
        type: "invalid_request_error",
      },
    }),
    {
      status: 404,
      headers,
    }
  );
};

// 启动Deno服务器
console.log("Starting Deno server on http://localhost:8000");
Deno.serve(handler);
