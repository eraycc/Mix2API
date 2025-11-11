// Kimi For Coding API OpenAI Proxy for Deno Deploy
// 鉴权传入 sk-kimi-xxx

// --- 配置 ---
const KIMI_API_BASE_URL = "https://api.kimi.com/coding";
const USER_AGENT = "KimiCLI/0.2.0";

// --- 日志工具 ---
function log(level: string, message: string, ...args: unknown[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level}] ${message}`, ...args);
}

// --- 流式代理处理 ---
async function* streamProxyHandler(
  targetUrl: string,
  headers: Headers,
  body: Uint8Array
): AsyncGenerator<Uint8Array> {
  try {
    const response = await fetch(targetUrl, {
      method: "POST",
      headers: headers,
      body: body,
    });

    if (!response.ok) {
      const errorContent = await response.text();
      log("ERROR", `Upstream server returned an error: ${response.status} - ${errorContent}`);
      const errorData = {
        error: {
          message: `Kimi API Error: ${response.status} - ${errorContent}`,
          type: "upstream_error"
        }
      };
      yield new TextEncoder().encode(JSON.stringify(errorData));
      return;
    }

    if (!response.body) {
      throw new Error("Response body is null");
    }

    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        yield value;
      }
    } finally {
      reader.releaseLock();
    }
  } catch (error) {
    log("ERROR", `Streaming proxy error: ${error}`);
    const errorData = {
      error: {
        message: `Proxy request failed: ${error}`,
        type: "proxy_error"
      }
    };
    yield new TextEncoder().encode(JSON.stringify(errorData));
  }
}

// --- 主要处理函数 ---
async function handleChatCompletions(request: Request): Promise<Response> {
  const targetUrl = `${KIMI_API_BASE_URL}/v1/chat/completions`;
  
  const body = await request.arrayBuffer();
  const bodyUint8Array = new Uint8Array(body);
  let isStream = false;
  let modifiedBody = bodyUint8Array;

  // --- 智能模式切换逻辑 ---
  try {
    const bodyText = new TextDecoder().decode(bodyUint8Array);
    const requestData = JSON.parse(bodyText);
    isStream = requestData.stream || false;

    // 检查是否使用虚拟的 "thinking" 模型
    if (requestData.model === "kimi-for-coding-thinking") {
      log("INFO", "Virtual model 'kimi-for-coding-thinking' detected. Enabling thinking mode.");
      requestData.thinking = true;
      requestData.model = "kimi-for-coding";
      modifiedBody = new TextEncoder().encode(JSON.stringify(requestData));
      log("INFO", `Modified request body for upstream: ${JSON.stringify(requestData)}`);
    }
  } catch (error) {
    log("WARN", "Received a request with a non-JSON body. Passing through without modification.");
  }

  // 准备转发头部
  const headersToForward = new Headers(request.headers);
  headersToForward.set("host", "api.kimi.com");
  headersToForward.set("user-agent", USER_AGENT);
  headersToForward.delete("content-length");
  headersToForward.delete("transfer-encoding");
  headersToForward.set("connection", "close");

  if (isStream) {
    // 流式响应
    const stream = streamProxyHandler(targetUrl, headersToForward, modifiedBody);
    const readableStream = new ReadableStream({
      async start(controller) {
        try {
          for await (const chunk of stream) {
            controller.enqueue(chunk);
          }
        } catch (error) {
          log("ERROR", `Stream processing error: ${error}`);
        } finally {
          controller.close();
        }
      }
    });

    return new Response(readableStream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      },
    });
  } else {
    // 非流式响应
    try {
      const proxiedResponse = await fetch(targetUrl, {
        method: "POST",
        headers: headersToForward,
        body: modifiedBody,
      });

      const responseHeaders = new Headers(proxiedResponse.headers);
      responseHeaders.delete("content-length");
      responseHeaders.delete("content-encoding");
      responseHeaders.delete("transfer-encoding");
      responseHeaders.delete("connection");

      return new Response(proxiedResponse.body, {
        status: proxiedResponse.status,
        headers: responseHeaders,
      });
    } catch (error) {
      log("ERROR", `Non-streaming proxy error: ${error}`);
      const errorData = {
        error: {
          message: String(error),
          type: "proxy_error"
        }
      };
      return new Response(JSON.stringify(errorData), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }
  }
}

// --- 模型列表接口 ---
function handleListModels(): Response {
  return new Response(
    JSON.stringify({
      object: "list",
      data: [
        { id: "kimi-for-coding", object: "model", owned_by: "moonshot-ai" },
        { id: "kimi-for-coding-thinking", object: "model", owned_by: "moonshot-ai" },
      ],
    }),
    {
      headers: { "Content-Type": "application/json" },
    }
  );
}

// --- 根路径处理 ---
function handleRoot(): Response {
  return new Response(
    JSON.stringify({ status: "running" }),
    {
      headers: { "Content-Type": "application/json" },
    }
  );
}

// --- 主路由处理 ---
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    log("INFO", `${method} ${path}`);

    // 路由处理
    if (path === "/" && method === "GET") {
      return handleRoot();
    }

    if (path === "/v1/chat/completions" && method === "POST") {
      return handleChatCompletions(request);
    }

    if (path === "/v1/models" && method === "GET") {
      return handleListModels();
    }

    // 404 处理
    return new Response(
      JSON.stringify({ error: "Not Found" }),
      {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }
    );
  },
};
