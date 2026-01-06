// main.ts - H2OGPTE to OpenAI API for Deno Deploy
// 支持多账号、会话池、Guest自动凭证、流式响应

// ============ 类型定义 ============

interface AccountCredential {
  H2OGPTE_SESSION: string;
  H2OGPTE_CSRF_TOKEN: string;
  H2OGPTE_WORKSPACE_ID: string;
  H2OGPTE_PROMPT_TEMPLATE_ID: string;
}

interface StoredCredential {
  session: string;
  csrf_token: string;
  user_id: string;
  username: string;
  created_at: string;
  last_used_at: string;
}

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  top_p?: number;
  n?: number;
  stream?: boolean;
  max_tokens?: number;
  presence_penalty?: number;
  frequency_penalty?: number;
  user?: string;
}

interface Model {
  id: string;
  object: string;
  created: number;
  owned_by: string;
}

// ============ 配置管理 ============

class Config {
  static H2OGPTE_BASE_URL: string = Deno.env.get("H2OGPTE_BASE_URL") || "https://h2ogpte.genai.h2o.ai";
  static IS_GUEST: boolean = (Deno.env.get("IS_GUEST") || "true").toLowerCase() === "true";
  
  // 多账号配置 (JSON格式)
  static ACCOUNTS: AccountCredential[] = [];
  
  // 账号选择模式: "random" | "round-robin"
  static ACCOUNT_MODE: string = Deno.env.get("ACCOUNT_MODE") || "round-robin";
  private static _accountIndex: number = 0;
  
  // 多API Key支持
  static API_KEYS: string[] = [];
  
  // 动态凭证 (Guest模式)
  private static _currentSession: string = "";
  private static _currentCsrfToken: string = "";
  private static _currentWorkspaceId: string = "";
  private static _currentPromptTemplateId: string = "";
  
  static {
    // 初始化API Keys
    const apiKeyStr = Deno.env.get("API_KEY") || "sk-false,sk-default";
    Config.API_KEYS = apiKeyStr.split(",").map(k => k.trim()).filter(k => k);
    
    // 初始化账号配置 (非Guest模式)
    if (!Config.IS_GUEST) {
      const accountsStr = Deno.env.get("H2OGPTE_ACCOUNTS");
      if (accountsStr) {
        try {
          Config.ACCOUNTS = JSON.parse(accountsStr);
        } catch (e) {
          console.error("解析 H2OGPTE_ACCOUNTS 失败:", e);
        }
      }
      
      // 如果没有多账号配置，尝试读取单账号配置
      if (Config.ACCOUNTS.length === 0) {
        const session = Deno.env.get("H2OGPTE_SESSION") || "";
        const csrfToken = Deno.env.get("H2OGPTE_CSRF_TOKEN") || "";
        if (session && csrfToken) {
          Config.ACCOUNTS.push({
            H2OGPTE_SESSION: session,
            H2OGPTE_CSRF_TOKEN: csrfToken,
            H2OGPTE_WORKSPACE_ID: Deno.env.get("H2OGPTE_WORKSPACE_ID") || "workspaces/h2ogpte-guest",
            H2OGPTE_PROMPT_TEMPLATE_ID: Deno.env.get("H2OGPTE_PROMPT_TEMPLATE_ID") || ""
          });
        }
      }
    }
  }
  
  static getNextAccount(): AccountCredential | null {
    if (Config.ACCOUNTS.length === 0) return null;
    
    let account: AccountCredential;
    if (Config.ACCOUNT_MODE === "random") {
      const index = Math.floor(Math.random() * Config.ACCOUNTS.length);
      account = Config.ACCOUNTS[index];
    } else {
      // round-robin
      account = Config.ACCOUNTS[Config._accountIndex];
      Config._accountIndex = (Config._accountIndex + 1) % Config.ACCOUNTS.length;
    }
    return account;
  }
  
  static getSession(): string {
    if (Config.IS_GUEST) {
      return Config._currentSession;
    }
    const account = Config.getNextAccount();
    return account?.H2OGPTE_SESSION || "";
  }
  
  static getCsrfToken(): string {
    if (Config.IS_GUEST) {
      return Config._currentCsrfToken;
    }
    const account = Config.getNextAccount();
    return account?.H2OGPTE_CSRF_TOKEN || "";
  }
  
  static getWorkspaceId(): string {
    if (Config.IS_GUEST) {
      return Config._currentWorkspaceId || "workspaces/h2ogpte-guest";
    }
    const account = Config.getNextAccount();
    return account?.H2OGPTE_WORKSPACE_ID || "workspaces/h2ogpte-guest";
  }
  
  static getPromptTemplateId(): string {
    if (Config.IS_GUEST) {
      return Config._currentPromptTemplateId || "";
    }
    const account = Config.getNextAccount();
    return account?.H2OGPTE_PROMPT_TEMPLATE_ID || "";
  }
  
  static updateCredentials(session: string, csrfToken: string, workspaceId?: string, promptTemplateId?: string): void {
    Config._currentSession = session;
    Config._currentCsrfToken = csrfToken;
    if (workspaceId) Config._currentWorkspaceId = workspaceId;
    if (promptTemplateId !== undefined) Config._currentPromptTemplateId = promptTemplateId;
  }
  
  static getCookies(): Record<string, string> {
    return {
      "h2ogpte.session": Config.getSession()
    };
  }
  
  static getHeaders(): Record<string, string> {
    return {
      "accept": "*/*",
      "content-type": "application/json",
      "origin": Config.H2OGPTE_BASE_URL,
      "x-csrf-token": Config.getCsrfToken(),
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    };
  }
  
  static verifyApiKey(authorization: string | null): boolean {
    // 如果没有配置API Key或只有默认值，跳过验证
    if (Config.API_KEYS.length === 0) return true;
    if (Config.API_KEYS.length === 2 && 
        Config.API_KEYS.includes("sk-false") && 
        Config.API_KEYS.includes("sk-default")) {
      return true;
    }
    
    if (!authorization) return false;
    
    let token = authorization;
    if (authorization.startsWith("Bearer ")) {
      token = authorization.substring(7);
    }
    
    return Config.API_KEYS.includes(token);
  }
}

// ============ 凭证存储 (内存版，适用于Edge环境) ============

class CredentialStore {
  private credential: StoredCredential | null = null;
  private refreshLock: boolean = false;
  
  async getCredential(): Promise<StoredCredential | null> {
    return this.credential;
  }
  
  async saveCredential(session: string, csrfToken: string, userId: string = "", username: string = ""): Promise<boolean> {
    const now = new Date().toISOString();
    this.credential = {
      session,
      csrf_token: csrfToken,
      user_id: userId,
      username,
      created_at: now,
      last_used_at: now
    };
    return true;
  }
  
  async clearCredential(): Promise<boolean> {
    this.credential = null;
    return true;
  }
  
  async renewSession(): Promise<StoredCredential | null> {
    const currentCred = await this.getCredential();
    if (!currentCred || !currentCred.session) {
      console.log("没有现有凭证，无法续期");
      return null;
    }
    
    console.log(`正在续期 ${currentCred.username} 的 session...`);
    
    try {
      const headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "cookie": `h2ogpte.session=${currentCred.session}`
      };
      
      const response = await fetch("https://h2ogpte.genai.h2o.ai/chats", {
        headers,
        redirect: "follow"
      });
      
      if (!response.ok) {
        console.log(`续期请求失败: ${response.status}`);
        return null;
      }
      
      // 尝试从响应获取新的 session
      let newSession = currentCred.session;
      const setCookies = response.headers.get("set-cookie");
      if (setCookies) {
        const match = setCookies.match(/h2ogpte\.session=([^;]+)/);
        if (match) {
          newSession = match[1];
        }
      }
      
      // 提取新的 csrf_token
      const html = await response.text();
      const startMarker = "data-conf='";
      const start = html.indexOf(startMarker);
      if (start >= 0) {
        const configStart = start + startMarker.length;
        const end = html.indexOf("'", configStart);
        if (end > configStart) {
          const configJson = html.substring(configStart, end);
          try {
            const configData = JSON.parse(configJson);
            const newCsrf = configData.csrf_token || "";
            const newUserId = configData.user_id || currentCred.user_id;
            const newUsername = configData.username || currentCred.username;
            
            await this.saveCredential(newSession, newCsrf, newUserId, newUsername);
            Config.updateCredentials(newSession, newCsrf);
            console.log(`续期成功: ${newUsername}`);
            return this.credential;
          } catch (_e) {
            // JSON 解析失败
          }
        }
      }
      
      console.log("续期失败: 无法解析新 token");
      return null;
    } catch (e) {
      console.log(`续期失败: ${e}`);
      return null;
    }
  }
  
  async refreshCredential(): Promise<StoredCredential | null> {
    return await this.fetchNewGuest();
  }
  
  private async fetchNewGuest(): Promise<StoredCredential | null> {
    console.log("正在获取新的 Guest 凭证...");
    
    try {
      const headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      };
      
      const response = await fetch("https://h2ogpte.genai.h2o.ai/chats", {
        headers,
        redirect: "follow"
      });
      
      if (!response.ok) {
        console.log(`获取新凭证失败: ${response.status}`);
        return null;
      }
      
      // 从响应获取 session
      let newSession = "";
      const setCookies = response.headers.get("set-cookie");
      if (setCookies) {
        const match = setCookies.match(/h2ogpte\.session=([^;]+)/);
        if (match) {
          newSession = match[1];
        }
      }
      
      if (!newSession) {
        console.log("获取新凭证失败: 无法获取 session");
        return null;
      }
      
      // 提取 csrf_token 和用户信息
      const html = await response.text();
      const startMarker = "data-conf='";
      const start = html.indexOf(startMarker);
      if (start >= 0) {
        const configStart = start + startMarker.length;
        const end = html.indexOf("'", configStart);
        if (end > configStart) {
          const configJson = html.substring(configStart, end);
          try {
            const configData = JSON.parse(configJson);
            const newCsrf = configData.csrf_token || "";
            const newUserId = configData.user_id || "";
            const newUsername = configData.username || "";
            
            await this.saveCredential(newSession, newCsrf, newUserId, newUsername);
            Config.updateCredentials(newSession, newCsrf);
            console.log(`获取新凭证成功: ${newUsername}`);
            return this.credential;
          } catch (_e) {
            // JSON 解析失败
          }
        }
      }
      
      console.log("获取新凭证失败: 无法解析配置");
      return null;
    } catch (e) {
      console.log(`获取新凭证失败: ${e}`);
      return null;
    }
  }
  
  getSession(): string {
    return this.credential?.session || "";
  }
  
  getCsrfToken(): string {
    return this.credential?.csrf_token || "";
  }
}

const credentialStore = new CredentialStore();

// ============ H2OGPTE 客户端 ============

class H2OGPTEClient {
  private baseUrl: string;
  private rpcDbEndpoint: string;
  private wsEndpoint: string;
  private refreshing: boolean = false;
  
  constructor() {
    this.baseUrl = Config.H2OGPTE_BASE_URL;
    this.rpcDbEndpoint = `${this.baseUrl}/rpc/db`;
    this.wsEndpoint = this.baseUrl.replace("https://", "wss://") + "/ws";
  }
  
  private getHeaders(): Record<string, string> {
    return Config.getHeaders();
  }
  
  private getCookieHeader(): string {
    const cookies = Config.getCookies();
    return Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  }
  
  private async ensureCredentials(): Promise<boolean> {
    if (Config.getSession() && Config.getCsrfToken()) {
      return true;
    }
    
    if (Config.IS_GUEST) {
      return await this.refreshCredentials();
    }
    
    console.log("非 Guest 模式，请配置账号凭证");
    return false;
  }
  
  private async refreshCredentials(forceNew: boolean = false): Promise<boolean> {
    if (this.refreshing) {
      // 等待刷新完成
      await new Promise(resolve => setTimeout(resolve, 100));
      return Config.getSession() !== "" && Config.getCsrfToken() !== "";
    }
    
    this.refreshing = true;
    
    try {
      if (!forceNew) {
        const cred = await credentialStore.renewSession();
        if (cred) {
          return true;
        }
      }
      
      if (Config.IS_GUEST) {
        const cred = await credentialStore.refreshCredential();
        if (cred) {
          return true;
        }
      }
      
      return false;
    } finally {
      this.refreshing = false;
    }
  }
  
  private async rpcDb(method: string, ...args: unknown[]): Promise<unknown> {
    await this.ensureCredentials();
    
    const payload = JSON.stringify([method, ...args]);
    const headers = {
      ...this.getHeaders(),
      "cookie": this.getCookieHeader()
    };
    
    let response = await fetch(this.rpcDbEndpoint, {
      method: "POST",
      headers,
      body: payload
    });
    
    if (response.status === 401 && Config.IS_GUEST) {
      console.log("检测到 401 Unauthorized，正在刷新凭证...");
      if (await this.refreshCredentials()) {
        const newHeaders = {
          ...this.getHeaders(),
          "cookie": this.getCookieHeader()
        };
        response = await fetch(this.rpcDbEndpoint, {
          method: "POST",
          headers: newHeaders,
          body: payload
        });
      }
    }
    
    if (!response.ok) {
      throw new Error(`RPC 请求失败: ${response.status}`);
    }
    
    return await response.json();
  }
  
  async listModels(): Promise<Model[]> {
    return [
      { id: "auto", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "claude-sonnet-4-5-20250929", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "claude-3-7-sonnet", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "claude-3-5-sonnet", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "deepseek-ai/DeepSeek-R1", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "deepseek-ai/DeepSeek-V3", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "gpt-4.1", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "gpt-4o", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "gpt-5", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "gemini-2.5-pro", object: "model", created: Date.now(), owned_by: "h2ogpte" },
      { id: "gemini-2.5-flash", object: "model", created: Date.now(), owned_by: "h2ogpte" },
    ];
  }
  
  async createChatSession(workspace?: string): Promise<string> {
    try {
      const targetWorkspace = workspace || Config.getWorkspaceId();
      const result = await this.rpcDb("create_chat_session", null, targetWorkspace);
      if (typeof result === "object" && result !== null && "id" in result) {
        return (result as { id: string }).id;
      } else if (typeof result === "string") {
        return result;
      }
      return crypto.randomUUID();
    } catch (e) {
      console.log(`创建聊天会话失败: ${e}`);
      return crypto.randomUUID();
    }
  }
  
  async deleteChatSession(sessionId: string): Promise<boolean> {
    try {
      await this.ensureCredentials();
      
      const payload = JSON.stringify([
        "q:crawl_quick.DeleteChatSessionsJob",
        {
          name: "Deleting Chat Sessions",
          chat_session_ids: [sessionId]
        }
      ]);
      
      const headers = {
        ...this.getHeaders(),
        "cookie": this.getCookieHeader()
      };
      
      await fetch(`${this.baseUrl}/rpc/job`, {
        method: "POST",
        headers,
        body: payload
      });
      
      return true;
    } catch (e) {
      console.log(`删除聊天会话失败: ${e}`);
      return false;
    }
  }
  
  async sendMessage(
    message: string,
    chatId?: string,
    model?: string,
    systemPrompt?: string,
    temperature: number = 0.7,
    _maxTokens?: number
  ): Promise<string> {
    if (!chatId) {
      chatId = await this.createChatSession();
    }
    
    let fullResponse = "";
    for await (const chunk of this.wsChat(chatId, message, model, systemPrompt, temperature)) {
      fullResponse += chunk;
    }
    
    return fullResponse;
  }
  
  async *sendMessageStream(
    message: string,
    chatId?: string,
    model?: string,
    systemPrompt?: string,
    temperature: number = 0.7,
    _maxTokens?: number
  ): AsyncGenerator<string, void, unknown> {
    if (!chatId) {
      chatId = await this.createChatSession();
    }
    
    for await (const chunk of this.wsChat(chatId, message, model, systemPrompt, temperature)) {
      yield chunk;
    }
  }
  
  private async *wsChat(
    sessionId: string,
    message: string,
    llm?: string,
    systemPrompt?: string,
    temperature: number = 0.7
  ): AsyncGenerator<string, void, unknown> {
    await this.ensureCredentials();
    
    const wsUrl = `${this.wsEndpoint}?currentSessionID=${sessionId}`;
    
    const llmArgs = {
      enable_vision: "auto",
      visible_vision_models: ["auto"],
      use_agent: false,
      cost_controls: {
        max_cost: 0.05,
        willingness_to_pay: 1,
        willingness_to_wait: 60
      },
      remove_non_private: false,
      temperature: Math.min(Math.max(temperature, 0), 1.0)
    };
    
    const ragConfig = {
      rag_type: "auto",
      hyde_no_rag_llm_prompt_extension: null,
      num_neighbor_chunks_to_include: 1,
      meta_data_to_include: {
        name: true,
        page: true,
        text: true,
        captions: true
      }
    };
    
    const chatRequest: Record<string, unknown> = {
      t: "cq",
      mode: "s",
      session_id: sessionId,
      correlation_id: crypto.randomUUID(),
      body: message,
      llm: llm || "auto",
      llm_args: JSON.stringify(llmArgs),
      self_reflection_config: "null",
      rag_config: JSON.stringify(ragConfig),
      include_chat_history: "auto",
      tags: [],
      prompt_template_id: Config.getPromptTemplateId() || null
    };
    
    if (systemPrompt) {
      chatRequest.system_prompt = systemPrompt;
    }
    
    try {
      const socket = new WebSocket(wsUrl, {
        headers: {
          "Cookie": this.getCookieHeader(),
          "Origin": this.baseUrl,
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      } as unknown as string[]);
      
      let collectedResponse = "";
      let resolveNext: ((value: IteratorResult<string, void>) => void) | null = null;
      let rejectNext: ((reason: unknown) => void) | null = null;
      const messageQueue: string[] = [];
      let done = false;
      let error: Error | null = null;
      
      socket.onopen = () => {
        socket.send(JSON.stringify(chatRequest));
      };
      
      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const msgType = data.t || "";
          
          if (msgType === "cp") {
            const content = data.body || "";
            if (content) {
              collectedResponse += content;
              if (resolveNext) {
                resolveNext({ value: content, done: false });
                resolveNext = null;
                rejectNext = null;
              } else {
                messageQueue.push(content);
              }
            }
          } else if (msgType === "cr") {
            const content = data.body || "";
            if (!collectedResponse && content) {
              if (resolveNext) {
                resolveNext({ value: content, done: false });
                resolveNext = null;
                rejectNext = null;
              } else {
                messageQueue.push(content);
              }
            }
          } else if (msgType === "ca" || msgType === "cd") {
            done = true;
            socket.close();
            if (resolveNext) {
              resolveNext({ value: undefined, done: true });
              resolveNext = null;
              rejectNext = null;
            }
          } else if (msgType === "ce") {
            const errorMsg = data.error || data.body || "Unknown error";
            error = new Error(`聊天错误: ${errorMsg}`);
            done = true;
            socket.close();
            if (rejectNext) {
              rejectNext(error);
              resolveNext = null;
              rejectNext = null;
            }
          }
        } catch (e) {
          console.log(`解析 WebSocket 消息失败: ${e}`);
        }
      };
      
      socket.onerror = (e) => {
        error = new Error(`WebSocket 错误: ${e}`);
        done = true;
        if (rejectNext) {
          rejectNext(error);
          resolveNext = null;
          rejectNext = null;
        }
      };
      
      socket.onclose = () => {
        done = true;
        if (resolveNext) {
          resolveNext({ value: undefined, done: true });
          resolveNext = null;
          rejectNext = null;
        }
      };
      
      // 等待连接打开
      await new Promise<void>((resolve, reject) => {
        const originalOnOpen = socket.onopen;
        const originalOnError = socket.onerror;
        
        socket.onopen = (e) => {
          if (originalOnOpen) originalOnOpen.call(socket, e);
          resolve();
        };
        
        socket.onerror = (e) => {
          if (originalOnError) originalOnError.call(socket, e as Event);
          reject(new Error("WebSocket 连接失败"));
        };
        
        // 超时处理
        setTimeout(() => reject(new Error("WebSocket 连接超时")), 30000);
      });
      
      // 生成消息
      while (!done || messageQueue.length > 0) {
        if (messageQueue.length > 0) {
          yield messageQueue.shift()!;
        } else if (!done) {
          const result = await new Promise<IteratorResult<string, void>>((resolve, reject) => {
            resolveNext = resolve;
            rejectNext = reject;
            
            // 超时处理
            setTimeout(() => {
              if (resolveNext === resolve) {
                resolve({ value: undefined, done: true });
                resolveNext = null;
                rejectNext = null;
              }
            }, 120000);
          });
          
          if (result.done) break;
          if (result.value) yield result.value;
        }
      }
      
      if (error) {
        throw error;
      }
      
    } catch (e) {
      console.log(`WebSocket 聊天失败: ${e}`);
      throw e;
    }
  }
}

const h2ogpteClient = new H2OGPTEClient();

// ============ 会话池管理 ============

class SessionManager {
  private client: H2OGPTEClient;
  private targetPoolSize: number;
  private queue: string[] = [];
  private cleanupQueue: string[] = [];
  private running: boolean = false;
  private maintainerInterval: number | null = null;
  private cleanupInterval: number | null = null;
  
  constructor(client: H2OGPTEClient, poolSize: number = 5) {
    this.client = client;
    this.targetPoolSize = poolSize;
  }
  
  async start(): Promise<void> {
    this.running = true;
    
    // 预热会话池
    console.log("🔄 预热会话池...");
    await this.replenishPool();
    
    // 启动后台维护任务
    this.maintainerInterval = setInterval(() => this.poolMaintainer(), 5000);
    this.cleanupInterval = setInterval(() => this.cleanupWorker(), 1000);
    
    console.log(`✓ 会话池启动完成，当前大小: ${this.queue.length}`);
  }
  
  async stop(): Promise<void> {
    this.running = false;
    
    if (this.maintainerInterval) {
      clearInterval(this.maintainerInterval);
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    // 清理剩余会话
    while (this.queue.length > 0) {
      const sessionId = this.queue.shift();
      if (sessionId) {
        await this.client.deleteChatSession(sessionId);
      }
    }
    
    console.log("✓ 会话池已停止");
  }
  
  async getSession(): Promise<string> {
    if (this.queue.length === 0) {
      console.log("⚠ 会话池为空，正在创建临时会话...");
      return await this.client.createChatSession();
    }
    
    const sessionId = this.queue.shift()!;
    console.log(`📤 从池中获取会话: ${sessionId} (剩余: ${this.queue.length})`);
    
    // 触发补充
    if (this.queue.length < this.targetPoolSize) {
      this.replenishPool().catch(console.error);
    }
    
    return sessionId;
  }
  
  async recycleSession(sessionId: string): Promise<void> {
    this.cleanupQueue.push(sessionId);
    console.log(`♻️ 会话已加入清理队列: ${sessionId}`);
  }
  
  private async replenishPool(): Promise<void> {
    const needed = this.targetPoolSize - this.queue.length;
    if (needed <= 0) return;
    
    console.log(`📥 补充会话池 (需要: ${needed})...`);
    
    const promises: Promise<string>[] = [];
    for (let i = 0; i < needed; i++) {
      promises.push(this.client.createChatSession());
    }
    
    const results = await Promise.allSettled(promises);
    
    for (const result of results) {
      if (result.status === "fulfilled") {
        this.queue.push(result.value);
      } else {
        console.log(`❌ 创建会话失败: ${result.reason}`);
      }
    }
    
    console.log(`✓ 会话池补充完成，当前大小: ${this.queue.length}`);
  }
  
  private async poolMaintainer(): Promise<void> {
    if (!this.running) return;
    
    if (this.queue.length < this.targetPoolSize) {
      await this.replenishPool();
    }
  }
  
  private async cleanupWorker(): Promise<void> {
    if (!this.running) return;
    
    while (this.cleanupQueue.length > 0) {
      const sessionId = this.cleanupQueue.shift();
      if (sessionId) {
        try {
          await this.client.deleteChatSession(sessionId);
          console.log(`🗑️ 会话清理完成: ${sessionId}`);
        } catch (e) {
          console.log(`❌ 会话清理失败: ${sessionId} - ${e}`);
        }
      }
    }
  }
}

const sessionManager = new SessionManager(h2ogpteClient, 5);

// ============ HTTP 路由处理 ============

function generateCompletionId(): string {
  return `chatcmpl-${crypto.randomUUID().replace(/-/g, "").substring(0, 24)}`;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  };
}

function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders()
    }
  });
}

function errorResponse(message: string, status: number = 500): Response {
  return jsonResponse({ error: { message, type: "error", code: status } }, status);
}

async function handleRoot(_req: Request): Promise<Response> {
  return jsonResponse({
    message: "H2OGPTE to OpenAI API",
    docs: "/docs",
    endpoints: ["/v1/models", "/v1/chat/completions"]
  });
}

async function handleListModels(req: Request): Promise<Response> {
  const auth = req.headers.get("Authorization");
  if (!Config.verifyApiKey(auth)) {
    return errorResponse("Invalid API Key", 401);
  }
  
  try {
    const models = await h2ogpteClient.listModels();
    return jsonResponse({
      object: "list",
      data: models
    });
  } catch (e) {
    return errorResponse(`获取模型列表失败: ${e}`, 500);
  }
}

async function handleGetModel(req: Request, modelId: string): Promise<Response> {
  const auth = req.headers.get("Authorization");
  if (!Config.verifyApiKey(auth)) {
    return errorResponse("Invalid API Key", 401);
  }
  
  return jsonResponse({
    id: modelId,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "h2ogpte"
  });
}

async function handleChatCompletions(req: Request): Promise<Response> {
  const auth = req.headers.get("Authorization");
  if (!Config.verifyApiKey(auth)) {
    return errorResponse("Invalid API Key", 401);
  }
  
  try {
    const body: ChatCompletionRequest = await req.json();
    
    // 提取系统提示词并构建完整的对话上下文
    let systemPrompt: string | undefined;
    const conversationParts: string[] = [];
    
    for (const msg of body.messages) {
      if (msg.role === "system") {
        systemPrompt = msg.content;
      } else if (msg.role === "user") {
        conversationParts.push(`User: ${msg.content}`);
      } else if (msg.role === "assistant") {
        conversationParts.push(`Assistant: ${msg.content}`);
      }
    }
    
    // 将对话历史拼接成完整的消息
    let userMessage: string;
    if (conversationParts.length === 1) {
      userMessage = body.messages[body.messages.length - 1]?.content || "";
    } else {
      userMessage = conversationParts.join("\n");
    }
    
    if (!userMessage && body.messages.length > 0) {
      userMessage = body.messages[body.messages.length - 1].content;
    }
    
    // 从会话池获取聊天会话
    const chatId = await sessionManager.getSession();
    
    if (body.stream) {
      // 流式响应
      const stream = streamChatCompletion(
        chatId,
        userMessage,
        body.model,
        systemPrompt,
        body.temperature || 0.7,
        body.max_tokens
      );
      
      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
          ...corsHeaders()
        }
      });
    } else {
      // 非流式响应
      const responseContent = await h2ogpteClient.sendMessage(
        userMessage,
        chatId,
        body.model,
        systemPrompt,
        body.temperature || 0.7,
        body.max_tokens
      );
      
      // 回收聊天会话
      await sessionManager.recycleSession(chatId);
      
      const completionId = generateCompletionId();
      
      return jsonResponse({
        id: completionId,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: body.model,
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: responseContent
            },
            finish_reason: "stop"
          }
        ],
        usage: {
          prompt_tokens: Math.floor(userMessage.length / 4),
          completion_tokens: Math.floor(responseContent.length / 4),
          total_tokens: Math.floor((userMessage.length + responseContent.length) / 4)
        }
      });
    }
  } catch (e) {
    return errorResponse(`聊天补全失败: ${e}`, 500);
  }
}

function streamChatCompletion(
  chatId: string,
  message: string,
  model: string,
  systemPrompt: string | undefined,
  temperature: number,
  maxTokens: number | undefined
): ReadableStream<Uint8Array> {
  const completionId = generateCompletionId();
  const created = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  
  return new ReadableStream({
    async start(controller) {
      try {
        // 发送角色信息
        const roleChunk = {
          id: completionId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            {
              index: 0,
              delta: { role: "assistant" },
              finish_reason: null
            }
          ]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(roleChunk)}\n\n`));
        
        // 流式获取内容
        for await (const contentChunk of h2ogpteClient.sendMessageStream(
          message,
          chatId,
          model,
          systemPrompt,
          temperature,
          maxTokens
        )) {
          const chunk = {
            id: completionId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [
              {
                index: 0,
                delta: { content: contentChunk },
                finish_reason: null
              }
            ]
          };
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
        }
        
        // 发送结束信号
        const finalChunk = {
          id: completionId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: "stop"
            }
          ]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        
        // 回收聊天会话
        await sessionManager.recycleSession(chatId);
        
      } catch (e) {
        // 发送错误信息
        const errorChunk = {
          id: completionId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            {
              index: 0,
              delta: { content: `[Error: ${e}]` },
              finish_reason: null
            }
          ]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(errorChunk)}\n\n`));
        
        const finalChunk = {
          id: completionId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: "stop"
            }
          ]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      } finally {
        controller.close();
      }
    }
  });
}

// ============ 主处理函数 ============

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;
  
  // CORS 预检请求
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders()
    });
  }
  
  // 路由
  if (path === "/" && method === "GET") {
    return handleRoot(req);
  }
  
  if (path === "/v1/models" && method === "GET") {
    return handleListModels(req);
  }
  
  if (path.startsWith("/v1/models/") && method === "GET") {
    const modelId = path.substring("/v1/models/".length);
    return handleGetModel(req, modelId);
  }
  
  if (path === "/v1/chat/completions" && method === "POST") {
    return handleChatCompletions(req);
  }
  
  return errorResponse("Not Found", 404);
}

// ============ 初始化和启动 ============

let initialized = false;

async function initialize(): Promise<void> {
  if (initialized) return;
  
  console.log("🚀 H2OGPTE to OpenAI API 服务启动");
  console.log(`🔗 目标服务: ${Config.H2OGPTE_BASE_URL}`);
  console.log(`👤 运行模式: ${Config.IS_GUEST ? "Guest (自动凭证)" : "登录用户"}`);
  console.log(`🔑 API Keys 数量: ${Config.API_KEYS.length}`);
  
  if (!Config.IS_GUEST && Config.ACCOUNTS.length > 0) {
    console.log(`📦 已配置账号数量: ${Config.ACCOUNTS.length}`);
    console.log(`🔄 账号选择模式: ${Config.ACCOUNT_MODE}`);
  }
  
  // Guest 模式下初始化凭证
  if (Config.IS_GUEST) {
    console.log("🔑 正在初始化 Guest 凭证...");
    const cred = await credentialStore.refreshCredential();
    if (cred) {
      console.log(`✓ 凭证初始化成功: ${cred.username}`);
    } else {
      console.log("⚠ 凭证初始化失败，将在首次请求时重试");
    }
  }
  
  // 启动会话池
  console.log("🔄 启动会话池管理器...");
  await sessionManager.start();
  
  initialized = true;
}

// Deno Deploy 入口
Deno.serve(async (req: Request) => {
  await initialize();
  return handler(req);
});
