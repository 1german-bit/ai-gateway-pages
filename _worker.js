/**
 * AI API 网关 Worker —— 隐蔽统一入口 + 多上游路由 + Bearer 鉴权 + SSE 流式透传
 *
 * 设计目标
 *  1. 隐蔽性：入口路径不含厂商名（/api/v1、/v1beta），根路径伪装为普通服务状态；
 *     统一错误格式，不暴露 Worker / 上游厂商特征；清理 CF 与代理特征头。
 *  2. 可靠性：常数时间鉴权（防时序攻击）、上游错误透传、流式透传、每 IP 限流、
 *     上游不可用时返回 502 统一 JSON；真实 API Key 只存 Cloudflare Secrets，代码零硬编码。
 *  3. 可扩展：新增厂商只需在 ROUTES 表中加一行。
 *
 * 部署后客户端配置：
 *  - OpenRouter（OpenAI 兼容）：base_url = https://你的域名/api/v1 ，API Key = 你的访问令牌
 *  - Gemini（原生）：           base_url = https://你的域名/v1beta ，API Key = 你的访问令牌
 */

const ROUTES = [
  // 前缀匹配顺序即优先级，先写更长的前缀
  // host 可被同名 env 变量覆盖（测试/自定义镜像时使用）
  { prefix: "/api/v1/", host: "https://openrouter.ai", hostEnv: "OPENROUTER_BASE",
    keyEnv: "OPENROUTER_KEY", auth: "bearer" },
  { prefix: "/v1beta/", host: "https://generativelanguage.googleapis.com", hostEnv: "GEMINI_BASE",
    keyEnv: "GEMINI_KEY", auth: "x-goog-api-key" },
];

// 简单滥用防护（内存滑动窗口，单边缘近似；免费版多边缘不共享计数，够个人使用）
const RATE_LIMIT = { windowMs: 60_000, max: 120 }; // 每 IP 每分钟最多 120 次请求

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, x-goog-api-key",
  "Access-Control-Max-Age": "86400",
};

// 请求/响应中清理的特征头（防暴露链路与代理痕迹）
const STRIP_HEADERS = [
  "cf-connecting-ip", "cf-ray", "cf-visitor", "cf-ipcountry", "cf-ipcontinent",
  "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "true-client-ip",
  "forwarded", "connection", "accept-encoding",
];

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
  });
}

/** 常数时间字符串比较，防时序攻击 */
function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------- 限流 ----------
const buckets = new Map();

function rateLimit(ip) {
  const now = Date.now();
  // 防止 Map 无限膨胀：超过阈值时清一次过期桶
  if (buckets.size > 10_000) {
    for (const [k, b] of buckets) {
      if (now > b.reset) buckets.delete(k);
    }
  }
  const b = buckets.get(ip);
  if (!b || now > b.reset) {
    buckets.set(ip, { count: 1, reset: now + RATE_LIMIT.windowMs });
    return true;
  }
  b.count++;
  return b.count <= RATE_LIMIT.max;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;

    // CORS 预检
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // 根路径伪装：普通服务状态，不暴露任何 AI 特征
    if (url.pathname === "/" || url.pathname === "/health") {
      return json(200, { status: "ok", ts: Date.now() });
    }

    // 鉴权：客户端必须带 Authorization: Bearer <访问令牌>
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!env.ACCESS_TOKEN || !timingSafeEqualStr(token, env.ACCESS_TOKEN)) {
      return json(401, { error: { message: "unauthorized" } });
    }

    // 限流
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!rateLimit(ip)) {
      return json(429, { error: { message: "too many requests" } });
    }

    // 路由
    const route = ROUTES.find((r) => url.pathname.startsWith(r.prefix));
    if (!route) {
      return json(404, { error: { message: "not found" } });
    }

    const apiKey = env[route.keyEnv];
    if (!apiKey) {
      return json(503, { error: { message: "upstream not configured" } });
    }

    // Gemini 客户端可能带 ?key= 参数：替换为真实 Key
    if (route.auth === "x-goog-api-key" && url.searchParams.has("key")) {
      url.searchParams.set("key", apiKey);
    }

    const host = env[route.hostEnv] || route.host;
    const target = host + url.pathname + url.search;

    // 转发请求头：复制客户端头，去掉 Host 与特征头
    const headers = new Headers(request.headers);
    headers.delete("host");
    for (const h of STRIP_HEADERS) headers.delete(h);

    // 注入真实 API Key（覆盖客户端传入的任何 Authorization）
    headers.delete("Authorization");
    if (route.auth === "bearer") {
      headers.set("Authorization", "Bearer " + apiKey);
    } else {
      headers.set("x-goog-api-key", apiKey);
    }

    let upstream;
    try {
      upstream = await fetch(target, {
        method,
        headers,
        body: ["GET", "HEAD"].includes(method) ? undefined : request.body,
        redirect: "manual",
        // Node/undici 发送流式 body 时必需；Cloudflare Workers 会忽略该字段，无副作用
        duplex: "half",
      });
    } catch (e) {
      return json(502, { error: { message: "upstream unreachable" } });
    }

    // 透传上游响应（body 为流式，SSE 自然透传）
    const respHeaders = new Headers(upstream.headers);
    respHeaders.delete("set-cookie");
    for (const h of STRIP_HEADERS) respHeaders.delete(h);
    for (const [k, v] of Object.entries(CORS_HEADERS)) respHeaders.set(k, v);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: respHeaders,
    });
  },
};
