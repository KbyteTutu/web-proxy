import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import express from "express";
import cookieParser from "cookie-parser";
import { createBareServer } from "@tomphttp/bare-server-node";
import { uvPath } from "@titaniumnetwork-dev/ultraviolet";
import { SocksProxyAgent } from "socks-proxy-agent";
import { RateLimiterMemory } from "rate-limiter-flexible";
import { config } from "./config.js";
import {
  COOKIE_NAME,
  isAuthed,
  checkPassword,
  sessionCookieValue,
  verifyToken,
  csrfToken,
  verifyCsrf,
} from "./auth.js";

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const bareMuxPath = dirname(require.resolve("@mercuryworkshop/bare-mux"));
const transportPath = join(
  dirname(require.resolve("@mercuryworkshop/bare-as-module3")),
  "..",
  "dist"
);

const bareInit = {
  blockLocal: config.blockLocal,
  logErrors: true,
  maintainer: { email: "admin@localhost", website: "" },
};

if (config.upstreamSocks5) {
  const agent = new SocksProxyAgent(config.upstreamSocks5);
  bareInit.httpAgent = agent;
  bareInit.httpsAgent = agent;
  console.log(`[web-proxy] egress via upstream SOCKS5: ${config.upstreamSocks5}`);
} else {
  console.log("[web-proxy] egress via direct server connection");
}

const bare = createBareServer("/bare/", bareInit);

const app = express();
app.disable("x-powered-by");
app.use(cookieParser());

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const ip = req.ip || req.socket.remoteAddress || "-";
    const ms = Date.now() - start;
    console.log(
      `[web-proxy] ${new Date().toISOString()} ${ip} "${req.method} ${req.originalUrl}" ${res.statusCode} ${ms}ms`
    );
  });
  next();
});

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'self'; img-src * data:"
  );
  if (config.tlsCertPath) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }
  next();
});

// Rate limiter: 5 login attempts per minute per IP
const loginLimiter = new RateLimiterMemory({
  points: 5,
  duration: 60,
});

function renderLogin(res, error) {
  const token = csrfToken();
  res.type("html").send(loginPage(error, token));
}

async function rateLimitLogin(req, res, next) {
  try {
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    await loginLimiter.consume(ip);
    next();
  } catch {
    res.status(429);
    renderLogin(res, "请求过于频繁，请稍后再试");
  }
}

app.get("/proxy-token", (req, res) => {
  if (!isAuthed(req)) return res.status(401).end();
  res.json({ token: sessionCookieValue() });
});

app.get("/login", (req, res) => {
  renderLogin(res, "");
});

app.post("/login", express.urlencoded({ extended: false, limit: "1kb" }), rateLimitLogin, (req, res) => {
  if (!verifyCsrf(req.body._csrf)) {
    res.status(403);
    return renderLogin(res, "请求无效，请刷新重试");
  }
  if (checkPassword(req.body.password)) {
    res.cookie(COOKIE_NAME, sessionCookieValue(), {
      httpOnly: true,
      sameSite: "lax",
      maxAge: config.sessionTtlMs,
    });
    res.redirect("/");
  } else {
    res.status(401);
    renderLogin(res, "密码错误");
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect("/login");
});

app.use((req, res, next) => {
  if (isAuthed(req)) return next();
  res.redirect("/login");
});

app.use(express.static(join(__dirname, "public")));
app.use("/uv/", express.static(uvPath));
app.use("/baremux/", express.static(bareMuxPath));
app.use("/transport/", express.static(transportPath));

const useTls = config.tlsCertPath && config.tlsKeyPath;
let tlsOptions;
if (useTls) {
  try {
    tlsOptions = {
      cert: readFileSync(config.tlsCertPath),
      key: readFileSync(config.tlsKeyPath),
    };
    console.log("[web-proxy] TLS enabled");
  } catch (err) {
    console.error("[web-proxy] failed to load TLS certificates:", err.message);
    process.exit(1);
  }
}
const httpServer = useTls ? createHttpsServer(tlsOptions) : createServer();
const TOKEN_PREFIX = /^\/wp\/([^/]+)(\/bare\/)/;

function stripToken(req) {
  const m = req.url.match(TOKEN_PREFIX);
  if (!m) return false;
  if (!verifyToken(m[1])) return false;
  req.url = req.url.slice(`/wp/${m[1]}`.length);
  return true;
}

const ALLOWED_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

function validBareTarget(req) {
  const target = req.headers["x-bare-url"];
  if (!target) return true;
  try {
    return ALLOWED_PROTOCOLS.has(new URL(target).protocol);
  } catch {
    return false;
  }
}

function blockedBareTarget(req) {
  if (!config.blockDomains.length) return false;
  const target = req.headers["x-bare-url"];
  if (!target) return false;
  try {
    const host = new URL(target).hostname.toLowerCase();
    return config.blockDomains.some(
      (d) => host === d || host.endsWith("." + d)
    );
  } catch {
    return false;
  }
}

httpServer.on("request", (req, res) => {
  if (req.url.startsWith("/wp/")) {
    if (
      stripToken(req) &&
      validBareTarget(req) &&
      !blockedBareTarget(req) &&
      bare.shouldRoute(req)
    )
      bare.routeRequest(req, res);
    else res.writeHead(401).end("Unauthorized");
  } else {
    app(req, res);
  }
});

httpServer.on("upgrade", (req, socket, head) => {
  if (
    req.url.startsWith("/wp/") &&
    stripToken(req) &&
    validBareTarget(req) &&
    !blockedBareTarget(req) &&
    bare.shouldRoute(req)
  ) {
    bare.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

httpServer.listen(config.port, config.host, () => {
  const proto = useTls ? "https" : "http";
  console.log(`[web-proxy] listening on ${proto}://${config.host}:${config.port}`);
});

function loginPage(error, token = "") {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0}
.card{background:#1e293b;padding:2rem;border-radius:12px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
h1{margin:0 0 1.25rem;font-size:1.25rem}
input{width:100%;padding:.7rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:1rem}
button{width:100%;margin-top:1rem;padding:.7rem;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer}
button:hover{background:#2563eb}.err{color:#f87171;margin-top:.75rem;font-size:.9rem;text-align:center}
</style></head><body><form class="card" method="post" action="/login">
<h1>Web 代理 · 登录</h1>
<input type="password" name="password" placeholder="访问密码" autofocus required>
${token ? `<input type="hidden" name="_csrf" value="${token}">` : ""}
<button type="submit">进入</button>
${error ? `<div class="err">${error}</div>` : ""}
</form></body></html>`;
}
