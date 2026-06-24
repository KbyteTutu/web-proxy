import crypto from "node:crypto";

// UPSTREAM_SOCKS5 accepts socks5://host:port or socks5://user:pass@host:port
export const config = {
  password: process.env.PROXY_PASSWORD || "tukechao",
  port: parseInt(process.env.PROXY_PORT || "8080", 10),
  host: process.env.PROXY_HOST || "0.0.0.0",
  upstreamSocks5: process.env.UPSTREAM_SOCKS5 || "",
  blockLocal: process.env.PROXY_BLOCK_LOCAL !== "false",
  sessionSecret:
    process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  sessionTtlMs: parseInt(
    process.env.SESSION_TTL_MS || String(12 * 3600 * 1000),
    10
  ),
  tlsCertPath: process.env.TLS_CERT_PATH || "",
  tlsKeyPath: process.env.TLS_KEY_PATH || "",
  blockDomains: (process.env.PROXY_BLOCK_DOMAINS || "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean),
};

if (config.password === "tukechao") {
  console.warn(
    "[web-proxy] WARNING: default password 'tukechao' in use. Set PROXY_PASSWORD."
  );
}
