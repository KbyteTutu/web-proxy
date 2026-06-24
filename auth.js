import crypto from "node:crypto";
import { config } from "./config.js";

export const COOKIE_NAME = "wp_session";
export const CSRF_COOKIE = "wp_csrf";

function sign(value) {
  const h = crypto
    .createHmac("sha256", config.sessionSecret)
    .update(value)
    .digest("base64url");
  return `${value}.${h}`;
}

function verify(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf(".");
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const expected = sign(value);
  const a = Buffer.from(signed);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const exp = parseInt(value, 10);
  if (!Number.isFinite(exp) || Date.now() > exp) return null;
  return value;
}

export function isAuthed(req) {
  return verify(req.cookies?.[COOKIE_NAME]) !== null;
}

export function checkPassword(input) {
  const a = Buffer.from(String(input ?? ""));
  const b = Buffer.from(config.password);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function sessionCookieValue() {
  return sign(String(Date.now() + config.sessionTtlMs));
}

export function verifyToken(token) {
  return verify(token) !== null;
}

export function csrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

export function verifyCsrf(cookieValue, formValue) {
  if (!cookieValue || !formValue) return false;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(cookieValue),
      Buffer.from(formValue)
    );
  } catch {
    return false;
  }
}
