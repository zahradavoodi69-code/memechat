"use strict";

/* MemeChat — ماژول افزودنی «فراموشی رمز عبور» (سمت سرور)
 *
 * اصول امنیتی و معماری:
 *   1. رمز عبور در میمچت با scrypt یکطرفه (salt تصادفی ۱۶ بایتی + ۶۴ بایت خروجی)
 *      هش میشود؛ هیچ رمز خامی ذخیره یا برگردانده نمیشود.
 *   2. بازیابی بدون اثبات مالکیت ایمیل (کد ۶ رقمی یکبارمصرف با انقضای ۱۰ دقیقه)
 *      ممنوع است: اگر سرویس ایمیل پیکربندی نشده باشد، با ۵۰۳ fail-closed میشود.
 *   3. جدول اختصاصی `mimchat_password_resets` + برچسبهای HMAC جداگانه
 *      (`pw_reset_otp` و `pw_reset_token`) تا توکن ثبتنام قابل استفاده نباشد.
 *   4. جلوگیری از افشای وجود حساب (anti-enumeration): محدودیت نرخ و پیام
 *      پاسخ برای ایمیل موجود و ناموجود یکسان است.
 *   5. ابطال اتمیک یکبارمصرف (PATCH شرطی `used_at=is.null` / `reset_used_at=is.null`)
 *      برای جلوگیری از race و استفادهٔ مجدد.
 *   6. پس از تغییر رمز: `session_epoch` کاربر +۱ و `mimchat_sessions` باطل
 *      (`revoked: true`) میشوند تا همهٔ نشستهای قبلی بسته شوند.
 *   7. صفر DELETE / DROP / TRUNCATE / RESET؛ صفر ورسل؛ صفر راز ثابت.
 */

const crypto = require("node:crypto");

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CODE_RE = /^\d{6}$/;
const RESET_TOKEN_RE = /^[0-9a-f]{64}$/;

const OTP_TTL_MS = 10 * 60 * 1000;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const RESEND_COOLDOWN_SEC = 60;
const MIN_PASSWORD_LEN = 6;
const MAX_PASSWORD_LEN = 64;
const MAX_ATTEMPTS = 5;

const FORGOT_ACTIONS = Object.freeze([
  "forgot-request",
  "forgot-verify",
  "forgot-reset",
]);

const API_SECURITY_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
});

function normalizeEmail(raw) {
  return String(raw || "").trim().toLowerCase();
}

function escapePostgrestLike(s) {
  return String(s || "").replace(/[\\%_]/g, "\\$&");
}

function generateSixDigitCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, 64);
  return {
    saltHex: salt.toString("hex"),
    hashHex: derived.toString("hex"),
  };
}

function verifyPassword(password, storedHashHex, saltHex) {
  if (!storedHashHex || !saltHex) return false;
  const { hashHex } = hashPassword(password, saltHex);
  return safeEqualHex(hashHex, storedHashHex);
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !a.length || a.length !== b.length) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

function defaultGetHmacSecret() {
  const s = (process.env.OTP_HMAC_SECRET || process.env.SESSION_SECRET || "").trim();
  if (!s || s.length < 16) {
    const err = new Error("SERVER_CRYPTO_NOT_CONFIGURED");
    err.code = "SERVER_CRYPTO_NOT_CONFIGURED";
    throw err;
  }
  return s;
}

function defaultHmacHex(purpose, value) {
  return crypto
    .createHmac("sha256", defaultGetHmacSecret())
    .update(`${purpose}:${String(value || "")}`)
    .digest("hex");
}

function defaultSendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(API_SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }
  res.end(JSON.stringify(payload));
}

function defaultGetClientIp(req) {
  const xff = req && req.headers && req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return (req && req.socket && req.socket.remoteAddress) || "unknown";
}

function defaultSbConfig() {
  const url = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
  if (!url || !key) {
    const err = new Error("SUPABASE_NOT_CONFIGURED");
    err.code = "SUPABASE_NOT_CONFIGURED";
    throw err;
  }
  return { url, key };
}

async function defaultSbRequest(pathWithQuery, { method = "GET", body, prefer } = {}) {
  const m = String(method || "GET").toUpperCase();
  if (m === "DELETE") {
    throw new Error("NO_DELETE_ALLOWED");
  }
  const { url, key } = defaultSbConfig();
  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    Accept: "application/json",
  };
  if (prefer) headers.Prefer = prefer;
  let payload;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const resp = await fetch(`${url}/rest/v1/${pathWithQuery}`, {
    method: m,
    headers,
    body: payload,
  });
  const text = await resp.text();
  let parsed = null;
  if (text) {
    try { parsed = JSON.parse(text); } catch { parsed = text; }
  }
  if (!resp.ok) {
    const err = new Error(`SUPABASE_${resp.status}`);
    err.status = resp.status;
    err.detail = parsed;
    throw err;
  }
  return parsed;
}

function createDefaultRateLimiter({ sbRequest, hmacHex, now = () => Date.now() }) {
  return async function enforceRateLimit(rawKey, maxCount, windowSeconds) {
    const bucketKey = hmacHex("ratelimit", rawKey);
    const nowMs = now();
    const nowIso = new Date(nowMs).toISOString();
    const rows = await sbRequest(
      `mimchat_rate_limits?bucket_key=eq.${encodeURIComponent(bucketKey)}&select=*`
    );
    const existing = Array.isArray(rows) ? rows[0] : null;
    const nextExpiry = new Date(nowMs + windowSeconds * 1000).toISOString();

    if (!existing || new Date(existing.expires_at).getTime() <= nowMs) {
      await sbRequest("mimchat_rate_limits?on_conflict=bucket_key", {
        method: "POST",
        prefer: "resolution=merge-duplicates,return=minimal",
        body: {
          bucket_key: bucketKey,
          count: 1,
          window_start: nowIso,
          expires_at: nextExpiry,
        },
      });
      return { allowed: true, remaining: Math.max(0, maxCount - 1), retryAfter: 0 };
    }

    if (Number(existing.count || 0) >= maxCount) {
      const retryAfter = Math.max(
        1,
        Math.ceil((new Date(existing.expires_at).getTime() - nowMs) / 1000)
      );
      return { allowed: false, remaining: 0, retryAfter };
    }

    const nextCount = Number(existing.count || 0) + 1;
    await sbRequest(`mimchat_rate_limits?bucket_key=eq.${encodeURIComponent(bucketKey)}`, {
      method: "PATCH",
      prefer: "return=minimal",
      body: { count: nextCount },
    });
    return { allowed: true, remaining: Math.max(0, maxCount - nextCount), retryAfter: 0 };
  };
}

function buildPasswordResetEmail(sixDigitCode) {
  const html = `
  <div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;background:#14100c;color:#f5f0e6;padding:28px;border-radius:16px;max-width:480px;margin:0 auto;border:1px solid #3d3428;">
    <h2 style="color:#ffb347;margin:0 0 12px;">بازیابی رمز عبور میمچت</h2>
    <p style="font-size:14px;line-height:1.8;color:#d6cec2;">این کد یکبارمصرف برای تغییر رمز عبور حساب شماست:</p>
    <div style="background:#241c14;border:1px solid #ff8c00;border-radius:12px;padding:16px;text-align:center;font-size:28px;font-weight:bold;letter-spacing:8px;color:#ffb347;margin:18px 0;direction:ltr;">
      ${sixDigitCode}
    </div>
    <p style="font-size:12px;color:#a89f8f;line-height:1.7;">
      این کد تا <b>۱۰ دقیقه</b> معتبر است و فقط یک بار قابل استفاده است. اگر شما درخواست بازیابی نداده اید، این ایمیل را نادیده بگیرید؛ رمز شما تغییر نمیکند.
    </p>
  </div>`;

  const text = `کد بازیابی رمز عبور میمچت: ${sixDigitCode}\nاین کد تا ۱۰ دقیقه معتبر است و فقط یک بار قابل استفاده است. اگر شما درخواست نداده اید، آن را نادیده بگیرید.`;
  return { subject: "کد بازیابی رمز عبور میمچت", html, text };
}

function parseSender(value, fallbackName) {
  const raw = String(value || "").trim();
  const m = raw.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  if (m) return { name: m[1] || fallbackName, email: m[2].trim() };
  return { name: fallbackName, email: raw };
}

function isMailProviderConfigured(env = process.env) {
  const brevoReady = !!(env.BREVO_API_KEY || "").trim() && !!(env.BREVO_FROM_EMAIL || "").trim();
  const resendReady = !!(env.RESEND_API_KEY || "").trim() && !!(env.RESEND_FROM_EMAIL || "").trim();
  return brevoReady || resendReady;
}

async function sendResetEmailViaEnv(toEmail, sixDigitCode, env = process.env, fetchFn = globalThis.fetch) {
  const mail = buildPasswordResetEmail(sixDigitCode);
  const brevoKey = (env.BREVO_API_KEY || "").trim();
  const brevoFrom = (env.BREVO_FROM_EMAIL || "").trim();
  const resendKey = (env.RESEND_API_KEY || "").trim();
  const resendFrom = (env.RESEND_FROM_EMAIL || "").trim();

  if (brevoKey && brevoFrom) {
    const base = (env.BREVO_API_BASE || "https://api.brevo.com").replace(/\/+$/, "");
    const sender = parseSender(brevoFrom, "MemeChat");
    const resp = await fetchFn(`${base}/v3/smtp/email`, {
      method: "POST",
      headers: { "api-key": brevoKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        sender: { name: sender.name, email: sender.email },
        to: [{ email: toEmail }],
        subject: mail.subject,
        htmlContent: mail.html,
        textContent: mail.text,
      }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !(data.messageId || data.messageIds)) {
      const err = new Error("EMAIL_REJECTED");
      err.code = "EMAIL_REJECTED";
      err.httpStatus = resp.status;
      throw err;
    }
    return { messageId: String(data.messageId || (data.messageIds && data.messageIds[0]) || "brevo") };
  }

  if (resendKey && resendFrom) {
    const base = (env.RESEND_API_BASE || "https://api.resend.com").replace(/\/+$/, "");
    const resp = await fetchFn(`${base}/emails`, {
      method: "POST",
      headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: resendFrom,
        to: [toEmail],
        subject: mail.subject,
        html: mail.html,
        text: mail.text,
      }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.id) {
      const err = new Error("RESEND_REJECTED");
      err.code = "RESEND_REJECTED";
      err.httpStatus = resp.status;
      throw err;
    }
    return { messageId: String(data.id) };
  }

  const err = new Error("MAIL_NOT_CONFIGURED");
  err.code = "MAIL_NOT_CONFIGURED";
  throw err;
}

const GENERIC_REQUEST_MESSAGE =
  "اگر این ایمیل در سیستم ثبت شده باشد، کد ۶ رقمی بازیابی ارسال شد. لطفاً صندوق ورودی و هرزنامه را بررسی کنید.";

function createForgotPasswordHandler(deps = {}) {
  const sbRequest = deps.sbRequest || defaultSbRequest;
  const hmacHex = deps.hmacHex || defaultHmacHex;
  const hashPwd = deps.hashPassword || hashPassword;
  const sendJson = deps.sendJson || defaultSendJson;
  const getClientIp = deps.getClientIp || defaultGetClientIp;
  const now = deps.now || (() => Date.now());
  const enforceRateLimit =
    deps.enforceRateLimit || createDefaultRateLimiter({ sbRequest, hmacHex, now });

  const hasMailTransport = () => {
    if (typeof deps.isMailConfigured === "function") return Boolean(deps.isMailConfigured());
    return typeof deps.sendResetEmail === "function" || isMailProviderConfigured(deps.env || process.env);
  };

  const deliverResetEmail = async (toEmail, code) => {
    if (typeof deps.sendResetEmail === "function") {
      return deps.sendResetEmail(toEmail, code, buildPasswordResetEmail(code));
    }
    return sendResetEmailViaEnv(toEmail, code, deps.env || process.env, deps.fetchFn || globalThis.fetch);
  };

  return async function handleForgotPassword(req, res, action, body = {}) {
    const ip = getClientIp(req);

    // -----------------------------------------------------------------------
    // 1) درخواست کد بازیابی: forgot-request
    // -----------------------------------------------------------------------
    if (action === "forgot-request") {
      const email = normalizeEmail(body.email);
      if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
        return sendJson(res, 400, {
          success: false,
          error: "لطفاً یک آدرس ایمیل معتبر وارد کنید.",
        });
      }

      // fail-closed: بدون سرویس ارسال ایمیل هرگز بازیابی انجام نمیشود.
      if (!hasMailTransport()) {
        return sendJson(res, 503, {
          success: false,
          code: "MAIL_NOT_CONFIGURED",
          error: "سرویس ارسال ایمیل روی سرور فعال نیست؛ بازیابی رمز عبور بدون تأیید ایمیل انجام نمیشود.",
        });
      }

      const ipLimit = await enforceRateLimit(`forgot_req_ip:${ip}`, 10, 900);
      if (!ipLimit.allowed) {
        return sendJson(res, 429, {
          success: false,
          retryAfter: ipLimit.retryAfter,
          error: `تعداد درخواستها بیش از حد مجاز است. لطفاً ${ipLimit.retryAfter} ثانیه دیگر تلاش کنید.`,
        });
      }

      const cooldown = await enforceRateLimit(`forgot_cd:${email}`, 1, RESEND_COOLDOWN_SEC);
      if (!cooldown.allowed) {
        return sendJson(res, 429, {
          success: false,
          retryAfter: cooldown.retryAfter,
          error: `لطفاً ${cooldown.retryAfter} ثانیه صبر کنید و دوباره درخواست بدهید.`,
        });
      }

      const emailLimit = await enforceRateLimit(`forgot_req_email:${email}`, 5, 1800);
      if (!emailLimit.allowed) {
        return sendJson(res, 429, {
          success: false,
          retryAfter: emailLimit.retryAfter,
          error: "سقف درخواست بازیابی برای این ایمیل موقتاً پر شده است. کمی بعد تلاش کنید.",
        });
      }

      // جستجوی امن بدون wildcard injection و بدون خواندن رمز/هش کاربر
      const escaped = escapePostgrestLike(email);
      const users = await sbRequest(
        `mimchat_users?email=ilike.${encodeURIComponent(escaped)}&select=id,email&limit=5`
      );
      const user = (Array.isArray(users) ? users : []).find(
        (u) => normalizeEmail(u.email) === email
      );

      // ضدتشخیص (anti-enumeration): اگر ایمیل نبود، دقیقاً همان پاسخ عمومی ۲٠٠
      if (!user || !user.id) {
        return sendJson(res, 200, {
          success: true,
          accepted: true,
          expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
          resendAfter: RESEND_COOLDOWN_SEC,
          message: GENERIC_REQUEST_MESSAGE,
        });
      }

      const nowMs = now();
      const nowIso = new Date(nowMs).toISOString();

      // باطل کردن کدهای استفادهنشدهٔ قبلی فقط با PATCH (صفر DELETE)
      await sbRequest(
        `mimchat_password_resets?email=eq.${encodeURIComponent(email)}&used_at=is.null`,
        {
          method: "PATCH",
          prefer: "return=minimal",
          body: { used_at: nowIso },
        }
      );

      const code = generateSixDigitCode();
      const nonce = crypto.randomBytes(16).toString("hex");
      const codeHash = hmacHex("pw_reset_otp", `${email}|${code}|${nonce}`);
      const expiresAt = new Date(nowMs + OTP_TTL_MS).toISOString();

      const inserted = await sbRequest("mimchat_password_resets", {
        method: "POST",
        prefer: "return=representation",
        body: {
          user_id: String(user.id),
          email,
          code_hash: codeHash,
          nonce,
          expires_at: expiresAt,
          attempts: 0,
          max_attempts: MAX_ATTEMPTS,
          ip_hash: hmacHex("ip", ip),
        },
      });
      const row = Array.isArray(inserted) ? inserted[0] : null;
      if (!row || !row.id) {
        return sendJson(res, 500, {
          success: false,
          error: "ثبت درخواست بازیابی ناموفق بود.",
        });
      }

      let mailResult;
      try {
        mailResult = await deliverResetEmail(email, code);
      } catch (err) {
        // اگر ایمیل ارسال نشد، کد را فوراً با PATCH باطل کن (صفر DELETE)
        await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, {
          method: "PATCH",
          prefer: "return=minimal",
          body: { used_at: new Date(now()).toISOString() },
        }).catch(() => {});
        return sendJson(res, 502, {
          success: false,
          code: err && err.code ? err.code : "EMAIL_DELIVERY_FAILED",
          error: "ارسال ایمیل بازیابی انجام نشد. لطفاً تنظیمات سرویس ایمیل سرور را بررسی کنید.",
        });
      }

      if (mailResult && mailResult.messageId) {
        await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, {
          method: "PATCH",
          prefer: "return=minimal",
          body: { mail_message_id: String(mailResult.messageId).slice(0, 128) },
        }).catch(() => {});
      }

      // کد ۶ رقمی هرگز در پاسخ HTTP برگردانده نمیشود.
      return sendJson(res, 200, {
        success: true,
        accepted: true,
        expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
        resendAfter: RESEND_COOLDOWN_SEC,
        message: GENERIC_REQUEST_MESSAGE,
      });
    }

    // -----------------------------------------------------------------------
    // 2) تأیید کد ۶ رقمی: forgot-verify
    // -----------------------------------------------------------------------
    if (action === "forgot-verify") {
      const email = normalizeEmail(body.email);
      const code = String(body.code || "").trim();
      if (!email || !EMAIL_RE.test(email) || !CODE_RE.test(code)) {
        return sendJson(res, 400, {
          success: false,
          error: "ایمیل و کد ۶ رقمی معتبر وارد کنید.",
        });
      }

      const verifyLimit = await enforceRateLimit(`forgot_verify:${ip}:${email}`, 10, 600);
      if (!verifyLimit.allowed) {
        return sendJson(res, 429, {
          success: false,
          retryAfter: verifyLimit.retryAfter,
          error: "تعداد تلاشهای بررسی کد بیش از حد مجاز است. کمی صبر کنید.",
        });
      }

      const rows = await sbRequest(
        `mimchat_password_resets?email=eq.${encodeURIComponent(email)}&used_at=is.null&order=created_at.desc&limit=1&select=*`
      );
      const row = Array.isArray(rows) ? rows[0] : null;
      if (!row) {
        return sendJson(res, 400, {
          success: false,
          error: "کد فعالی برای این ایمیل یافت نشد یا قبلاً استفاده شده است.",
        });
      }

      const nowMs = now();
      const nowIso = new Date(nowMs).toISOString();

      if (new Date(row.expires_at).getTime() <= nowMs) {
        await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, {
          method: "PATCH",
          prefer: "return=minimal",
          body: { used_at: nowIso },
        });
        return sendJson(res, 400, {
          success: false,
          error: "مهلت کد بازیابی تمام شده است. لطفاً کد جدید درخواست کنید.",
        });
      }

      const maxAtt = Number(row.max_attempts || MAX_ATTEMPTS);
      const curAtt = Number(row.attempts || 0);
      if (curAtt >= maxAtt) {
        await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, {
          method: "PATCH",
          prefer: "return=minimal",
          body: { used_at: nowIso },
        });
        return sendJson(res, 400, {
          success: false,
          error: "تعداد تلاشهای مجاز این کد به پایان رسیده است. کد جدید بگیرید.",
        });
      }

      const candidateHash = hmacHex("pw_reset_otp", `${email}|${code}|${row.nonce}`);
      if (!safeEqualHex(candidateHash, row.code_hash)) {
        const nextAttempts = curAtt + 1;
        const burnNow = nextAttempts >= maxAtt;
        await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, {
          method: "PATCH",
          prefer: "return=minimal",
          body: burnNow ? { attempts: nextAttempts, used_at: nowIso } : { attempts: nextAttempts },
        });
        return sendJson(res, 400, {
          success: false,
          error: burnNow
            ? "کد نادرست بود و باطل شد. لطفاً کد جدید درخواست کنید."
            : "کد واردشده نادرست است.",
        });
      }

      // ابطال اتمیک کد و صدور توکن کوتاهمدت یکبارمصرف
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenHash = hmacHex("pw_reset_token", `${email}|${resetToken}`);
      const resetExpiresAt = new Date(nowMs + RESET_TOKEN_TTL_MS).toISOString();

      const burned = await sbRequest(
        `mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}&used_at=is.null`,
        {
          method: "PATCH",
          prefer: "return=representation",
          body: {
            used_at: nowIso,
            reset_token_hash: resetTokenHash,
            reset_expires_at: resetExpiresAt,
            reset_used_at: null,
          },
        }
      );
      if (!Array.isArray(burned) || !burned.length) {
        return sendJson(res, 400, {
          success: false,
          error: "این کد قبلاً استفاده شده است. کد جدید درخواست کنید.",
        });
      }

      return sendJson(res, 200, {
        success: true,
        verified: true,
        resetToken,
        expiresInSeconds: Math.floor(RESET_TOKEN_TTL_MS / 1000),
      });
    }

    // -----------------------------------------------------------------------
    // 3) ثبت رمز جدید و بستن نشستهای قبلی: forgot-reset
    // -----------------------------------------------------------------------
    if (action === "forgot-reset") {
      const email = normalizeEmail(body.email);
      const resetToken = String(body.resetToken || "").trim().toLowerCase();
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

      if (!email || !EMAIL_RE.test(email) || !RESET_TOKEN_RE.test(resetToken)) {
        return sendJson(res, 400, {
          success: false,
          error: "توکن بازیابی معتبر نیست یا منقضی شده است.",
        });
      }
      if (newPassword.length < MIN_PASSWORD_LEN || newPassword.length > MAX_PASSWORD_LEN) {
        return sendJson(res, 400, {
          success: false,
          error: "رمز جدید باید بین ۶ تا ۶۴ نویسه باشد.",
        });
      }

      const resetLimit = await enforceRateLimit(`forgot_complete:${ip}`, 10, 900);
      if (!resetLimit.allowed) {
        return sendJson(res, 429, {
          success: false,
          retryAfter: resetLimit.retryAfter,
          error: "تعداد درخواستهای تغییر رمز زیاد است. کمی صبر کنید.",
        });
      }

      const expectedTokenHash = hmacHex("pw_reset_token", `${email}|${resetToken}`);
      const rows = await sbRequest(
        `mimchat_password_resets?email=eq.${encodeURIComponent(email)}&reset_token_hash=eq.${encodeURIComponent(expectedTokenHash)}&reset_used_at=is.null&order=created_at.desc&limit=1&select=*`
      );
      const row = Array.isArray(rows) ? rows[0] : null;
      const nowMs = now();
      const nowIso = new Date(nowMs).toISOString();

      if (
        !row ||
        !row.used_at ||
        !row.reset_token_hash ||
        !safeEqualHex(expectedTokenHash, row.reset_token_hash) ||
        !row.reset_expires_at ||
        new Date(row.reset_expires_at).getTime() <= nowMs
      ) {
        return sendJson(res, 400, {
          success: false,
          error: "توکن بازیابی نامعتبر است یا مهلت آن به پایان رسیده است.",
        });
      }

      // ابطال اتمیک توکن پیش از تغییر رمز (جلوگیری از استفادهٔ موازی/مجدد)
      const burned = await sbRequest(
        `mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}&reset_used_at=is.null`,
        {
          method: "PATCH",
          prefer: "return=representation",
          body: { reset_used_at: nowIso },
        }
      );
      if (!Array.isArray(burned) || !burned.length) {
        return sendJson(res, 400, {
          success: false,
          error: "این توکن بازیابی قبلاً مصرف شده است.",
        });
      }

      const userRows = await sbRequest(
        `mimchat_users?id=eq.${encodeURIComponent(row.user_id)}&select=id,email,session_epoch&limit=1`
      );
      const user = Array.isArray(userRows) ? userRows[0] : null;
      if (!user || normalizeEmail(user.email) !== email) {
        return sendJson(res, 404, {
          success: false,
          error: "حساب کاربری متناظر یافت نشد.",
        });
      }

      const { saltHex, hashHex } = hashPwd(newPassword);
      const nextEpoch = Number(user.session_epoch || 0) + 1;

      await sbRequest(`mimchat_users?id=eq.${encodeURIComponent(user.id)}`, {
        method: "PATCH",
        prefer: "return=minimal",
        body: {
          password_hash: hashHex,
          password_salt: saltHex,
          session_epoch: nextEpoch,
        },
      });

      await sbRequest(`mimchat_sessions?user_id=eq.${encodeURIComponent(user.id)}`, {
        method: "PATCH",
        prefer: "return=minimal",
        body: { revoked: true },
      }).catch(() => {});

      return sendJson(res, 200, {
        success: true,
        reset: true,
        sessionsRevoked: true,
        message: "رمز عبور جدید با موفقیت ثبت شد. همهٔ نشستهای قبلی بسته شدند؛ اکنون با رمز جدید وارد شوید.",
      });
    }

    return sendJson(res, 404, {
      success: false,
      error: "مسیر فراموشی رمز یافت نشد.",
    });
  };
}

module.exports = {
  FORGOT_ACTIONS,
  OTP_TTL_MS,
  RESET_TOKEN_TTL_MS,
  RESEND_COOLDOWN_SEC,
  MIN_PASSWORD_LEN,
  MAX_PASSWORD_LEN,
  MAX_ATTEMPTS,
  normalizeEmail,
  escapePostgrestLike,
  generateSixDigitCode,
  hashPassword,
  verifyPassword,
  safeEqualHex,
  buildPasswordResetEmail,
  isMailProviderConfigured,
  sendResetEmailViaEnv,
  createDefaultRateLimiter,
  createForgotPasswordHandler,
};
