// MemeChat API on Supabase Edge — «فراموشی رمز عبور» افزوده شد، اینلاین.
// صفحه ایستای GitHub Pages است؛ باندل اجرایی در باکت Storage edge-code و رازها در Deno.env.
// سه اکشن فراموشی رمز اینجا مدیریت می‌شوند؛ بقیه مسارات بدون تغییری به باندل delegate می‌شوند.
import { createRequire } from 'node:module';
import { Buffer } from 'node:buffer';
import { scryptSync, timingSafeEqual, createHmac, randomBytes, randomInt } from 'node:crypto';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};
const BUNDLE = 'mimchat-backend-v5422.cjs';
const SHA256 = 'e3d0049157e6de422e49c590bf527d0924abb68a823a3ac2e095c990bf8eff16';
const FORGOT_ACTIONS = new Set(['forgot-request', 'forgot-verify', 'forgot-reset']);
let appPromise;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CODE_RE = /^\d{6}$/;
const RESET_TOKEN_RE = /^[0-9a-f]{64}$/;
const OTP_TTL_MS = 10 * 60 * 1000;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const RESEND_COOLDOWN_SEC = 60;
const MIN_PASSWORD_LEN = 6;
const MAX_PASSWORD_LEN = 64;
const MAX_ATTEMPTS = 5;

function normalizeEmail(raw) { return String(raw || '').trim().toLowerCase(); }
function escapePostgrestLike(s) { return String(s || '').replace(/[\\%_]/g, '\\$&'); }
function generateSixDigitCode() { return String(randomInt(100000, 1000000)); }
function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !a.length || a.length !== b.length) return false;
  try { return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); } catch { return false; }
}
function hmacSecret() {
  const s = (Deno.env.get('OTP_HMAC_SECRET') || Deno.env.get('SESSION_SECRET') || '').trim();
  if (!s || s.length < 16) throw new Error('SERVER_CRYPTO_NOT_CONFIGURED');
  return s;
}
function hmacHex(purpose, value) {
  return createHmac('sha256', hmacSecret()).update(`${purpose}:${String(value || '')}`).digest('hex');
}
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : randomBytes(16);
  const derived = scryptSync(String(password), salt, 64);
  return { saltHex: salt.toString('hex'), hashHex: derived.toString('hex') };
}
function sbConfig() {
  const url = String(Deno.env.get('SUPABASE_URL') || '').replace(/\/+$/, '');
  const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
  if (!url || !key) throw new Error('SUPABASE_NOT_CONFIGURED');
  return { url, key };
}
async function sbRequest(pathWithQuery, { method = 'GET', body, prefer } = {}) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'DELETE') throw new Error('NO_DELETE_ALLOWED');
  const { url, key } = sbConfig();
  const headers = { apikey: key, Authorization: `Bearer ${key}`, Accept: 'application/json' };
  if (prefer) headers.Prefer = prefer;
  let payload;
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const resp = await fetch(`${url}/rest/v1/${pathWithQuery}`, { method: m, headers, body: payload });
  const text = await resp.text();
  let parsed = null;
  if (text) { try { parsed = JSON.parse(text); } catch { parsed = text; } }
  if (!resp.ok) { const err = new Error(`SUPABASE_${resp.status}`); err.status = resp.status; err.detail = parsed; throw err; }
  return parsed;
}
function getClientIp(request) {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const parts = xff.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return 'unknown';
}
function isMailConfigured() {
  const brevo = !!(Deno.env.get('BREVO_API_KEY') || '').trim() && !!(Deno.env.get('BREVO_FROM_EMAIL') || '').trim();
  const resend = !!(Deno.env.get('RESEND_API_KEY') || '').trim() && !!(Deno.env.get('RESEND_FROM_EMAIL') || '').trim();
  return brevo || resend;
}
function buildPasswordResetEmail(sixDigitCode) {
  const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;background:#14100c;color:#f5f0e6;padding:28px;border-radius:16px;max-width:480px;margin:0 auto;border:1px solid #3d3428;"><h2 style="color:#ffb347;margin:0 0 12px;">بازیابی رمز عبور میمچت</h2><p style="font-size:14px;line-height:1.8;color:#d6cec2;">این کد یکبارمصرف برای تغییر رمز عبور حساب شماست:</p><div style="background:#241c14;border:1px solid #ff8c00;border-radius:12px;padding:16px;text-align:center;font-size:28px;font-weight:bold;letter-spacing:8px;color:#ffb347;margin:18px 0;direction:ltr;">${sixDigitCode}</div><p style="font-size:12px;color:#a89f8f;line-height:1.7;">این کد تا <b>۱۰ دقیقه</b> معتبر است و فقط یک بار قابل استفاده است. اگر شما درخواست بازیابی نداده اید، این ایمیل را نادیده بگیرید؛ رمز شما تغییر نمیکند.</p></div>`;
  const text = `کد بازیابی رمز عبور میمچت: ${sixDigitCode}\nاین کد تا ۱۰ دقیقه معتبر است و فقط یک بار قابل استفاده است. اگر شما درخواست نداده اید، آن را نادیده بگیرید.`;
  return { subject: 'کد بازیابی رمز عبور میمچت', html, text };
}
function parseSender(value, fallbackName) {
  const raw = String(value || '').trim();
  const m = raw.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  if (m) return { name: m[1] || fallbackName, email: m[2].trim() };
  return { name: fallbackName, email: raw };
}
async function sendResetEmailViaEnv(toEmail, sixDigitCode, fetchFn = fetch) {
  const mail = buildPasswordResetEmail(sixDigitCode);
  const brevoKey = (Deno.env.get('BREVO_API_KEY') || '').trim();
  const brevoFrom = (Deno.env.get('BREVO_FROM_EMAIL') || '').trim();
  const resendKey = (Deno.env.get('RESEND_API_KEY') || '').trim();
  const resendFrom = (Deno.env.get('RESEND_FROM_EMAIL') || '').trim();
  if (brevoKey && brevoFrom) {
    const base = (Deno.env.get('BREVO_API_BASE') || 'https://api.brevo.com').replace(/\/+$/, '');
    const sender = parseSender(brevoFrom, 'MemeChat');
    const resp = await fetchFn(`${base}/v3/smtp/email`, {
      method: 'POST',
      headers: { 'api-key': brevoKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: { name: sender.name, email: sender.email }, to: [{ email: toEmail }], subject: mail.subject, htmlContent: mail.html, textContent: mail.text }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !(data.messageId || data.messageIds)) { const err = new Error('EMAIL_REJECTED'); err.code = 'EMAIL_REJECTED'; err.httpStatus = resp.status; throw err; }
    return { messageId: String(data.messageId || (data.messageIds && data.messageIds[0]) || 'brevo') };
  }
  if (resendKey && resendFrom) {
    const base = (Deno.env.get('RESEND_API_BASE') || 'https://api.resend.com').replace(/\/+$/, '');
    const resp = await fetchFn(`${base}/emails`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: resendFrom, to: [toEmail], subject: mail.subject, html: mail.html, text: mail.text }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.id) { const err = new Error('RESEND_REJECTED'); err.code = 'RESEND_REJECTED'; err.httpStatus = resp.status; throw err; }
    return { messageId: String(data.id) };
  }
  const err = new Error('MAIL_NOT_CONFIGURED'); err.code = 'MAIL_NOT_CONFIGURED'; throw err;
}
const GENERIC_REQUEST_MESSAGE = "اگر این ایمیل در سیستم ثبت شده باشد، کد ۶ رقمی بازیابی ارسال شد. لطفاً صندوق ورودی و هرزنامه را بررسی کنید.";
function json(status, payload) {
  return new Response(JSON.stringify(payload), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS } });
}
async function handleForgotPassword(request, action) {
  const ip = getClientIp(request);
  let body = {};
  try { body = await request.json(); } catch { body = {}; }

  if (action === 'forgot-request') {
    const email = normalizeEmail(body.email);
    if (!email || email.length > 254 || !EMAIL_RE.test(email)) return json(400, { success: false, error: 'لطفاً یک آدرس ایمیل معتبر وارد کنید.' });
    if (!isMailConfigured()) return json(503, { success: false, code: 'MAIL_NOT_CONFIGURED', error: 'سرویس ارسال ایمیل روی سرور فعال نیست؛ بازیابی رمز عبور بدون تأیید ایمیل انجام نمیشود.' });

    const ipLimit = await enforceRateLimit(`forgot_req_ip:${ip}`, 10, 900);
    if (!ipLimit.allowed) return json(429, { success: false, retryAfter: ipLimit.retryAfter, error: `تعداد درخواستها بیش از حد مجاز است. لطفاً ${ipLimit.retryAfter} ثانیه دیگر تلاش کنید.` });
    const cooldown = await enforceRateLimit(`forgot_cd:${email}`, 1, RESEND_COOLDOWN_SEC);
    if (!cooldown.allowed) return json(429, { success: false, retryAfter: cooldown.retryAfter, error: `لطفاً ${cooldown.retryAfter} ثانیه صبر کنید و دوباره درخواست بدهید.` });
    const emailLimit = await enforceRateLimit(`forgot_req_email:${email}`, 5, 1800);
    if (!emailLimit.allowed) return json(429, { success: false, retryAfter: emailLimit.retryAfter, error: 'سقف درخواست بازیابی برای این ایمیل موقتاً پر شده است. کمی بعد تلاش کنید.' });

    const escaped = escapePostgrestLike(email);
    const users = await sbRequest(`mimchat_users?email=ilike.${encodeURIComponent(escaped)}&select=id,email&limit=5`);
    const user = (Array.isArray(users) ? users : []).find(u => normalizeEmail(u.email) === email);
    if (!user || !user.id) return json(200, { success: true, accepted: true, expiresInSeconds: Math.floor(OTP_TTL_MS / 1000), resendAfter: RESEND_COOLDOWN_SEC, message: GENERIC_REQUEST_MESSAGE });

    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    await sbRequest(`mimchat_password_resets?email=eq.${encodeURIComponent(email)}&used_at=is.null`, { method: 'PATCH', prefer: 'return=minimal', body: { used_at: nowIso } });

    const code = generateSixDigitCode();
    const nonce = randomBytes(16).toString('hex');
    const codeHash = hmacHex('pw_reset_otp', `${email}|${code}|${nonce}`);
    const expiresAt = new Date(nowMs + OTP_TTL_MS).toISOString();
    const inserted = await sbRequest('mimchat_password_resets', { method: 'POST', prefer: 'return=representation', body: { user_id: String(user.id), email, code_hash: codeHash, nonce, expires_at: expiresAt, attempts: 0, max_attempts: MAX_ATTEMPTS, ip_hash: hmacHex('ip', ip) } });
    const row = Array.isArray(inserted) ? inserted[0] : null;
    if (!row || !row.id) return json(500, { success: false, error: 'ثبت درخواست بازیابی ناموفق بود.' });

    let mailResult;
    try { mailResult = await sendResetEmailViaEnv(email, code); } catch (err) {
      await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { used_at: new Date(Date.now()).toISOString() } }).catch(() => {});
      return json(502, { success: false, code: err && err.code ? err.code : 'EMAIL_DELIVERY_FAILED', error: 'ارسال ایمیل بازیابی انجام نشد. لطفاً تنظیمات سرویس ایمیل سرور را بررسی کنید.' });
    }
    if (mailResult && mailResult.messageId) {
      await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { mail_message_id: String(mailResult.messageId).slice(0, 128) } }).catch(() => {});
    }
    return json(200, { success: true, accepted: true, expiresInSeconds: Math.floor(OTP_TTL_MS / 1000), resendAfter: RESEND_COOLDOWN_SEC, message: GENERIC_REQUEST_MESSAGE });
  }

  if (action === 'forgot-verify') {
    const email = normalizeEmail(body.email);
    const code = String(body.code || '').trim();
    if (!email || !EMAIL_RE.test(email) || !CODE_RE.test(code)) return json(400, { success: false, error: 'ایمیل و کد ۶ رقمی معتبر وارد کنید.' });
    const verifyLimit = await enforceRateLimit(`forgot_verify:${ip}:${email}`, 10, 600);
    if (!verifyLimit.allowed) return json(429, { success: false, retryAfter: verifyLimit.retryAfter, error: 'تعداد تلاشهای بررسی کد بیش از حد مجاز است. کمی صبر کنید.' });
    const rows = await sbRequest(`mimchat_password_resets?email=eq.${encodeURIComponent(email)}&used_at=is.null&order=created_at.desc&limit=1&select=*`);
    const row = Array.isArray(rows) ? rows[0] : null;
    if (!row) return json(400, { success: false, error: 'کد فعالی برای این ایمیل یافت نشد یا قبلاً استفاده شده است.' });
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    if (new Date(row.expires_at).getTime() <= nowMs) {
      await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { used_at: nowIso } });
      return json(400, { success: false, error: 'مهلت کد بازیابی تمام شده است. لطفاً کد جدید درخواست کنید.' });
    }
    const maxAtt = Number(row.max_attempts || MAX_ATTEMPTS);
    const curAtt = Number(row.attempts || 0);
    if (curAtt >= maxAtt) {
      await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { used_at: nowIso } });
      return json(400, { success: false, error: 'تعداد تلاشهای مجاز این کد به پایان رسیده است. کد جدید بگیرید.' });
    }
    const candidateHash = hmacHex('pw_reset_otp', `${email}|${code}|${row.nonce}`);
    if (!safeEqualHex(candidateHash, row.code_hash)) {
      const nextAttempts = curAtt + 1;
      const burnNow = nextAttempts >= maxAtt;
      await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: burnNow ? { attempts: nextAttempts, used_at: nowIso } : { attempts: nextAttempts } });
      return json(400, { success: false, error: burnNow ? 'کد نادرست بود و باطل شد. لطفاً کد جدید درخواست کنید.' : 'کد واردشده نادرست است.' });
    }
    const resetToken = randomBytes(32).toString('hex');
    const resetTokenHash = hmacHex('pw_reset_token', `${email}|${resetToken}`);
    const resetExpiresAt = new Date(nowMs + RESET_TOKEN_TTL_MS).toISOString();
    const burned = await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}&used_at=is.null`, { method: 'PATCH', prefer: 'return=representation', body: { used_at: nowIso, reset_token_hash: resetTokenHash, reset_expires_at: resetExpiresAt, reset_used_at: null } });
    if (!Array.isArray(burned) || !burned.length) return json(400, { success: false, error: 'این کد قبلاً استفاده شده است. کد جدید درخواست کنید.' });
    return json(200, { success: true, verified: true, resetToken, expiresInSeconds: Math.floor(RESET_TOKEN_TTL_MS / 1000) });
  }

  if (action === 'forgot-reset') {
    const email = normalizeEmail(body.email);
    const resetToken = String(body.resetToken || '').trim().toLowerCase();
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
    if (!email || !EMAIL_RE.test(email) || !RESET_TOKEN_RE.test(resetToken)) return json(400, { success: false, error: 'توکن بازیابی معتبر نیست یا منقضی شده است.' });
    if (newPassword.length < MIN_PASSWORD_LEN || newPassword.length > MAX_PASSWORD_LEN) return json(400, { success: false, error: 'رمز جدید باید بین ۶ تا ۶۴ نویسه باشد.' });
    const resetLimit = await enforceRateLimit(`forgot_complete:${ip}`, 10, 900);
    if (!resetLimit.allowed) return json(429, { success: false, retryAfter: resetLimit.retryAfter, error: 'تعداد درخواستهای تغییر رمز زیاد است. کمی صبر کنید.' });
    const expectedTokenHash = hmacHex('pw_reset_token', `${email}|${resetToken}`);
    const rows = await sbRequest(`mimchat_password_resets?email=eq.${encodeURIComponent(email)}&reset_token_hash=eq.${encodeURIComponent(expectedTokenHash)}&reset_used_at=is.null&order=created_at.desc&limit=1&select=*`);
    const row = Array.isArray(rows) ? rows[0] : null;
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    if (!row || !row.used_at || !row.reset_token_hash || !safeEqualHex(expectedTokenHash, row.reset_token_hash) || !row.reset_expires_at || new Date(row.reset_expires_at).getTime() <= nowMs) {
      return json(400, { success: false, error: 'توکن بازیابی نامعتبر است یا مهلت آن به پایان رسیده است.' });
    }
    const burned = await sbRequest(`mimchat_password_resets?id=eq.${encodeURIComponent(row.id)}&reset_used_at=is.null`, { method: 'PATCH', prefer: 'return=representation', body: { reset_used_at: nowIso } });
    if (!Array.isArray(burned) || !burned.length) return json(400, { success: false, error: 'این توکن بازیابی قبلاً مصرف شده است.' });
    const userRows = await sbRequest(`mimchat_users?id=eq.${encodeURIComponent(row.user_id)}&select=id,email,session_epoch&limit=1`);
    const user = Array.isArray(userRows) ? userRows[0] : null;
    if (!user || normalizeEmail(user.email) !== email) return json(404, { success: false, error: 'حساب کاربری متناظر یافت نشد.' });
    const { saltHex, hashHex } = hashPassword(newPassword);
    const nextEpoch = Number(user.session_epoch || 0) + 1;
    await sbRequest(`mimchat_users?id=eq.${encodeURIComponent(user.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { password_hash: hashHex, password_salt: saltHex, session_epoch: nextEpoch } });
    await sbRequest(`mimchat_sessions?user_id=eq.${encodeURIComponent(user.id)}`, { method: 'PATCH', prefer: 'return=minimal', body: { revoked: true } }).catch(() => {});
    return json(200, { success: true, reset: true, sessionsRevoked: true, message: 'رمز عبور جدید با موفقیت ثبت شد. همهٔ نشستهای قبلی بسته شدند؛ اکنون با رمز جدید وارد شوید.' });
  }

  return json(404, { success: false, error: 'مسیر فراموشی رمز یافت نشد.' });
}

async function loadApp() {
  if (!appPromise) appPromise = (async () => {
    const url = String(Deno.env.get('SUPABASE_URL') || '').replace(/\/+$/, '');
    const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!url || !key) throw new Error('Backend configuration unavailable');
    const resp = await fetch(url + '/storage/v1/object/edge-code/' + BUNDLE, { headers: { apikey: key, Authorization: 'Bearer ' + key } });
    if (!resp.ok) throw new Error('Backend source unavailable (' + resp.status + ')');
    const bytes = await resp.arrayBuffer();
    const actualHash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(v => v.toString(16).padStart(2, '0')).join('');
    if (actualHash !== SHA256) throw new Error('Backend integrity check failed');
    const mod = { exports: {} };
    const nodeRequire = createRequire('file:///tmp/mimchat-edge-entry.cjs');
    const proc = { env: new Proxy({}, { get: (_, name) => typeof name === 'string' ? Deno.env.get(name) : undefined }) };
    new Function('module', 'exports', 'require', 'Buffer', 'process', 'global', new TextDecoder().decode(bytes))(mod, mod.exports, nodeRequire, Buffer, proc, globalThis);
    if (typeof mod.exports.default !== 'function') throw new Error('Backend entry missing');
    return mod.exports.default;
  })().catch(err => { appPromise = undefined; throw err; });
  return appPromise;
}

async function enforceRateLimit(rawKey, maxCount, windowSeconds) {
  const sbRequestF = sbRequest;
  const bucketKey = hmacHex('ratelimit', rawKey);
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const rows = await sbRequestF(`mimchat_rate_limits?bucket_key=eq.${encodeURIComponent(bucketKey)}&select=*`);
  const existing = Array.isArray(rows) ? rows[0] : null;
  const nextExpiry = new Date(nowMs + windowSeconds * 1000).toISOString();
  if (!existing || new Date(existing.expires_at).getTime() <= nowMs) {
    await sbRequestF('mimchat_rate_limits?on_conflict=bucket_key', { method: 'POST', prefer: 'resolution=merge-duplicates,return=minimal', body: { bucket_key: bucketKey, count: 1, window_start: nowIso, expires_at: nextExpiry } });
    return { allowed: true, remaining: Math.max(0, maxCount - 1), retryAfter: 0 };
  }
  if (Number(existing.count || 0) >= maxCount) {
    const retryAfter = Math.max(1, Math.ceil((new Date(existing.expires_at).getTime() - nowMs) / 1000));
    return { allowed: false, remaining: 0, retryAfter };
  }
  const nextCount = Number(existing.count || 0) + 1;
  await sbRequestF(`mimchat_rate_limits?bucket_key=eq.${encodeURIComponent(bucketKey)}`, { method: 'PATCH', prefer: 'return=minimal', body: { count: nextCount } });
  return { allowed: true, remaining: Math.max(0, maxCount - nextCount), retryAfter: 0 };
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const url = new URL(request.url);
  if (url.pathname.endsWith('/__ping')) {
    return Response.json({ ok: true, edge: 'Deno.serve' }, { headers: CORS });
  }
  try {
    const action = url.searchParams.get('action');
    if (action && FORGOT_ACTIONS.has(action)) return await handleForgotPassword(request, action);
    const app = await loadApp();
    return await app(request);
  } catch (err) {
    console.error('[mimchat-api] request failed', err);
    return Response.json({ success: false, error: 'خطا در سرور' + '؛ دوباره تلاش کنید' }, { status: 503, headers: CORS });
  }
});
