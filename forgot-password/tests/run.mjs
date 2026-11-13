/* تستهای آفلاین قابلیت «فراموشی رمز عبور» میمچت.
 * اجرا: node forgot-password/tests/run.mjs
 *
 * بدون تماس با Supabase زنده، بدون ارسال ایمیل واقعی، بدون ورسل و بدون حذف.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');

const fp = require('../server/forgot-password.cjs');
const { createForgotPasswordController } = require('../client/forgot-password.js');

let passed = 0;
const test = async (name, fn) => {
  try {
    await fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (err) {
    console.error(`FAIL  ${name}\n      ${err.stack}`);
    process.exitCode = 1;
  }
};

/* شبیهساز دقیق PostgREST فقطبرای تستهای آفلاین — هر DELETE رد میشود. */
class MockSupabase {
  constructor() {
    this.tables = {
      mimchat_users: [],
      mimchat_password_resets: [],
      mimchat_rate_limits: [],
      mimchat_sessions: [],
    };
    this.deleteCalls = 0;
  }

  _matchFilter(row, key, expr) {
    if (expr === 'is.null') return row[key] === null || row[key] === undefined;
    if (expr.startsWith('eq.')) return String(row[key] ?? '') === decodeURIComponent(expr.slice(3));
    if (expr.startsWith('ilike.')) {
      const rawPat = decodeURIComponent(expr.slice(6));
      let regex = '^';
      for (let i = 0; i < rawPat.length; i++) {
        const ch = rawPat[i];
        if (ch === '\\' && i + 1 < rawPat.length) {
          regex += rawPat[++i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        } else if (ch === '%') regex += '.*';
        else if (ch === '_') regex += '.';
        else regex += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      }
      regex += '$';
      return new RegExp(regex, 'i').test(String(row[key] ?? ''));
    }
    throw new Error(`UNSUPPORTED_FILTER:${key}=${expr}`);
  }

  async request(pathWithQuery, { method = 'GET', body, prefer } = {}) {
    const m = String(method || 'GET').toUpperCase();
    if (m === 'DELETE') {
      this.deleteCalls++;
      throw new Error('NO_DELETE_ALLOWED');
    }
    const [table, qs = ''] = pathWithQuery.split('?');
    if (!this.tables[table]) throw new Error(`UNKNOWN_TABLE:${table}`);
    const params = new URLSearchParams(qs);
    const filters = [];
    for (const [k, v] of params.entries()) {
      if (['select', 'order', 'limit', 'on_conflict'].includes(k)) continue;
      filters.push([k, v]);
    }
    const rows = this.tables[table];
    const matching = () => rows.filter((r) => filters.every(([k, v]) => this._matchFilter(r, k, v)));

    if (m === 'GET') {
      let out = matching().map((r) => ({ ...r }));
      const order = params.get('order');
      if (order) {
        const [col, dir] = order.split('.');
        out.sort((a, b) => {
          const av = String(a[col] ?? '');
          const bv = String(b[col] ?? '');
          return dir === 'desc' ? bv.localeCompare(av) : av.localeCompare(bv);
        });
      }
      const limit = Number(params.get('limit') || 0);
      if (limit > 0) out = out.slice(0, limit);
      return out;
    }

    if (m === 'POST') {
      const list = Array.isArray(body) ? body : [body];
      const conflictCol = params.get('on_conflict');
      const inserted = [];
      for (const item of list) {
        const rec = {
          id: item.id || crypto.randomUUID(),
          created_at: item.created_at || new Date().toISOString(),
          ...item,
        };
        if (conflictCol) {
          const idx = rows.findIndex((r) => r[conflictCol] === rec[conflictCol]);
          if (idx >= 0) {
            rows[idx] = { ...rows[idx], ...rec };
            inserted.push({ ...rows[idx] });
            continue;
          }
        }
        rows.push(rec);
        inserted.push({ ...rec });
      }
      return prefer && prefer.includes('return=minimal') ? null : inserted;
    }

    if (m === 'PATCH') {
      const hits = matching();
      const updated = [];
      for (const r of hits) {
        Object.assign(r, body);
        updated.push({ ...r });
      }
      return prefer && prefer.includes('return=representation') ? updated : null;
    }

    throw new Error(`UNSUPPORTED_METHOD:${m}`);
  }
}

function makeRes() {
  const headers = {};
  const res = {
    statusCode: 200,
    body: null,
    json: null,
    headers,
    setHeader(k, v) { headers[k.toLowerCase()] = String(v); },
    end(txt) {
      this.body = txt;
      try { this.json = JSON.parse(txt); } catch { this.json = null; }
    },
  };
  return res;
}

function makeHarness({ mailConfigured = true, mailFail = false } = {}) {
  const sb = new MockSupabase();
  let clockMs = Date.UTC(2026, 10, 12, 20, 0, 0);
  const sentMails = [];
  const secret = 'test-hmac-secret-at-least-32-bytes-long!!';
  const hmacHex = (purpose, value) =>
    crypto.createHmac('sha256', secret).update(`${purpose}:${String(value || '')}`).digest('hex');

  const initPass = fp.hashPassword('OldPass!123');
  sb.tables.mimchat_users.push({
    id: 'u_alice01',
    username: 'alice_m',
    email: 'Alice_Test@Example.com',
    password_hash: initPass.hashHex,
    password_salt: initPass.saltHex,
    session_epoch: 0,
    created_at: new Date(clockMs - 86400000).toISOString(),
  });
  sb.tables.mimchat_sessions.push({
    id: 'sess_old_1',
    user_id: 'u_alice01',
    revoked: false,
  });

  const handler = fp.createForgotPasswordHandler({
    sbRequest: (q, o) => sb.request(q, o),
    hmacHex,
    now: () => clockMs,
    isMailConfigured: () => mailConfigured,
    sendResetEmail: async (to, code, mail) => {
      if (mailFail) {
        const e = new Error('SMTP_DOWN');
        e.code = 'EMAIL_NETWORK_FAILURE';
        throw e;
      }
      sentMails.push({ to, code, subject: mail.subject });
      return { messageId: `msg_${sentMails.length}` };
    },
  });

  async function call(action, body, ip = '203.0.113.10') {
    const req = { method: 'POST', headers: { 'x-forwarded-for': ip }, socket: { remoteAddress: ip } };
    const res = makeRes();
    await handler(req, res, action, body);
    return { status: res.statusCode, json: res.json, headers: res.headers, body: res.body };
  }

  return {
    sb,
    sentMails,
    call,
    advanceMs: (ms) => { clockMs += ms; },
  };
}

/* DOM سبک برای تست کلاینت در Node (بدون مرورگر یا شبکه) */
function makeMockDocument() {
  const byId = new Map();
  function makeEl(tag, id = '') {
    const listeners = {};
    const children = [];
    const el = {
      tagName: tag.toUpperCase(),
      id,
      type: '',
      className: '',
      value: '',
      textContent: '',
      disabled: false,
      style: { display: '' },
      attrs: {},
      parentNode: null,
      children,
      setAttribute(k, v) { this.attrs[k] = String(v); },
      appendChild(child) {
        child.parentNode = this;
        children.push(child);
        if (child.id) byId.set(child.id, child);
        return child;
      },
      removeChild(child) {
        const idx = children.indexOf(child);
        if (idx >= 0) children.splice(idx, 1);
        child.parentNode = null;
        if (child.id) byId.delete(child.id);
      },
      addEventListener(ev, fn) {
        listeners[ev] = listeners[ev] || [];
        listeners[ev].push(fn);
      },
      removeEventListener(ev, fn) {
        if (!listeners[ev]) return;
        listeners[ev] = listeners[ev].filter((f) => f !== fn);
      },
      dispatch(ev, evObj = {}) {
        (listeners[ev] || []).forEach((fn) => fn(evObj));
      },
      focus() {},
      set innerHTML(html) {
        // استخراج idهای عناصر ساختارشده برای تست کلاینت
        this._innerHTML = html;
        const ids = [...String(html).matchAll(/id="([^"]+)"/g)].map((m) => m[1]);
        for (const cid of ids) {
          if (!byId.has(cid)) {
            const c = makeEl('div', cid);
            c.parentNode = this;
            children.push(c);
            byId.set(cid, c);
          }
        }
      },
      get innerHTML() { return this._innerHTML || ''; },
    };
    if (id) byId.set(id, el);
    return el;
  }

  const head = makeEl('head');
  const boxLog = makeEl('div', 'boxLog');
  const logStep1 = makeEl('div', 'logStep1');
  const logStep2 = makeEl('div', 'logStep2');
  const lUser = makeEl('input', 'lUser');
  const tabReg = makeEl('button', 'tabReg');
  boxLog.appendChild(logStep1);
  boxLog.appendChild(logStep2);
  logStep1.appendChild(lUser);

  return {
    head,
    getElementById: (id) => byId.get(id) || null,
    createElement: (tag) => makeEl(tag),
  };
}

await test('ثابتها و هش scrypt با قالب میمچت سازگار است', () => {
  assert.deepEqual(fp.FORGOT_ACTIONS, ['forgot-request', 'forgot-verify', 'forgot-reset']);
  const { saltHex, hashHex } = fp.hashPassword('MySecret#2026');
  assert.equal(saltHex.length, 32);
  assert.equal(hashHex.length, 128);
  assert.equal(fp.verifyPassword('MySecret#2026', hashHex, saltHex), true);
  assert.equal(fp.verifyPassword('WrongPass', hashHex, saltHex), false);
});

await test('اگر سرویس ایمیل پیکربندی نشده باشد، با ۵۰۳ fail-closed میشود (هیچ دور زدنی نیست)', async () => {
  const { sb, sentMails, call } = makeHarness({ mailConfigured: false });
  const r = await call('forgot-request', { email: 'alice_test@example.com' });
  assert.equal(r.status, 503);
  assert.equal(r.json.success, false);
  assert.equal(r.json.code, 'MAIL_NOT_CONFIGURED');
  assert.equal(sb.tables.mimchat_password_resets.length, 0);
  assert.equal(sentMails.length, 0);
});

await test('ضدتشخیص حساب (anti-enumeration): ایمیل ناموجود دقیقاً پاسخ ۲٠٠ یکسان میگیرد', async () => {
  const { sb, sentMails, call } = makeHarness();
  const rMissing = await call('forgot-request', { email: 'nobody@example.com' }, '198.51.100.1');
  const rExists = await call('forgot-request', { email: 'alice_test@example.com' }, '198.51.100.2');
  assert.equal(rMissing.status, 200);
  assert.equal(rExists.status, 200);
  assert.deepEqual(rMissing.json, rExists.json);
  assert.equal(sentMails.length, 1);
  assert.equal(sb.tables.mimchat_password_resets.length, 1);
  assert.equal(JSON.stringify(rExists.json).includes(sentMails[0].code), false, 'کد هرگز در پاسخ نیست');
});

await test('پیشگیری از wildcard injection روی underscore در ایمیل', async () => {
  const { sb, sentMails, call } = makeHarness();
  // کاربر ثبتشده: Alice_Test@Example.com
  const rWildcard = await call('forgot-request', { email: 'alicextest@example.com' });
  assert.equal(rWildcard.status, 200);
  assert.equal(sentMails.length, 0, 'n نباید جایگزین _ شود');
  assert.equal(sb.tables.mimchat_password_resets.length, 0);
});

await test('جریان کامل فراموشی رمز: درخواست → کد ۶ رقمی → تغییر رمز → ابطال نشستها', async () => {
  const { sb, sentMails, call } = makeHarness();
  const r1 = await call('forgot-request', { email: 'ALICE_TEST@EXAMPLE.COM' });
  assert.equal(r1.status, 200);
  assert.equal(sentMails.length, 1);
  assert.match(sentMails[0].code, /^\d{6}$/);

  const row = sb.tables.mimchat_password_resets[0];
  assert.equal(row.code_hash.includes(sentMails[0].code), false, 'کد خام در دیتابیس ذخیره نمیشود');
  assert.equal(row.used_at, undefined);

  const r2 = await call('forgot-verify', { email: 'alice_test@example.com', code: sentMails[0].code });
  assert.equal(r2.status, 200);
  assert.equal(r2.json.verified, true);
  assert.match(r2.json.resetToken, /^[0-9a-f]{64}$/);
  assert.ok(row.used_at, 'کد بلافاصله مصرف شد');

  const r3 = await call('forgot-reset', {
    email: 'alice_test@example.com',
    resetToken: r2.json.resetToken,
    newPassword: 'BrandNewPassword!99',
  });
  assert.equal(r3.status, 200);
  assert.equal(r3.json.reset, true);
  assert.equal(r3.json.sessionsRevoked, true);

  const user = sb.tables.mimchat_users[0];
  assert.equal(fp.verifyPassword('OldPass!123', user.password_hash, user.password_salt), false);
  assert.equal(fp.verifyPassword('BrandNewPassword!99', user.password_hash, user.password_salt), true);
  assert.equal(user.session_epoch, 1, 'session_epoch برای خروج همهٔ نشستها بالا رفت');
  assert.equal(sb.tables.mimchat_sessions[0].revoked, true);
  assert.equal(sb.deleteCalls, 0);
});

await test('تلاش دوباره با همان کد یا همان resetToken رد میشود', async () => {
  const { sentMails, call } = makeHarness();
  await call('forgot-request', { email: 'alice_test@example.com' });
  const code = sentMails[0].code;

  const v1 = await call('forgot-verify', { email: 'alice_test@example.com', code });
  assert.equal(v1.status, 200);
  const v2 = await call('forgot-verify', { email: 'alice_test@example.com', code });
  assert.equal(v2.status, 400);

  const f1 = await call('forgot-reset', {
    email: 'alice_test@example.com',
    resetToken: v1.json.resetToken,
    newPassword: 'PasswordOne123',
  });
  assert.equal(f1.status, 200);
  const f2 = await call('forgot-reset', {
    email: 'alice_test@example.com',
    resetToken: v1.json.resetToken,
    newPassword: 'PasswordTwo123',
  });
  assert.equal(f2.status, 400);
});

await test('مقاومت در برابر race condition (دو درخواست موازی همزمان فقط یکی برنده میشود)', async () => {
  const { sentMails, call } = makeHarness();
  await call('forgot-request', { email: 'alice_test@example.com' });
  const v = await call('forgot-verify', { email: 'alice_test@example.com', code: sentMails[0].code });
  assert.equal(v.status, 200);

  const [a, b] = await Promise.all([
    call('forgot-reset', { email: 'alice_test@example.com', resetToken: v.json.resetToken, newPassword: 'RacePassA1' }, '198.51.100.1'),
    call('forgot-reset', { email: 'alice_test@example.com', resetToken: v.json.resetToken, newPassword: 'RacePassB2' }, '198.51.100.2'),
  ]);
  const statuses = [a.status, b.status].sort();
  assert.deepEqual(statuses, [200, 400]);
});

await test('سقف ۵ تلاش اشتباه کد را میسوزاند؛ حتی کد درست بعدی رد میشود', async () => {
  const { sb, sentMails, call } = makeHarness();
  await call('forgot-request', { email: 'alice_test@example.com' });
  const realCode = sentMails[0].code;
  const wrongCode = realCode === '123456' ? '654321' : '123456';

  for (let i = 0; i < 5; i++) {
    const r = await call('forgot-verify', { email: 'alice_test@example.com', code: wrongCode });
    assert.equal(r.status, 400);
  }
  assert.ok(sb.tables.mimchat_password_resets[0].used_at, 'بعد از ۵ خطا سوخت');

  const rRight = await call('forgot-verify', { email: 'alice_test@example.com', code: realCode });
  assert.equal(rRight.status, 400);
});

await test('انقضای کد (۱۰ دقیقه) و انقضای resetToken (۱۵ دقیقه)', async () => {
  const { sentMails, call, advanceMs } = makeHarness();
  await call('forgot-request', { email: 'alice_test@example.com' });
  advanceMs(11 * 60 * 1000);
  const expiredCode = await call('forgot-verify', {
    email: 'alice_test@example.com',
    code: sentMails[0].code,
  });
  assert.equal(expiredCode.status, 400);

  // درخواست جدید بعد از cooldown
  await call('forgot-request', { email: 'alice_test@example.com' });
  const v = await call('forgot-verify', { email: 'alice_test@example.com', code: sentMails[1].code });
  assert.equal(v.status, 200);
  advanceMs(16 * 60 * 1000);
  const expiredTok = await call('forgot-reset', {
    email: 'alice_test@example.com',
    resetToken: v.json.resetToken,
    newPassword: 'LatePassword99',
  });
  assert.equal(expiredTok.status, 400);
});

await test('cooldown ۶۰ ثانیه و محدودیت نرخ IP', async () => {
  const { call, advanceMs } = makeHarness();
  const a = await call('forgot-request', { email: 'alice_test@example.com' }, '198.51.100.5');
  assert.equal(a.status, 200);
  const b = await call('forgot-request', { email: 'alice_test@example.com' }, '198.51.100.5');
  assert.equal(b.status, 429);

  advanceMs(61 * 1000);
  for (let i = 0; i < 8; i++) {
    await call('forgot-request', { email: `other${i}@example.com` }, '198.51.100.5');
  }
  const overIp = await call('forgot-request', { email: 'another@example.com' }, '198.51.100.5');
  assert.equal(overIp.status, 429);
});

await test('اگر ارسال ایمیل شکست بخورد، کد با PATCH باطل میشود (۵۰۲ و صفر DELETE)', async () => {
  const { sb, call } = makeHarness({ mailFail: true });
  const r = await call('forgot-request', { email: 'alice_test@example.com' });
  assert.equal(r.status, 502);
  assert.equal(sb.tables.mimchat_password_resets.length, 1);
  assert.ok(sb.tables.mimchat_password_resets[0].used_at, 'کد غیرقابلارسال فوراً باطل شد');
  assert.equal(sb.deleteCalls, 0);
});

await test('توکن یک ایمیل روی ایمیل دیگر کار نمیکند و رمز کوتاه رد میشود', async () => {
  const { sb, sentMails, call } = makeHarness();
  const bobPass = fp.hashPassword('BobSecret1');
  sb.tables.mimchat_users.push({
    id: 'u_bob02',
    username: 'bob',
    email: 'bob@example.com',
    password_hash: bobPass.hashHex,
    password_salt: bobPass.saltHex,
    session_epoch: 0,
  });

  await call('forgot-request', { email: 'alice_test@example.com' });
  const v = await call('forgot-verify', { email: 'alice_test@example.com', code: sentMails[0].code });
  assert.equal(v.status, 200);

  const cross = await call('forgot-reset', {
    email: 'bob@example.com',
    resetToken: v.json.resetToken,
    newPassword: 'HackedPassword!',
  });
  assert.equal(cross.status, 400);
  assert.equal(fp.verifyPassword('BobSecret1', sb.tables.mimchat_users[1].password_hash, sb.tables.mimchat_users[1].password_salt), true);

  const shortPw = await call('forgot-reset', {
    email: 'alice_test@example.com',
    resetToken: v.json.resetToken,
    newPassword: '123',
  });
  assert.equal(shortPw.status, 400);
});

await test('ویجت کلاینت: روی DOM سوار میشود، ۳ مرحله را طی میکند و با restore برمیگردد', async () => {
  const doc = makeMockDocument();
  const { sentMails, call } = makeHarness();
  doc.getElementById('lUser').value = 'Alice_Test@Example.com';

  const ctrl = createForgotPasswordController({
    document: doc,
    apiFn: async (url, opts) => {
      const action = new URLSearchParams(url.split('?')[1]).get('action');
      const r = await call(action, opts.body);
      return { ok: r.status >= 200 && r.status < 300, status: r.status, data: r.json };
    },
  });

  assert.equal(ctrl.mount(), true);
  assert.ok(doc.getElementById('mcForgotOpenBtn1'));
  assert.ok(doc.getElementById('mcForgotOpenBtn2'));

  ctrl.open();
  assert.equal(doc.getElementById('mcFpEmail').value, 'Alice_Test@Example.com');
  await ctrl.requestCode(false);
  assert.equal(ctrl.getState().step, 2);
  assert.equal(sentMails.length, 1);

  doc.getElementById('mcFpCode').value = sentMails[0].code;
  await ctrl.verifyCode();
  assert.equal(ctrl.getState().step, 3);
  assert.equal(ctrl.getState().hasResetToken, true);
  assert.equal(doc.getElementById('mcFpCode').value, '', 'فیلد کد پاک شد');

  doc.getElementById('mcFpPass1').value = 'NewClientPass!7';
  doc.getElementById('mcFpPass2').value = 'NewClientPass!7';
  await ctrl.submitReset();
  assert.equal(ctrl.getState().hasResetToken, false, 'resetToken بعد از ثبت پاک شد');
  assert.equal(doc.getElementById('mcFpPass1').value, '');
  assert.equal(doc.getElementById('mcFpPass2').value, '');
  assert.equal(doc.getElementById('mcForgotBox').style.display, 'none');

  ctrl.restore();
  assert.equal(doc.getElementById('mcForgotBox'), null);
  assert.equal(doc.getElementById('mcForgotOpenBtn1'), null);
});

await test('سورس ماژول و SQL هیچ DELETE/DROP/TRUNCATE/ورسل/راز/CJK ندارد', async () => {
  const sql = await fs.readFile(path.join(ROOT, 'sql', '001_password_resets_additive.sql'), 'utf8');
  const srv = await fs.readFile(path.join(ROOT, 'server', 'forgot-password.cjs'), 'utf8');
  const cli = await fs.readFile(path.join(ROOT, 'client', 'forgot-password.js'), 'utf8');
  const doc = await fs.readFile(path.join(ROOT, '..', 'docs', 'FORGOT-PASSWORD.md'), 'utf8');

  assert.equal(/\b(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE\s+\S+\s+DROP)\b/i.test(sql), false);
  assert.equal(srv.includes('api.vercel.com'), false);
  assert.equal(cli.includes('SUPABASE_SERVICE_ROLE_KEY'), false);
  assert.equal(cli.includes('OTP_HMAC_SECRET'), false);
  assert.equal(cli.includes('localStorage'), false);

  const all = [sql, srv, cli, doc].join('\n');
  assert.equal(/[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\uff0c]/.test(all), false);
});

console.log(`\n${passed} تست قابلیت «فراموشی رمز عبور» سبز شد (کاملاً آفلاین، صفر DELETE، صفر ارسال زنده).`);
if (process.exitCode) process.exit(process.exitCode);
