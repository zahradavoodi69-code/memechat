/* MemeChat — ویجت افزودنی «فراموشی رمز عبور» برای صفحهٔ ورود (CSP-safe)
 *
 * نحوهٔ کار:
 *   - با یک خط `<script src="./forgot-password/forgot-password.js"></script>`
 *     بدون تغییر CSP یا پاک کردن منطق ورود قبلی روی `#boxLog` سوار میشود.
 *   - هیچ کلید، توکن ثابت یا ذخیرهسازی رمز در مرورگر ندارد.
 *   - `resetToken` فقط در حافظهٔ موقت همین فرم نگه داشته میشود و بلافاصله پس از
 *     بازگشت یا تغییر رمز پاک میشود.
 */

(function (global) {
  "use strict";

  var STYLE_ID = "mcForgotStyle";
  var BOX_ID = "mcForgotBox";
  var BTN1_ID = "mcForgotOpenBtn1";
  var BTN2_ID = "mcForgotOpenBtn2";

  var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  var CODE_RE = /^\d{6}$/;

  function createForgotPasswordController(options) {
    options = options || {};
    var doc = options.document || global.document;
    var state = {
      mounted: false,
      step: 1,
      email: "",
      resetToken: "",
      busy: false,
      cleanups: [],
    };

    function byId(id) {
      return doc ? doc.getElementById(id) : null;
    }

    function callApi(path, body) {
      if (typeof options.apiFn === "function") {
        return options.apiFn(path, { method: "POST", body: body });
      }
      if (typeof global.api === "function") {
        return global.api(path, { method: "POST", body: body });
      }
      var fetchFn = options.fetchFn || global.fetch;
      if (typeof fetchFn !== "function") {
        return Promise.resolve({ ok: false, status: 0, data: { error: "ابزار شبکه در دسترس نیست." } });
      }
      var base = String(global.MC_API || "");
      return fetchFn(base + path, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body || {}),
      })
        .then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (d) {
            return { ok: !!r.ok, status: r.status || 0, data: d };
          });
        })
        .catch(function () {
          return { ok: false, status: 0, data: { error: "شبکه پاسخ نداد." } };
        });
    }

    function setStatus(text, kind) {
      var el = byId("mcFpStatus");
      if (!el) return;
      el.textContent = text || "";
      el.style.display = text ? "block" : "none";
      if (kind === "ok") {
        el.style.color = "var(--ok, #2ecc71)";
        el.style.borderColor = "rgba(46, 204, 113, .35)";
      } else if (kind === "err") {
        el.style.color = "var(--danger, #e74c3c)";
        el.style.borderColor = "rgba(231, 76, 60, .4)";
      } else {
        el.style.color = "var(--muted, #9b938a)";
        el.style.borderColor = "#3d3428";
      }
    }

    function clearSensitiveInputs() {
      state.resetToken = "";
      ["mcFpCode", "mcFpPass1", "mcFpPass2"].forEach(function (id) {
        var inp = byId(id);
        if (inp) inp.value = "";
      });
    }

    function setStep(step) {
      state.step = step;
      var s1 = byId("mcFpStep1");
      var s2 = byId("mcFpStep2");
      var s3 = byId("mcFpStep3");
      if (s1) s1.style.display = step === 1 ? "block" : "none";
      if (s2) s2.style.display = step === 2 ? "block" : "none";
      if (s3) s3.style.display = step === 3 ? "block" : "none";
    }

    function setBusy(busy) {
      state.busy = !!busy;
      ["mcFpSendBtn", "mcFpVerifyBtn", "mcFpResendBtn", "mcFpSaveBtn"].forEach(function (id) {
        var b = byId(id);
        if (b) b.disabled = !!busy;
      });
    }

    function open() {
      if (!state.mounted) mount();
      var box = byId(BOX_ID);
      var ls1 = byId("logStep1");
      var ls2 = byId("logStep2");
      var lUser = byId("lUser");
      var fpEmail = byId("mcFpEmail");
      if (ls1) ls1.style.display = "none";
      if (ls2) ls2.style.display = "none";
      if (box) box.style.display = "block";
      clearSensitiveInputs();
      state.email = "";
      setStep(1);
      setStatus("", "");
      if (typeof global.note === "function") global.note("");
      if (fpEmail && lUser && EMAIL_RE.test(String(lUser.value || "").trim())) {
        fpEmail.value = String(lUser.value || "").trim();
      }
      if (fpEmail && typeof fpEmail.focus === "function") {
        try { fpEmail.focus(); } catch (e) {}
      }
    }

    function close(opts) {
      opts = opts || {};
      clearSensitiveInputs();
      state.email = "";
      var box = byId(BOX_ID);
      var ls1 = byId("logStep1");
      var ls2 = byId("logStep2");
      if (box) box.style.display = "none";
      if (ls2) ls2.style.display = "none";
      if (ls1) ls1.style.display = "block";
      setStatus("", "");
      if (opts.notice && typeof global.note === "function") {
        global.note(opts.notice, !!opts.isError);
      }
    }

    async function requestCode(isResend) {
      if (state.busy) return;
      var inp = byId("mcFpEmail");
      var raw = isResend && state.email ? state.email : (inp ? inp.value : "");
      var email = String(raw || "").trim().toLowerCase();
      if (!EMAIL_RE.test(email)) {
        setStatus("لطفاً یک آدرس ایمیل معتبر وارد کنید.", "err");
        return;
      }
      setBusy(true);
      setStatus("در حال بررسی و ارسال کد بازیابی...", "");
      var r = await callApi("/api/auth?action=forgot-request", { email: email });
      setBusy(false);
      if (!r.ok || !r.data || !r.data.success) {
        setStatus((r.data && r.data.error) || "ارسال کد بازیابی انجام نشد.", "err");
        return;
      }
      state.email = email;
      var hint = byId("mcFpCodeHint");
      if (hint) {
        hint.textContent = "کد ۶ رقمی (در صورت ثبت بودن ایمیل) برای " + email + " ارسال شد.";
      }
      setStep(2);
      setStatus(r.data.message || "کد ۶ رقمی ارسال شد.", "ok");
      var codeEl = byId("mcFpCode");
      if (codeEl && typeof codeEl.focus === "function") {
        try { codeEl.focus(); } catch (e) {}
      }
    }

    async function verifyCode() {
      if (state.busy) return;
      var codeEl = byId("mcFpCode");
      var code = String(codeEl ? codeEl.value : "").trim();
      if (!state.email || !EMAIL_RE.test(state.email)) {
        setStep(1);
        setStatus("ابتدا ایمیل را وارد کنید.", "err");
        return;
      }
      if (!CODE_RE.test(code)) {
        setStatus("کد تأیید باید دقیقاً ۶ رقم انگلیسی باشد.", "err");
        return;
      }
      setBusy(true);
      setStatus("در حال بررسی کد...", "");
      var r = await callApi("/api/auth?action=forgot-verify", {
        email: state.email,
        code: code,
      });
      if (codeEl) codeEl.value = "";
      setBusy(false);
      if (!r.ok || !r.data || !r.data.success || !r.data.resetToken) {
        setStatus((r.data && r.data.error) || "کد واردشده نادرست یا منقضی است.", "err");
        return;
      }
      state.resetToken = String(r.data.resetToken);
      setStep(3);
      setStatus("کد تأیید شد. رمز عبور جدید را وارد کنید.", "ok");
      var p1 = byId("mcFpPass1");
      if (p1 && typeof p1.focus === "function") {
        try { p1.focus(); } catch (e) {}
      }
    }

    async function submitReset() {
      if (state.busy) return;
      var p1El = byId("mcFpPass1");
      var p2El = byId("mcFpPass2");
      var p1 = p1El ? String(p1El.value || "") : "";
      var p2 = p2El ? String(p2El.value || "") : "";
      if (!state.email || !state.resetToken) {
        setStep(1);
        setStatus("نشست بازیابی منقضی شده است؛ دوباره درخواست کد بدهید.", "err");
        return;
      }
      if (p1.length < 6 || p1.length > 64) {
        setStatus("رمز جدید باید بین ۶ تا ۶۴ نویسه باشد.", "err");
        return;
      }
      if (p1 !== p2) {
        setStatus("رمز جدید و تکرار آن یکسان نیستند.", "err");
        return;
      }
      setBusy(true);
      setStatus("در حال ثبت رمز عبور جدید...", "");
      var payload = {
        email: state.email,
        resetToken: state.resetToken,
        newPassword: p1,
      };
      if (p1El) p1El.value = "";
      if (p2El) p2El.value = "";
      var r = await callApi("/api/auth?action=forgot-reset", payload);
      setBusy(false);
      if (!r.ok || !r.data || !r.data.success) {
        setStatus((r.data && r.data.error) || "تغییر رمز انجام نشد.", "err");
        return;
      }
      var savedEmail = state.email;
      var lUser = byId("lUser");
      if (lUser) lUser.value = savedEmail;
      close({
        notice: r.data.message || "رمز عبور جدید ثبت شد. اکنون وارد شوید.",
        isError: false,
      });
    }

    function injectStyles() {
      if (!doc || !doc.head || byId(STYLE_ID)) return;
      var st = doc.createElement("style");
      st.id = STYLE_ID;
      st.textContent =
        "#" + BOX_ID + "{display:none;width:100%;max-width:320px;padding:14px;border-radius:14px;" +
        "background:rgba(255,140,0,.05);border:1px solid #3d3428;text-align:right;margin-top:4px}" +
        "#" + BOX_ID + " .mcFpTitle{color:var(--gold,#ffb347);font-size:.96rem;font-weight:bold;margin-bottom:6px;text-align:center}" +
        "#" + BOX_ID + " .mcFpHint{color:var(--muted,#9b938a);font-size:.78rem;line-height:1.65;margin-bottom:10px}" +
        "#mcFpStatus{display:none;font-size:.78rem;line-height:1.6;padding:8px 10px;border-radius:10px;" +
        "border:1px solid #3d3428;background:rgba(255,255,255,.03);margin-bottom:10px}" +
        ".mcFpLinkBtn{width:100%;max-width:320px;margin-top:8px;padding:10px 12px;border-radius:10px;" +
        "background:transparent;color:var(--gold,#ffb347);border:1px dashed rgba(255,179,71,.38);" +
        "font-size:.86rem;cursor:pointer}";
      doc.head.appendChild(st);
    }

    function on(el, ev, fn) {
      if (!el || typeof el.addEventListener !== "function") return;
      el.addEventListener(ev, fn);
      state.cleanups.push(function () {
        if (typeof el.removeEventListener === "function") el.removeEventListener(ev, fn);
      });
    }

    function mount() {
      if (state.mounted || !doc) return false;
      var boxLog = byId("boxLog");
      if (!boxLog) return false;

      injectStyles();

      var ls1 = byId("logStep1");
      if (ls1 && !byId(BTN1_ID)) {
        var b1 = doc.createElement("button");
        b1.type = "button";
        b1.id = BTN1_ID;
        b1.className = "mcFpLinkBtn";
        b1.textContent = "فراموشی رمز عبور";
        on(b1, "click", open);
        ls1.appendChild(b1);
      }

      var ls2 = byId("logStep2");
      if (ls2 && !byId(BTN2_ID)) {
        var b2 = doc.createElement("button");
        b2.type = "button";
        b2.id = BTN2_ID;
        b2.className = "mcFpLinkBtn";
        b2.textContent = "رمزت یادت رفته؟ بازیابی با ایمیل";
        on(b2, "click", open);
        ls2.appendChild(b2);
      }

      if (!byId(BOX_ID)) {
        var box = doc.createElement("div");
        box.id = BOX_ID;
        box.setAttribute("dir", "rtl");
        box.innerHTML =
          '<div class="mcFpTitle">بازیابی رمز عبور</div>' +
          '<div id="mcFpStatus"></div>' +
          '<div id="mcFpStep1">' +
            '<div class="mcFpHint">ایمیل ثبتشدهٔ حسابت را وارد کن تا کد ۶ رقمی بازیابی ارسال شود.</div>' +
            '<input id="mcFpEmail" type="email" inputmode="email" maxlength="254" autocomplete="email" placeholder="ایمیل حساب">' +
            '<button type="button" class="main" id="mcFpSendBtn">ارسال کد بازیابی</button>' +
          "</div>" +
          '<div id="mcFpStep2" style="display:none">' +
            '<div class="mcFpHint" id="mcFpCodeHint">کد ۶ رقمی ارسال‌شده به ایمیل را وارد کن.</div>' +
            '<input id="mcFpCode" maxlength="6" inputmode="numeric" autocomplete="one-time-code" placeholder="کد ۶ رقمی" style="text-align:center;letter-spacing:6px;font-weight:bold">' +
            '<button type="button" class="main" id="mcFpVerifyBtn">تأیید کد</button>' +
            '<button type="button" class="main ghost" id="mcFpResendBtn">ارسال دوبارهٔ کد</button>' +
          "</div>" +
          '<div id="mcFpStep3" style="display:none">' +
            '<div class="mcFpHint">رمز جدید (حداقل ۶ نویسه) را انتخاب کن. نشستهای قبلی هم بسته میشوند.</div>' +
            '<input id="mcFpPass1" type="password" maxlength="64" autocomplete="new-password" placeholder="رمز عبور جدید">' +
            '<input id="mcFpPass2" type="password" maxlength="64" autocomplete="new-password" placeholder="تکرار رمز جدید">' +
            '<button type="button" class="main" id="mcFpSaveBtn">ثبت رمز جدید</button>' +
          "</div>" +
          '<button type="button" class="main ghost" id="mcFpBackBtn">بازگشت به ورود</button>';
        boxLog.appendChild(box);

        on(byId("mcFpSendBtn"), "click", function () { requestCode(false); });
        on(byId("mcFpVerifyBtn"), "click", verifyCode);
        on(byId("mcFpResendBtn"), "click", function () { requestCode(true); });
        on(byId("mcFpSaveBtn"), "click", submitReset);
        on(byId("mcFpBackBtn"), "click", function () { close({}); });
        on(byId("mcFpEmail"), "keydown", function (e) { if (e && e.key === "Enter") requestCode(false); });
        on(byId("mcFpCode"), "keydown", function (e) { if (e && e.key === "Enter") verifyCode(); });
        on(byId("mcFpPass2"), "keydown", function (e) { if (e && e.key === "Enter") submitReset(); });
      }

      on(byId("tabReg"), "click", function () {
        if (byId(BOX_ID) && byId(BOX_ID).style.display !== "none") close({});
      });

      state.mounted = true;
      return true;
    }

    function restore() {
      clearSensitiveInputs();
      state.cleanups.forEach(function (fn) { try { fn(); } catch (e) {} });
      state.cleanups = [];
      [BOX_ID, BTN1_ID, BTN2_ID, STYLE_ID].forEach(function (id) {
        var el = byId(id);
        if (el && el.parentNode) el.parentNode.removeChild(el);
      });
      var ls1 = byId("logStep1");
      if (ls1) ls1.style.display = "block";
      state.mounted = false;
    }

    return {
      mount: mount,
      open: open,
      close: close,
      restore: restore,
      requestCode: requestCode,
      verifyCode: verifyCode,
      submitReset: submitReset,
      getState: function () {
        return { mounted: state.mounted, step: state.step, email: state.email, hasResetToken: !!state.resetToken };
      },
    };
  }

  if (typeof global.document !== "undefined") {
    var instance = createForgotPasswordController({ document: global.document });
    global.MemeChatForgotPassword = instance;
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", function () { instance.mount(); });
    } else {
      instance.mount();
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createForgotPasswordController: createForgotPasswordController };
  }
})(typeof window !== "undefined" ? window : globalThis);
