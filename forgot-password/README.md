# `forgot-password` — قابلیت «فراموشی رمز عبور» برای میمچت

افزودنی، بدون تغییر سایت زنده، بدون تغییر دیتابیس اصلی بدون اجازه،
بدون `DELETE` و بدون افشای رمز.

```text
forgot-password/
├── sql/001_password_resets_additive.sql   جدول الحاقی + RLS (صفر DELETE/DROP)
├── server/forgot-password.cjs             ۳ مسیر API: forgot-request / forgot-verify / forgot-reset
├── client/forgot-password.js              ویجت ورود (CSP-safe، فقط 'self')
├── tests/run.mjs                          ۱۴ تست آفلاین
├── package.json
└── README.md
```

## خلاصهٔ جریان امن

1. **`forgot-request`:** ایمیل نرمال میشود؛ محدودیت نرخ IP و cooldown ۶۰ ثانیه
   چک میشوند؛ اگر سرویس ارسال ایمیل روی سرور فعال نباشد با `503 MAIL_NOT_CONFIGURED`
   متوقف میشود (**بدون دور زدن تأیید**). برای ایمیلهای موجود یک کد ۶ رقمی
   CSPRNG تولید و فقط هش `HMAC-SHA256` آن در `mimchat_password_resets` ذخیره
   میشود؛ پاسخ HTTP برای ایمیل موجود و ناموجود یکسان است (anti-enumeration).
2. **`forgot-verify`:** کد ۶ رقمی با `timingSafeEqual`، سقف ۵ تلاش و انقضای
   ۱۰ دقیقه بررسی میشود؛ پس از تأیید، کد با `PATCH` شرطی اتمیک مصرف و یک
   `resetToken` یکبارمصرف ۱۵ دقیقهای صادر میشود.
3. **`forgot-reset`:** `resetToken` یکبارمصرف پیش از تغییر رمز بهصورت اتمیک
   باطل میشود؛ رمز جدید با `scrypt` (`salt` تصادفی ۱۶ بایتی + ۶۴ بایت خروجی،
   سازگار با میمچت) هش میشود؛ `session_epoch` کاربر +۱ و `mimchat_sessions`
   با `revoked: true` بسته میشوند.

## اجرا (آفلاین)

```bash
cd /home/user/memechat/forgot-password
npm test
```

## نکتهٔ مهم دربارهٔ رمز خام

در میمچت رمز عبور اصلاً خام ذخیره نمیشود (`scrypt` یکطرفه است). هیچ رمز
خام یا هشی خوانده، دیهش یا برگردانده نمیشود.

سند کامل و راهنمای اتصال: [`../docs/FORGOT-PASSWORD.md`](../docs/FORGOT-PASSWORD.md).
