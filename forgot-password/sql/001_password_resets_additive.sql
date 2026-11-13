-- ============================================================================
-- MemeChat — قابلیت «فراموشی رمز عبور» (فقط الحاقی / بدون هیچ حذف)
--
-- قانون عدم حذف داده:
--   - هیچ DROP / DELETE / TRUNCATE / ALTER COLUMN وجود ندارد.
--   - کدها و توکنهای منقضی یا مصرفشده با پر کردن `used_at` / `reset_used_at`
--     باطل میشوند، نه با حذف ردیف.
--   - جدول جدید و جدا از `mimchat_email_verifications` است تا هیچ توکن
--     ثبتنامی نتواند برای بازیابی رمز استفاده شود (و برعکس).
-- ============================================================================

create extension if not exists pgcrypto;

create table if not exists public.mimchat_password_resets (
  id                uuid primary key default gen_random_uuid(),
  user_id           text not null,
  email             text not null,
  code_hash         text not null,
  nonce             text not null,
  expires_at        timestamptz not null,
  attempts          integer not null default 0,
  max_attempts      integer not null default 5,
  used_at           timestamptz,
  reset_token_hash  text,
  reset_expires_at  timestamptz,
  reset_used_at     timestamptz,
  mail_message_id   text,
  ip_hash           text,
  created_at        timestamptz not null default now()
);

create index if not exists idx_mimchat_pw_resets_email
  on public.mimchat_password_resets (email, created_at desc);

create index if not exists idx_mimchat_pw_resets_token
  on public.mimchat_password_resets (reset_token_hash)
  where reset_token_hash is not null;

-- دسترسی مستقیم کلاینت (anon / authenticated) کاملاً بسته است؛
-- فقط بکاند امن با SERVICE_ROLE_KEY به این جدول دسترسی دارد.
alter table public.mimchat_password_resets enable row level security;
revoke all on public.mimchat_password_resets from anon, authenticated;

select 'memechat forgot-password additive table ready; zero delete; rls enabled' as status;
