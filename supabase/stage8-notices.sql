-- Separate resource; does not modify notes, user accounts or instructor memberships.
create table public.notices (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(btrim(title)) between 1 and 200),
  content text not null check (char_length(content) <= 20000),
  updated_by uuid not null,
  updated_at timestamptz not null default now()
);
alter table public.notices enable row level security;
revoke all on table public.notices from PUBLIC, anon, authenticated, service_role;
grant select, insert, update on table public.notices to service_role;
-- No user-facing policies: all access goes through the authenticated application API.
