-- 2단계 학습 DB의 구조와 권한만 재현합니다. 메모 본문과 실제 키는 포함하지 않습니다.
-- 새 학습용 프로젝트의 SQL Editor에서 실행합니다. 기존 가상 메모는 보존합니다.
begin;

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid,
  position integer not null unique check (position > 0),
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

-- owner_id는 다음 단계에서 사용합니다. auth.users 외래키는 아직 걸지 않습니다.
alter table public.notes enable row level security;
revoke all privileges on table public.notes from public, anon, authenticated;
grant usage on schema public to service_role;
grant select on table public.notes to service_role;

-- 자동 RLS 기능을 켠 프로젝트에서 공개 RPC 실행만 제한합니다.
do $$
begin
  if to_regprocedure('public.rls_auto_enable()') is not null then
    revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
  end if;
end $$;

commit;
