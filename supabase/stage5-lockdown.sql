-- 5단계 제작 2: 검토 후 Supabase SQL Editor에서 전체를 실행하세요.
-- 적용 전 배포 화면에서 A의 메모 조회·추가·수정·삭제가 되는지 확인하세요.
-- public.notes 테이블의 직접 접근 권한만 회수합니다.
-- 메모, 소유자, RLS 정책, Auth, service_role, 다른 테이블은 변경하지 않습니다.

begin;

-- 적용 전 명시적 권한
select 'before' as phase, grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

-- 적용 전 실제 권한(상속 권한 포함)
select 'before' as phase, r.role_name, p.privilege,
  has_table_privilege(r.role_name, 'public.notes', p.privilege) as allowed
from (values ('anon'), ('authenticated'), ('service_role')) r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER'), ('MAINTAIN')) p(privilege)
order by r.role_name, p.privilege;

revoke all on table public.notes from PUBLIC, anon, authenticated;

-- 의도한 차단과 서버 권한 유지가 확인되지 않으면 전체 변경을 취소합니다.
do $$
declare
  role_name text;
  privilege_name text;
begin
  foreach role_name in array array['anon', 'authenticated'] loop
    foreach privilege_name in array array['SELECT', 'INSERT', 'UPDATE', 'DELETE',
                                          'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'] loop
      if has_table_privilege(role_name, 'public.notes', privilege_name) then
        raise exception 'Direct access privilege remains: % %', role_name, privilege_name;
      end if;
    end loop;
    -- 테이블 권한과 별개인 열 단위 GRANT가 남아 있어도 중단합니다.
    foreach privilege_name in array array['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'] loop
      if has_any_column_privilege(role_name, 'public.notes', privilege_name) then
        raise exception 'Column privilege remains: % %', role_name, privilege_name;
      end if;
    end loop;
  end loop;
  foreach privilege_name in array array['SELECT', 'INSERT', 'UPDATE', 'DELETE'] loop
    if not has_table_privilege('service_role', 'public.notes', privilege_name) then
      raise exception 'Required server privilege missing: %', privilege_name;
    end if;
  end loop;
  if not (select relrowsecurity from pg_class where oid = 'public.notes'::regclass) then
    raise exception 'Expected existing RLS protection is disabled.';
  end if;
end $$;

commit;

-- 마지막 결과: anon/authenticated는 전부 false,
-- service_role의 SELECT/INSERT/UPDATE/DELETE는 true, rls_enabled는 true여야 합니다.
select
  'after' as phase,
  (select relrowsecurity from pg_class where oid = 'public.notes'::regclass) as rls_enabled,
  coalesce((
    select jsonb_agg(to_jsonb(g) order by g.grantee, g.privilege_type)
    from (
      select grantee, privilege_type, is_grantable
      from information_schema.role_table_grants
      where table_schema = 'public' and table_name = 'notes'
        and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
    ) g
  ), '[]'::jsonb) as table_grants,
  (
    select jsonb_agg(to_jsonb(e) order by e.role_name, e.privilege)
    from (
      select r.role_name, p.privilege,
        has_table_privilege(r.role_name, 'public.notes', p.privilege) as allowed
      from (values ('anon'), ('authenticated'), ('service_role')) r(role_name)
      cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                         ('TRUNCATE'), ('REFERENCES'), ('TRIGGER'), ('MAINTAIN')) p(privilege)
    ) e
  ) as effective_privileges;

-- 적용 후 A/B 각자의 서버 API CRUD는 계속 동작해야 합니다.
-- B의 A 메모 접근과 무로그인 서버 API 접근은 계속 거부되어야 합니다.
-- 원본 Data API에는 로그인 사용자 토큰이 있어도 자료 권한이 없습니다.
