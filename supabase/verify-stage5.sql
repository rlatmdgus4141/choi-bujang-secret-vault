-- 읽기 전용 확인: 메모 내용·계정 ID·키는 출력하지 않습니다.
-- Supabase SQL Editor에서 실행합니다. 권한이나 자료를 변경하지 않습니다.
with role_names(role_name) as (
  values ('anon'), ('authenticated'), ('service_role')
), table_permissions as (
  select r.role_name, p.privilege,
    has_table_privilege(r.role_name, 'public.notes', p.privilege) as allowed
  from role_names r
  cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                     ('TRUNCATE'), ('REFERENCES'), ('TRIGGER'), ('MAINTAIN')) p(privilege)
), column_permissions as (
  select r.role_name, p.privilege,
    has_any_column_privilege(r.role_name, 'public.notes', p.privilege) as allowed
  from role_names r
  cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) p(privilege)
), facts as (
  select
    (select relrowsecurity from pg_class where oid = 'public.notes'::regclass) as rls_enabled,
    not exists (
      select 1 from table_permissions
      where role_name in ('anon', 'authenticated') and allowed
    ) as direct_table_access_blocked,
    not exists (
      select 1 from column_permissions
      where role_name in ('anon', 'authenticated') and allowed
    ) as direct_column_access_blocked,
    (select bool_and(allowed) from table_permissions
      where role_name = 'service_role' and privilege in ('SELECT','INSERT','UPDATE','DELETE'))
      as server_crud_available,
    not exists (
      select 1 from information_schema.role_table_grants
      where table_schema = 'public' and table_name = 'notes'
        and grantee in ('PUBLIC', 'anon', 'authenticated')
    ) as direct_grants_absent
)
select
  (rls_enabled and direct_table_access_blocked and direct_column_access_blocked
    and server_crud_available and direct_grants_absent) as stage5_permissions_ok,
  facts.*,
  (select count(*) from public.notes) as note_count,
  (select count(*) from pg_policies where schemaname='public' and tablename='notes') as policy_count,
  (select jsonb_agg(to_jsonb(t) order by t.role_name,t.privilege) from table_permissions t)
    as effective_table_privileges,
  (select jsonb_agg(to_jsonb(c) order by c.role_name,c.privilege) from column_permissions c)
    as effective_column_privileges
from facts;
