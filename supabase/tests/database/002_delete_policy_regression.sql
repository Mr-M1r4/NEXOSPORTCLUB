-- Regression checks for the restrictive DELETE policy migration.
-- Run after applying the production-hardening migration on a disposable/test database.
do $$
declare
  t text;
  policy_name text;
  policy_row record;
begin
  foreach t in array array[
    'payments',
    'sales',
    'sale_items',
    'inventory_movements',
    'staff_payments',
    'memberships'
  ] loop
    policy_name := t || '_delete_owner_admin_only';
    select permissive, cmd, roles, qual into policy_row
    from pg_policies
    where schemaname = 'public' and tablename = t and policyname = policy_name;

    if not found then
      raise exception 'Missing restrictive delete guard for public.%', t;
    end if;
    if policy_row.permissive <> 'RESTRICTIVE' or policy_row.cmd <> 'DELETE'
       or not ('authenticated' = any(policy_row.roles))
       or policy_row.qual not like '%owner%' or policy_row.qual not like '%admin%' then
      raise exception 'Unexpected restrictive delete guard definition for public.%: %', t, row_to_json(policy_row);
    end if;
  end loop;

  if to_regclass('public.audit_logs') is not null then
    if not exists (
      select 1 from pg_policies
      where schemaname='public' and tablename='audit_logs'
        and policyname='audit_logs_no_delete'
        and permissive='RESTRICTIVE' and cmd='DELETE'
        and qual='false'
    ) then
      raise exception 'Audit log deletion must be blocked for authenticated users';
    end if;
  end if;
end
$$;
