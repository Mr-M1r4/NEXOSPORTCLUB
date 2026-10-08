-- Production hardening: prevent staff-role deletion of financial and historical records.
-- Apply through reviewed migrations; this file does not modify a live database by itself.
-- Existing permissive policies may allow staff deletes. A restrictive policy is ANDed
-- with permissive policies, so staff cannot bypass this guard through another DELETE policy.
do $$
declare
  t text;
  policy_name text;
begin
  foreach t in array array[
    'payments',
    'sales',
    'sale_items',
    'inventory_movements',
    'staff_payments',
    'memberships'
  ] loop
    if to_regclass(format('public.%I', t)) is null then
      raise exception 'Required table public.% is missing; refusing partial hardening', t;
    end if;
    policy_name := t || '_delete_owner_admin_only';
    execute format('drop policy if exists %I on public.%I', policy_name, t);
    execute format(
      'create policy %I on public.%I as restrictive for delete to authenticated using (private.current_role() in (''owner'', ''admin''))',
      policy_name, t
    );
  end loop;

  if to_regclass('public.audit_logs') is not null then
    drop policy if exists audit_logs_no_delete on public.audit_logs;
    create policy audit_logs_no_delete on public.audit_logs
      as restrictive for delete to authenticated using (false);
  end if;
end
$$;
