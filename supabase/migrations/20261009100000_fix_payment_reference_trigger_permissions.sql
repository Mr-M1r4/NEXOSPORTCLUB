-- Fix payment-reference trigger permissions without exposing the helper RPC.
-- The helper remains non-executable by API roles; the trigger wrapper runs with
-- its owner's privileges and has a fixed search_path.
create or replace function private.set_payment_reference()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, private, extensions
as $function$
begin
  if TG_TABLE_NAME = 'payments' then
    NEW.reference := private.generate_payment_reference('PAY');
  elsif TG_TABLE_NAME = 'staff_payments' then
    NEW.reference := private.generate_payment_reference('STP');
  elsif TG_TABLE_NAME = 'saas_payments' then
    NEW.reference := private.generate_payment_reference('SaaS');
  end if;
  return NEW;
end
$function$;

-- Trigger functions are not meant to be called directly by API clients.
revoke all on function private.set_payment_reference() from public, anon, authenticated;
revoke all on function private.generate_payment_reference(text) from public, anon, authenticated;

comment on function private.set_payment_reference() is
  'SECURITY DEFINER trigger wrapper for automatic payment references; fixed search_path; not directly executable by API roles.';
comment on function private.generate_payment_reference(text) is
  'Internal helper used only by the payment-reference trigger wrapper.';
