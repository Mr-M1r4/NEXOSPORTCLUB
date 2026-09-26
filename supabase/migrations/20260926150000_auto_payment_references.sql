-- Generate payment references server-side so users never need to enter them manually.
create or replace function private.generate_payment_reference(p_prefix text)
returns text
language plpgsql
as $$
begin
  return upper(coalesce(nullif(trim(p_prefix),''),'PAY')) || '-' ||
         to_char(current_date,'YYYYMMDD') || '-' ||
         upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
end
$$;

create or replace function private.set_payment_reference()
returns trigger
language plpgsql
as $$
begin
  if TG_TABLE_NAME = 'payments' then
    NEW.reference := private.generate_payment_reference('PAY');
  elsif TG_TABLE_NAME = 'staff_payments' then
    NEW.reference := private.generate_payment_reference('STP');
  elsif TG_TABLE_NAME = 'saas_payments' then
    NEW.reference := private.generate_payment_reference('SAAS');
  end if;
  return NEW;
end
$$;

drop trigger if exists payments_auto_reference on public.payments;
create trigger payments_auto_reference
before insert on public.payments
for each row execute function private.set_payment_reference();

drop trigger if exists staff_payments_auto_reference on public.staff_payments;
create trigger staff_payments_auto_reference
before insert on public.staff_payments
for each row execute function private.set_payment_reference();

drop trigger if exists saas_payments_auto_reference on public.saas_payments;
create trigger saas_payments_auto_reference
before insert on public.saas_payments
for each row execute function private.set_payment_reference();

create unique index if not exists payments_reference_unique_idx
  on public.payments(reference) where reference is not null;

create unique index if not exists staff_payments_reference_unique_idx
  on public.staff_payments(reference) where reference is not null;

create unique index if not exists saas_payments_reference_unique_idx
  on public.saas_payments(reference) where reference is not null;
