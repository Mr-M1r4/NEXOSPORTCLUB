-- Security hardening: prevent permissive-policy cross-tenant access,
-- enforce least-privilege anonymous access, and validate related IDs in RPCs.
-- Applied to production on 2026-10-06.

do $$
declare t text;
begin
  foreach t in array array[
    'athletes','attendance','audit_logs','categories','club_memberships','club_settings','clubs',
    'events','inventory_movements','membership_plans','memberships','notifications','payments',
    'platform_admins','product_variants','products','profiles','registrations','saas_payments',
    'saas_subscriptions','sale_items','sales','staff_members','staff_payments','teams','training_sessions'
  ] loop
    execute format('revoke all on table public.%I from anon',t);
  end loop;
end $$;

drop policy if exists athletes_access on public.athletes;
drop policy if exists attendance_insert on public.attendance;
drop policy if exists attendance_update on public.attendance;
drop policy if exists attendance_delete on public.attendance;
drop policy if exists "attendance delete" on public.attendance;
drop policy if exists "attendance insert" on public.attendance;
drop policy if exists "attendance update" on public.attendance;
drop policy if exists audit_access on public.audit_logs;
drop policy if exists audit_insert on public.audit_logs;
drop policy if exists settings_insert on public.club_settings;
drop policy if exists settings_update on public.club_settings;
drop policy if exists settings_delete on public.club_settings;
drop policy if exists "settings insert" on public.club_settings;
drop policy if exists "settings update" on public.club_settings;
drop policy if exists "settings delete" on public.club_settings;
drop policy if exists inventory_access on public.inventory_movements;
drop policy if exists plans_access on public.membership_plans;
drop policy if exists memberships_access on public.memberships;
drop policy if exists notifications_access on public.notifications;
drop policy if exists payments_access on public.payments;
drop policy if exists variants_access on public.product_variants;
drop policy if exists products_access on public.products;
drop policy if exists registrations_access on public.registrations;
drop policy if exists sale_items_access on public.sale_items;
drop policy if exists sales_access on public.sales;
drop policy if exists staff_access on public.staff_members;
drop policy if exists staff_payments_access on public.staff_payments;
drop policy if exists teams_insert on public.teams;
drop policy if exists teams_update on public.teams;
drop policy if exists teams_delete on public.teams;
drop policy if exists "teams insert" on public.teams;
drop policy if exists "teams update" on public.teams;
drop policy if exists "teams delete" on public.teams;
drop policy if exists sessions_insert on public.training_sessions;
drop policy if exists sessions_update on public.training_sessions;
drop policy if exists sessions_delete on public.training_sessions;
drop policy if exists "sessions insert" on public.training_sessions;
drop policy if exists "sessions update" on public.training_sessions;
drop policy if exists "sessions delete" on public.training_sessions;

-- Explicit tenant + role policies.
drop policy if exists tenant_isolation on public.athletes;
create policy athletes_select on public.athletes for select to authenticated using (club_id=private.current_club_id());
create policy athletes_insert on public.athletes for insert to authenticated with check (club_id=private.current_club_id());
create policy athletes_update on public.athletes for update to authenticated using (club_id=private.current_club_id()) with check (club_id=private.current_club_id());
create policy athletes_delete on public.athletes for delete to authenticated using (club_id=private.current_club_id());

drop policy if exists tenant_isolation on public.attendance;
create policy attendance_select on public.attendance for select to authenticated using (club_id=private.current_club_id());
create policy attendance_insert on public.attendance for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy attendance_update on public.attendance for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy attendance_delete on public.attendance for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.audit_logs;
create policy audit_select on public.audit_logs for select to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy audit_insert on public.audit_logs for insert to authenticated with check (club_id=private.current_club_id() and actor_id=(select auth.uid()));

drop policy if exists tenant_isolation on public.club_settings;
create policy settings_select on public.club_settings for select to authenticated using (club_id=private.current_club_id());
create policy settings_insert on public.club_settings for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy settings_update on public.club_settings for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.events;
drop policy if exists "events tenant delete" on public.events;
drop policy if exists "events tenant insert" on public.events;
drop policy if exists "events tenant select" on public.events;
drop policy if exists "events tenant update" on public.events;
create policy events_select on public.events for select to authenticated using (club_id=private.current_club_id());
create policy events_insert on public.events for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy events_update on public.events for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy events_delete on public.events for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.inventory_movements;
create policy inventory_select on public.inventory_movements for select to authenticated using (club_id=private.current_club_id());
create policy inventory_insert on public.inventory_movements for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy inventory_update on public.inventory_movements for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy inventory_delete on public.inventory_movements for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.membership_plans;
create policy plans_select on public.membership_plans for select to authenticated using (club_id=private.current_club_id());
create policy plans_insert on public.membership_plans for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy plans_update on public.membership_plans for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy plans_delete on public.membership_plans for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.memberships;
create policy memberships_select on public.memberships for select to authenticated using (club_id=private.current_club_id());
create policy memberships_insert on public.memberships for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy memberships_update on public.memberships for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy memberships_delete on public.memberships for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.notifications;
create policy notifications_select on public.notifications for select to authenticated using (club_id=private.current_club_id());
create policy notifications_insert on public.notifications for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy notifications_update on public.notifications for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy notifications_delete on public.notifications for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.payments;
create policy payments_select on public.payments for select to authenticated using (club_id=private.current_club_id());
create policy payments_insert on public.payments for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy payments_update on public.payments for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy payments_delete on public.payments for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.product_variants;
create policy variants_select on public.product_variants for select to authenticated using (club_id=private.current_club_id());
create policy variants_insert on public.product_variants for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy variants_update on public.product_variants for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy variants_delete on public.product_variants for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.products;
create policy products_select on public.products for select to authenticated using (club_id=private.current_club_id());
create policy products_insert on public.products for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy products_update on public.products for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy products_delete on public.products for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.registrations;
create policy registrations_select on public.registrations for select to authenticated using (club_id=private.current_club_id());
create policy registrations_insert on public.registrations for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy registrations_update on public.registrations for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy registrations_delete on public.registrations for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.sale_items;
create policy sale_items_select on public.sale_items for select to authenticated using (club_id=private.current_club_id());
create policy sale_items_insert on public.sale_items for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy sale_items_update on public.sale_items for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy sale_items_delete on public.sale_items for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.sales;
create policy sales_select on public.sales for select to authenticated using (club_id=private.current_club_id());
create policy sales_insert on public.sales for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy sales_update on public.sales for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy sales_delete on public.sales for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

drop policy if exists tenant_isolation on public.staff_members;
create policy staff_select on public.staff_members for select to authenticated using (club_id=private.current_club_id());
create policy staff_insert on public.staff_members for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy staff_update on public.staff_members for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy staff_delete on public.staff_members for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.staff_payments;
create policy staff_payments_select on public.staff_payments for select to authenticated using (club_id=private.current_club_id());
create policy staff_payments_insert on public.staff_payments for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy staff_payments_update on public.staff_payments for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy staff_payments_delete on public.staff_payments for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.teams;
create policy teams_select on public.teams for select to authenticated using (club_id=private.current_club_id());
create policy teams_insert on public.teams for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));
create policy teams_update on public.teams for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin')) with check (club_id=private.current_club_id());
create policy teams_delete on public.teams for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin'));

drop policy if exists tenant_isolation on public.training_sessions;
create policy sessions_select on public.training_sessions for select to authenticated using (club_id=private.current_club_id());
create policy sessions_insert on public.training_sessions for insert to authenticated with check (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));
create policy sessions_update on public.training_sessions for update to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff')) with check (club_id=private.current_club_id());
create policy sessions_delete on public.training_sessions for delete to authenticated using (club_id=private.current_club_id() and private.current_role() in ('owner','admin','staff'));

revoke all on all tables in schema public from anon;
grant select on public.clubs,public.club_memberships,public.profiles,public.platform_admins to authenticated;
grant select,insert,update,delete on public.athletes,public.attendance,public.categories,public.events,public.inventory_movements,public.membership_plans,public.memberships,public.notifications,public.payments,public.product_variants,public.products,public.registrations,public.sale_items,public.sales,public.staff_members,public.staff_payments,public.teams,public.training_sessions to authenticated;
grant select,insert on public.audit_logs to authenticated;
grant select,insert,update on public.club_settings to authenticated;
grant select,insert,update,delete on public.saas_payments,public.saas_subscriptions to authenticated;

create or replace function public.create_registration(p_athlete_id uuid,p_plan_id uuid,p_start_date date,p_registration_amount numeric,p_registration_method text default 'cash',p_membership_method text default 'cash')
returns jsonb language plpgsql set search_path='public','private' as $function$
declare v_reg public.registrations; v_mem public.memberships; v_plan public.membership_plans; v_pay public.payments; v_club uuid:=private.current_club_id();
begin
 if private.current_role() not in ('owner','admin','staff') then raise exception 'not authorized'; end if;
 if not exists(select 1 from public.athletes where id=p_athlete_id and club_id=v_club) then raise exception 'athlete not found in active club'; end if;
 select * into v_plan from public.membership_plans where id=p_plan_id and club_id=v_club and active;
 if not found then raise exception 'plan not found or inactive'; end if;
 if exists(select 1 from public.memberships where athlete_id=p_athlete_id and club_id=v_club and status='active' and end_date>=p_start_date) then raise exception 'athlete already has an active membership'; end if;
 insert into public.registrations(athlete_id,amount,registered_at,payment_status) values(p_athlete_id,greatest(coalesce(p_registration_amount,0),0),p_start_date,'confirmed') returning * into v_reg;
 insert into public.memberships(athlete_id,plan_id,start_date,end_date,status) values(p_athlete_id,p_plan_id,p_start_date,p_start_date+v_plan.duration_days-1,'active') returning * into v_mem;
 if coalesce(p_registration_amount,0)>0 then insert into public.payments(athlete_id,registration_id,concept,amount,method,status,paid_at) values(p_athlete_id,v_reg.id,'registration',p_registration_amount,p_registration_method,'confirmed',now()) returning * into v_pay; end if;
 insert into public.payments(athlete_id,membership_id,concept,amount,method,status,paid_at) values(p_athlete_id,v_mem.id,'membership',v_plan.price,p_membership_method,'confirmed',now());
 insert into public.audit_logs(actor_id,action,entity,entity_id,details) values(auth.uid(),'create','registration',v_reg.id,jsonb_build_object('membership_id',v_mem.id,'athlete_id',p_athlete_id));
 return jsonb_build_object('registration_id',v_reg.id,'membership_id',v_mem.id);
end $function$;

create or replace function public.create_sale(p_athlete_id uuid,p_variant_id uuid,p_quantity integer,p_method text default 'cash',p_reference text default null)
returns jsonb language plpgsql set search_path='public','private' as $function$
declare v_variant public.product_variants; v_sale public.sales; v_payment public.payments; v_total numeric; v_club uuid:=private.current_club_id();
begin
 if private.current_role() not in ('owner','admin','staff') then raise exception 'not authorized'; end if;
 if p_quantity<=0 then raise exception 'quantity invalid'; end if;
 if p_athlete_id is not null and not exists(select 1 from public.athletes where id=p_athlete_id and club_id=v_club) then raise exception 'athlete not found in active club'; end if;
 select * into v_variant from public.product_variants where id=p_variant_id and club_id=v_club for update;
 if not found then raise exception 'variant not found'; end if;
 if v_variant.stock<p_quantity then raise exception 'insufficient stock'; end if;
 v_total:=v_variant.price*p_quantity;
 insert into public.payments(athlete_id,concept,amount,method,reference,status,paid_at) values(p_athlete_id,'product',v_total,p_method,p_reference,'confirmed',now()) returning * into v_payment;
 insert into public.sales(athlete_id,total,payment_id) values(p_athlete_id,v_total,v_payment.id) returning * into v_sale;
 insert into public.sale_items(sale_id,variant_id,quantity,unit_price) values(v_sale.id,p_variant_id,p_quantity,v_variant.price);
 update public.product_variants set stock=stock-p_quantity where id=p_variant_id;
 insert into public.inventory_movements(variant_id,quantity,movement_type,reference,created_by) values(p_variant_id,-p_quantity,'sale',v_sale.id::text,auth.uid());
 insert into public.audit_logs(actor_id,action,entity,entity_id,details) values(auth.uid(),'create','sale',v_sale.id,jsonb_build_object('total',v_total,'variant_id',p_variant_id,'quantity',p_quantity));
 return jsonb_build_object('sale_id',v_sale.id,'payment_id',v_payment.id,'total',v_total,'remaining_stock',v_variant.stock-p_quantity);
end $function$;

create or replace function public.record_staff_payment(p_staff_id uuid,p_amount numeric,p_period_start date,p_period_end date,p_concept text,p_method text default 'cash',p_reference text default null,p_quantity numeric default 1)
returns uuid language plpgsql set search_path='public','private' as $function$
declare v_id uuid; v_club uuid:=private.current_club_id();
begin
 if private.current_role() not in ('owner','admin') then raise exception 'not authorized'; end if;
 if not exists(select 1 from public.staff_members where id=p_staff_id and club_id=v_club) then raise exception 'staff member not found in active club'; end if;
 if p_quantity<=0 then raise exception 'quantity must be greater than zero'; end if;
 insert into public.staff_payments(staff_id,amount,quantity,period_start,period_end,concept,method,reference,status,paid_at) values(p_staff_id,p_amount,p_quantity,p_period_start,p_period_end,p_concept,p_method,p_reference,'confirmed',now()) returning id into v_id;
 insert into public.audit_logs(actor_id,action,entity,entity_id,details) values(auth.uid(),'create','staff_payment',v_id,jsonb_build_object('staff_id',p_staff_id,'amount',p_amount,'quantity',p_quantity));
 return v_id;
end $function$;

drop function if exists public.record_staff_payment(uuid,numeric,date,date,text,text,text);

create or replace function public.renew_membership(p_athlete_id uuid,p_plan_id uuid,p_start_date date,p_method text default 'cash')
returns jsonb language plpgsql set search_path='public','private' as $function$
declare v_plan public.membership_plans; v_prev public.memberships; v_mem public.memberships; v_club uuid:=private.current_club_id();
begin
 if private.current_role() not in ('owner','admin','staff') then raise exception 'not authorized'; end if;
 if not exists(select 1 from public.athletes where id=p_athlete_id and club_id=v_club) then raise exception 'athlete not found in active club'; end if;
 select * into v_plan from public.membership_plans where id=p_plan_id and club_id=v_club and active;
 if not found then raise exception 'plan not found or inactive'; end if;
 select * into v_prev from public.memberships where athlete_id=p_athlete_id and club_id=v_club and status='active' order by end_date desc limit 1;
 if found and v_prev.end_date>=p_start_date then p_start_date:=v_prev.end_date+1; end if;
 insert into public.memberships(athlete_id,plan_id,start_date,end_date,status) values(p_athlete_id,p_plan_id,p_start_date,p_start_date+v_plan.duration_days-1,'active') returning * into v_mem;
 insert into public.payments(athlete_id,membership_id,concept,amount,method,status,paid_at) values(p_athlete_id,v_mem.id,'membership',v_plan.price,p_method,'confirmed',now());
 insert into public.audit_logs(actor_id,action,entity,entity_id,details) values(auth.uid(),'renew','membership',v_mem.id,jsonb_build_object('athlete_id',p_athlete_id));
 return jsonb_build_object('membership_id',v_mem.id,'start_date',v_mem.start_date,'end_date',v_mem.end_date);
end $function$;

notify pgrst,'reload schema';