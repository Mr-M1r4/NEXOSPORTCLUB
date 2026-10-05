drop function if exists public.update_club(uuid,text,text,boolean);

create or replace function private.current_club_id()
returns uuid language sql stable security definer
set search_path = ''
as $function$
  select active_club_id from public.profiles where id=(select auth.uid())
$function$;

create or replace function private.current_role()
returns public.user_role language sql stable security definer
set search_path = ''
as $function$
  select cm.role
  from public.club_memberships cm
  join public.profiles p on p.active_club_id=cm.club_id
  where cm.user_id=(select auth.uid()) and cm.active and p.id=(select auth.uid())
  limit 1
$function$;

create or replace function private.touch_saas_subscription()
returns trigger language plpgsql security definer
set search_path = ''
as $function$
begin
  update public.saas_subscriptions set updated_at=now() where club_id=new.club_id;
  return new;
end
$function$;

create or replace function private.refresh_saas_billing_status()
returns void language sql security definer
set search_path = ''
as $function$
  update public.saas_subscriptions
  set status=case
    when status in ('cancelled','suspended') then status
    when current_period_end < current_date then 'past_due'
    else status end,
    updated_at=now()
  where status in ('trial','active','past_due');
$function$;

create or replace function private.apply_saas_payment()
returns trigger language plpgsql security definer
set search_path = ''
as $function$
declare s public.saas_subscriptions%rowtype;
declare next_start date;
declare next_end date;
begin
  select * into s from public.saas_subscriptions where club_id=new.club_id for update;
  if not found then raise exception 'No existe suscripción para el club'; end if;
  if new.amount >= s.monthly_price and new.subscription_period_start=s.current_period_start then
    next_start:=s.current_period_end+1;
    next_end:=case s.billing_cycle
      when 'annual' then (next_start+interval '1 year')::date-1
      when 'quarterly' then (next_start+interval '3 months')::date-1
      else (next_start+interval '1 month')::date-1 end;
    update public.saas_subscriptions
    set current_period_start=next_start,current_period_end=next_end,status='active',updated_at=now()
    where club_id=new.club_id;
  end if;
  return new;
end
$function$;

create or replace function public.create_club(p_name text,p_slug text)
returns uuid language plpgsql security definer
set search_path = ''
as $function$
declare v_id uuid; v_uid uuid;
begin
  v_uid:=(select auth.uid());
  if v_uid is null then raise exception 'Sesión requerida'; end if;
  if not ((select private.current_role())='owner'
      or exists(select 1 from public.platform_admins where user_id=v_uid))
  then raise exception 'No tienes permisos para crear clubes'; end if;
  if trim(coalesce(p_name,''))='' or trim(coalesce(p_slug,''))='' then
    raise exception 'Nombre y slug son obligatorios';
  end if;
  insert into public.clubs(name,slug) values(trim(p_name),lower(trim(p_slug))) returning id into v_id;
  insert into public.club_memberships(club_id,user_id,role) values(v_id,v_uid,'owner');
  update public.profiles set active_club_id=v_id where id=v_uid;
  insert into public.club_settings(club_id,club_name) values(v_id,trim(p_name))
    on conflict (club_id) do update set club_name=excluded.club_name;
  insert into public.saas_subscriptions(club_id,monthly_price,billing_cycle,started_on,current_period_start,current_period_end)
    values(v_id,100000,'monthly',current_date,current_date,(current_date+interval '1 month')::date-1)
    on conflict (club_id) do nothing;
  return v_id;
end
$function$;

create or replace function public.switch_club(p_club_id uuid)
returns void language plpgsql security definer
set search_path = ''
as $function$
begin
  if not exists(select 1 from public.club_memberships
                where club_id=p_club_id and user_id=(select auth.uid()) and active)
  then raise exception 'No tienes acceso a este club'; end if;
  update public.profiles set active_club_id=p_club_id where id=(select auth.uid());
end
$function$;

create or replace function public.delete_club(p_id uuid)
returns text language plpgsql security definer
set search_path = ''
as $function$
declare v_uid uuid:=(select auth.uid()); v_active uuid;
begin
  if not ((select private.current_role())='owner'
      or exists(select 1 from public.platform_admins where user_id=v_uid))
  then raise exception 'No tienes permisos para eliminar clubes'; end if;
  if not exists(select 1 from public.clubs where id=p_id) then raise exception 'Club no encontrado'; end if;
  select active_club_id into v_active from public.profiles where id=v_uid;
  if v_active=p_id then raise exception 'Cambia primero a otro club antes de eliminar este club'; end if;
  update public.clubs set active=false where id=p_id;
  update public.saas_subscriptions set status='cancelled',auto_renew=false,updated_at=now() where club_id=p_id;
  return 'archived';
end
$function$;

create or replace function public.rename_club(p_club_id uuid,p_name text,p_slug text,p_active boolean)
returns void language plpgsql security definer
set search_path = ''
as $function$
declare v_uid uuid:=(select auth.uid()); v_name text:=trim(coalesce(p_name,'')); v_slug text:=lower(trim(coalesce(p_slug,'')));
begin
  if v_uid is null then raise exception 'Sesión requerida'; end if;
  if v_name='' then raise exception 'El nombre del club es obligatorio'; end if;
  if v_slug='' then raise exception 'El slug del club es obligatorio'; end if;
  if not (exists(select 1 from public.platform_admins where user_id=v_uid)
      or exists(select 1 from public.club_memberships where club_id=p_club_id and user_id=v_uid and active and role='owner'))
  then raise exception 'No tienes permisos para editar este club'; end if;
  if exists(select 1 from public.clubs where slug=v_slug and id<>p_club_id) then raise exception 'Ese slug ya está en uso'; end if;
  update public.clubs set name=v_name,slug=v_slug,active=p_active where id=p_club_id;
  if not found then raise exception 'Club no encontrado'; end if;
  insert into public.club_settings(club_id,club_name,updated_at,updated_by)
  values(p_club_id,v_name,now(),v_uid)
  on conflict(club_id) do update set club_name=excluded.club_name,updated_at=excluded.updated_at,updated_by=excluded.updated_by;
end
$function$;

revoke execute on function public.update_club(uuid,text,text,boolean) from public,anon,authenticated;
revoke execute on function private.apply_saas_payment() from public,anon,authenticated;
revoke execute on function private.refresh_saas_billing_status() from public,anon,authenticated;
revoke execute on function private.touch_saas_subscription() from public,anon,authenticated;
revoke execute on function private.generate_payment_reference(text) from public,anon,authenticated;
revoke execute on function private.set_payment_reference() from public,anon,authenticated;
revoke execute on function public.delete_athlete(uuid) from public,anon;
revoke execute on function public.delete_membership_plan(uuid) from public,anon;
revoke execute on function public.delete_product(uuid) from public,anon;

grant execute on function private.current_club_id() to authenticated;
grant execute on function private.current_role() to authenticated;
grant execute on function public.create_club(text,text) to authenticated;
grant execute on function public.switch_club(uuid) to authenticated;
grant execute on function public.delete_club(uuid) to authenticated;
grant execute on function public.rename_club(uuid,text,text,boolean) to authenticated;

notify pgrst,'reload schema';