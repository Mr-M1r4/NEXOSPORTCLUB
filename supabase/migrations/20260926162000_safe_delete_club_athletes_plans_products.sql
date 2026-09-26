-- Safe deletion is implemented as hard-delete when there is no history,
-- otherwise the record is archived/deactivated to preserve financial and attendance history.

create or replace function public.delete_athlete(p_id uuid)
returns text language plpgsql security invoker set search_path=public,private as $$
declare v_club uuid:=private.current_club_id(); v_count integer;
begin
  if private.current_role() not in ('owner','admin') then raise exception 'No tienes permisos para eliminar deportistas'; end if;
  if not exists(select 1 from public.athletes where id=p_id and club_id=v_club) then raise exception 'Deportista no encontrado'; end if;
  select count(*) into v_count from public.memberships where athlete_id=p_id;
  if v_count>0 then update public.athletes set status='inactive',updated_at=now() where id=p_id and club_id=v_club; return 'archived'; end if;
  select count(*) into v_count from public.payments where athlete_id=p_id;
  if v_count>0 then update public.athletes set status='inactive',updated_at=now() where id=p_id and club_id=v_club; return 'archived'; end if;
  select count(*) into v_count from public.sales where athlete_id=p_id;
  if v_count>0 then update public.athletes set status='inactive',updated_at=now() where id=p_id and club_id=v_club; return 'archived'; end if;
  select count(*) into v_count from public.attendance where athlete_id=p_id;
  if v_count>0 then update public.athletes set status='inactive',updated_at=now() where id=p_id and club_id=v_club; return 'archived'; end if;
  delete from public.notifications where athlete_id=p_id;
  delete from public.registrations where athlete_id=p_id;
  delete from public.athletes where id=p_id and club_id=v_club;
  return 'deleted';
end $$;

create or replace function public.delete_membership_plan(p_id uuid)
returns text language plpgsql security invoker set search_path=public,private as $$
declare v_club uuid:=private.current_club_id();
begin
  if private.current_role() not in ('owner','admin') then raise exception 'No tienes permisos para eliminar planes'; end if;
  if not exists(select 1 from public.membership_plans where id=p_id and club_id=v_club) then raise exception 'Plan no encontrado'; end if;
  if exists(select 1 from public.memberships where plan_id=p_id) then update public.membership_plans set active=false where id=p_id and club_id=v_club; return 'archived'; end if;
  delete from public.membership_plans where id=p_id and club_id=v_club; return 'deleted';
end $$;

create or replace function public.delete_product(p_id uuid)
returns text language plpgsql security invoker set search_path=public,private as $$
declare v_club uuid:=private.current_club_id();
begin
  if private.current_role() not in ('owner','admin') then raise exception 'No tienes permisos para eliminar servicios'; end if;
  if not exists(select 1 from public.products where id=p_id and club_id=v_club) then raise exception 'Servicio no encontrado'; end if;
  if exists(select 1 from public.sale_items si join public.product_variants pv on pv.id=si.variant_id where pv.product_id=p_id)
     or exists(select 1 from public.inventory_movements im join public.product_variants pv on pv.id=im.variant_id where pv.product_id=p_id) then update public.products set active=false where id=p_id and club_id=v_club; return 'archived'; end if;
  delete from public.product_variants where product_id=p_id; delete from public.products where id=p_id and club_id=v_club; return 'deleted';
end $$;

create or replace function public.delete_club(p_id uuid)
returns text language plpgsql security definer set search_path=public,private as $$
declare v_uid uuid:=auth.uid(); v_active uuid;
begin
  if not (private.current_role()='owner' or exists(select 1 from public.platform_admins where user_id=v_uid)) then raise exception 'No tienes permisos para eliminar clubes'; end if;
  if not exists(select 1 from public.clubs where id=p_id) then raise exception 'Club no encontrado'; end if;
  select active_club_id into v_active from public.profiles where id=v_uid;
  if v_active=p_id then raise exception 'Cambia primero a otro club antes de eliminar este club'; end if;
  update public.clubs set active=false where id=p_id;
  update public.saas_subscriptions set status='cancelled',auto_renew=false,updated_at=now() where club_id=p_id;
  return 'archived';
end $$;

grant execute on function public.delete_athlete(uuid) to authenticated;
grant execute on function public.delete_membership_plan(uuid) to authenticated;
grant execute on function public.delete_product(uuid) to authenticated;
grant execute on function public.delete_club(uuid) to authenticated;
}