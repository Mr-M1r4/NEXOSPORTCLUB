-- Fix category visibility with explicit tenant-scoped policies.
drop policy if exists "tenant_isolation" on public.categories;
drop policy if exists "categories insert" on public.categories;
drop policy if exists "categories update" on public.categories;
drop policy if exists "categories delete" on public.categories;
drop policy if exists "categories select" on public.categories;

create policy "categories select" on public.categories for select to authenticated
using (club_id = (select private.current_club_id()));

create policy "categories insert" on public.categories for insert to authenticated
with check (club_id = (select private.current_club_id()) and (select private.current_role()) in ('owner','admin'));

create policy "categories update" on public.categories for update to authenticated
using (club_id = (select private.current_club_id()) and (select private.current_role()) in ('owner','admin'))
with check (club_id = (select private.current_club_id()) and (select private.current_role()) in ('owner','admin'));

create policy "categories delete" on public.categories for delete to authenticated
using (club_id = (select private.current_club_id()) and (select private.current_role()) in ('owner','admin'));

create or replace function public.delete_category(p_id uuid)
returns text language plpgsql security definer set search_path = ''
as $function$
declare
  v_uid uuid := (select auth.uid());
  v_club uuid := (select private.current_club_id());
  v_used bigint;
begin
  if v_uid is null then raise exception 'Sesión requerida'; end if;
  if (select private.current_role()) not in ('owner','admin') then raise exception 'No tienes permisos para eliminar categorías'; end if;
  if not exists(select 1 from public.categories where id=p_id and club_id=v_club) then raise exception 'Categoría no encontrada'; end if;
  select
    (select count(*) from public.athletes where category_id=p_id and club_id=v_club)
    + (select count(*) from public.teams where category_id=p_id and club_id=v_club)
  into v_used;
  if v_used > 0 then
    update public.categories set active=false where id=p_id and club_id=v_club;
    return 'archived';
  end if;
  delete from public.categories where id=p_id and club_id=v_club;
  return 'deleted';
end
$function$;

revoke execute on function public.delete_category(uuid) from public,anon;
grant execute on function public.delete_category(uuid) to authenticated;

create or replace function public.delete_club(p_id uuid)
returns text language plpgsql security definer set search_path = ''
as $function$
declare
  v_uid uuid := (select auth.uid());
  v_active uuid;
begin
  if v_uid is null then raise exception 'Sesión requerida'; end if;
  if not (
    exists(select 1 from public.platform_admins where user_id=v_uid)
    or exists(select 1 from public.club_memberships where club_id=p_id and user_id=v_uid and active and role='owner')
  ) then raise exception 'No tienes permisos para eliminar este club'; end if;
  if not exists(select 1 from public.clubs where id=p_id) then raise exception 'Club no encontrado'; end if;
  select active_club_id into v_active from public.profiles where id=v_uid;
  if v_active=p_id then raise exception 'Cambia primero a otro club antes de eliminar este club'; end if;
  update public.clubs set active=false where id=p_id;
  update public.saas_subscriptions set status='cancelled',auto_renew=false,updated_at=now() where club_id=p_id;
  return 'archived';
end
$function$;

revoke execute on function public.delete_club(uuid) from public,anon;
grant execute on function public.delete_club(uuid) to authenticated;

notify pgrst,'reload schema';
