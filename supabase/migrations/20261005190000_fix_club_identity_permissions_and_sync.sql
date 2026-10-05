create or replace function public.rename_club(
  p_club_id uuid,
  p_name text,
  p_slug text,
  p_active boolean
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_uid uuid := (select auth.uid());
  v_name text := trim(coalesce(p_name,''));
  v_slug text := lower(trim(coalesce(p_slug,'')));
begin
  if v_uid is null then raise exception 'Sesión requerida'; end if;
  if v_name = '' then raise exception 'El nombre del club es obligatorio'; end if;
  if v_slug = '' then raise exception 'El slug del club es obligatorio'; end if;

  if not (
    exists (select 1 from public.platform_admins where user_id=v_uid)
    or exists (
      select 1 from public.club_memberships
      where club_id=p_club_id and user_id=v_uid and active and role in ('owner','admin')
    )
  ) then
    raise exception 'No tienes permisos para editar este club';
  end if;

  if exists (select 1 from public.clubs where slug=v_slug and id<>p_club_id) then
    raise exception 'Ese slug ya está en uso';
  end if;

  update public.clubs
  set name=v_name, slug=v_slug, active=p_active
  where id=p_club_id;

  if not found then raise exception 'Club no encontrado'; end if;

  insert into public.club_settings(club_id,club_name,updated_at,updated_by)
  values(p_club_id,v_name,now(),v_uid)
  on conflict(club_id) do update
  set club_name=excluded.club_name,
      updated_at=excluded.updated_at,
      updated_by=excluded.updated_by;
end
$function$;

revoke execute on function public.rename_club(uuid,text,text,boolean) from public, anon;
grant execute on function public.rename_club(uuid,text,text,boolean) to authenticated;

update public.clubs c
set name=cs.club_name
from public.club_settings cs
where c.id=cs.club_id
  and c.id='93bf6bac-c5fb-4d62-bed7-a9590d63174f'
  and nullif(trim(cs.club_name),'') is not null;

notify pgrst,'reload schema';
