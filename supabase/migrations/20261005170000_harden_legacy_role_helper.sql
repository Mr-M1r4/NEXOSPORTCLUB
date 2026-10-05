create or replace function public.current_role()
returns public.user_role
language sql
stable
security definer
set search_path = ''
as $function$
  select private.current_role()
$function$;

revoke execute on function public.current_role() from public, anon, authenticated;
notify pgrst,'reload schema';