create or replace function public.queue_membership_reminders()
returns integer
language plpgsql
security definer
set search_path = ''
as $function$
declare n integer;
begin
  insert into public.notifications(
    athlete_id,channel,template,scheduled_for,status,payload,club_id
  )
  select
    m.athlete_id,c.channel,'membership_expiring',now(),'pending',
    jsonb_build_object(
      'end_date',m.end_date,
      'days_left',(m.end_date-current_date),
      'email',a.email,
      'phone',a.phone,
      'athlete_name',a.full_name
    ),
    m.club_id
  from public.memberships m
  join public.athletes a on a.id=m.athlete_id and a.club_id=m.club_id
  cross join (values ('email'),('whatsapp'),('sms')) c(channel)
  where m.status='active'
    and m.end_date in (current_date,current_date+1,current_date+3,current_date+7)
    and not exists (
      select 1 from public.notifications n
      where n.athlete_id=m.athlete_id
        and n.club_id=m.club_id
        and n.channel=c.channel
        and n.template='membership_expiring'
        and n.created_at > now()-interval '24 hours'
    );
  get diagnostics n=row_count;
  return n;
end
$function$;

revoke execute on function public.queue_membership_reminders() from public, anon, authenticated;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
  insert into public.profiles(id,full_name,role,active_club_id)
  values(
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name',split_part(coalesce(new.email,''),'@',1)),
    'staff',
    '00000000-0000-0000-0000-000000000001'
  )
  on conflict(id) do nothing;
  return new;
end
$function$;