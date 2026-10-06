alter table public.club_settings
  add column if not exists logo_path text,
  add column if not exists logo_url text;

insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('club-logos','club-logos',true,2097152,array['image/jpeg','image/png','image/webp']::text[])
on conflict (id) do update set public=true,file_size_limit=2097152,allowed_mime_types=array['image/jpeg','image/png','image/webp']::text[];

drop policy if exists "club logos insert" on storage.objects;
drop policy if exists "club logos update" on storage.objects;
drop policy if exists "club logos delete" on storage.objects;

create policy "club logos insert" on storage.objects for insert to authenticated
with check (bucket_id='club-logos' and (storage.foldername(name))[1]=(select private.current_club_id())::text and (select private.current_role()) in ('owner'::public.user_role,'admin'::public.user_role));

create policy "club logos update" on storage.objects for update to authenticated
using (bucket_id='club-logos' and (storage.foldername(name))[1]=(select private.current_club_id())::text and (select private.current_role()) in ('owner'::public.user_role,'admin'::public.user_role))
with check (bucket_id='club-logos' and (storage.foldername(name))[1]=(select private.current_club_id())::text and (select private.current_role()) in ('owner'::public.user_role,'admin'::public.user_role));

create policy "club logos delete" on storage.objects for delete to authenticated
using (bucket_id='club-logos' and (storage.foldername(name))[1]=(select private.current_club_id())::text and (select private.current_role()) in ('owner'::public.user_role,'admin'::public.user_role));

notify pgrst,'reload schema';