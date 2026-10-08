-- Fix club logo replacement: Supabase Storage upsert checks the existing object.
-- An upsert needs SELECT as well as INSERT/UPDATE. Keep reads scoped to the active
-- club and owner/admin membership; public logo URLs still work because the bucket is public.
drop policy if exists "club logos select" on storage.objects;
create policy "club logos select" on storage.objects
for select to authenticated
using (
  bucket_id = 'club-logos'
  and (storage.foldername(name))[1] = (select private.current_club_id())::text
  and (select private.current_role()) in ('owner'::public.user_role, 'admin'::public.user_role)
);

notify pgrst, 'reload schema';
