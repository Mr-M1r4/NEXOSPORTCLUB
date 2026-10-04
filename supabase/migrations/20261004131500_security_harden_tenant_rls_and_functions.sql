-- Harden tenant isolation for legacy permissive policies.
drop policy if exists "attendance read" on public.attendance;
drop policy if exists "categories read" on public.categories;
drop policy if exists "settings read" on public.club_settings;
drop policy if exists "teams read" on public.teams;
drop policy if exists "sessions read" on public.training_sessions;

alter policy "plans_access" on public.membership_plans
  using (club_id = private.current_club_id())
  with check (
    club_id = private.current_club_id()
    and private.current_role() in ('owner','admin')
  );

alter policy "variants_access" on public.product_variants
  using (club_id = private.current_club_id())
  with check (
    club_id = private.current_club_id()
    and private.current_role() in ('owner','admin','staff')
  );

alter policy "products_access" on public.products
  using (club_id = private.current_club_id())
  with check (
    club_id = private.current_club_id()
    and private.current_role() in ('owner','admin')
  );

alter policy "staff_access" on public.staff_members
  using (club_id = private.current_club_id())
  with check (
    club_id = private.current_club_id()
    and private.current_role() in ('owner','admin')
  );

alter function private.generate_payment_reference(text)
  set search_path = pg_catalog, public, extensions;

alter function private.set_payment_reference()
  set search_path = pg_catalog, public, private, extensions;

revoke execute on function public.delete_club(uuid) from anon;

comment on function public.delete_club(uuid)
is 'Archives a club; callable only by authenticated owner or platform admin.';
