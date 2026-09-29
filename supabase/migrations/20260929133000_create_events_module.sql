create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null default private.current_club_id() references public.clubs(id) on delete cascade,
  name text not null,
  event_date date not null,
  start_time time,
  end_time time,
  location text,
  description text,
  expected_people integer check (expected_people is null or expected_people >= 0),
  status text not null default 'scheduled' check (status in ('scheduled','completed','cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists events_club_id_idx on public.events(club_id);
create index if not exists events_event_date_idx on public.events(club_id,event_date);

alter table public.events enable row level security;

drop policy if exists "events tenant select" on public.events;
create policy "events tenant select" on public.events
for select to authenticated
using (club_id = private.current_club_id());

drop policy if exists "events tenant insert" on public.events;
create policy "events tenant insert" on public.events
for insert to authenticated
with check (
  club_id = private.current_club_id()
  and private.current_role() in ('owner','admin')
);

drop policy if exists "events tenant update" on public.events;
create policy "events tenant update" on public.events
for update to authenticated
using (
  club_id = private.current_club_id()
  and private.current_role() in ('owner','admin')
)
with check (
  club_id = private.current_club_id()
  and private.current_role() in ('owner','admin')
);

drop policy if exists "events tenant delete" on public.events;
create policy "events tenant delete" on public.events
for delete to authenticated
using (
  club_id = private.current_club_id()
  and private.current_role() in ('owner','admin')
);

grant select, insert, update, delete on public.events to authenticated;
