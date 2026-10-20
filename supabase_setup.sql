-- =====================================================================
-- TransitOne Surat - Supabase setup
-- Run this once in: Supabase Dashboard -> SQL Editor -> New query -> Run
-- =====================================================================

-- ---------- 1. Profiles (one row per signed-in user) ----------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text,
  phone       text,
  email       text,
  role        text not null default 'passenger' check (role in ('passenger', 'admin')),
  created_at  timestamptz not null default now()
);

-- ---------- 2. Admin access code (never readable from the browser) --
create table if not exists public.admin_settings (
  key    text primary key,
  value  text not null
);
-- Do NOT put your real admin code in this file if the repo is public.
-- Run the statement below separately in the SQL Editor with your own secret code:
--
--   insert into public.admin_settings (key, value)
--   values ('admin_access_code', 'your-secret-code-here')
--   on conflict (key) do update set value = excluded.value;
--
-- Until you do, nobody can claim the admin role (claim_admin_role returns false).

-- ---------- 3. Tickets ----------------------------------------------
create table if not exists public.tickets (
  id              uuid primary key default gen_random_uuid(),
  ticket_no       text not null unique,
  user_id         uuid references auth.users(id) on delete set null default auth.uid(),
  from_station    text not null,
  to_station      text not null,
  passenger_type  text not null,
  qty             int  not null check (qty between 1 and 6),
  fare            numeric not null check (fare >= 0),
  journey_date    date not null,
  created_at      timestamptz not null default now()
);

-- ---------- 4. Feedback --------------------------------------------
create table if not exists public.feedback (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references auth.users(id) on delete set null default auth.uid(),
  category    text not null,
  comments    text,
  rating      int check (rating between 1 and 5),
  created_at  timestamptz not null default now()
);

-- ---------- 5. Activity log (admin dashboard) -----------------------
create table if not exists public.activity_logs (
  id          uuid primary key default gen_random_uuid(),
  action      text not null,
  details     text,
  created_at  timestamptz not null default now()
);

-- ---------- 6. Helper: is the current user an admin? ----------------
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  );
$$;

-- ---------- 7. Auto-create profile when a user signs up -------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, name, phone, email, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'name',
             new.raw_user_meta_data ->> 'full_name',
             'Commuter'),
    new.phone,
    new.email,
    'passenger'            -- everyone starts as passenger; admin is claimed via RPC below
  )
  on conflict (id) do nothing;

  insert into public.activity_logs (action, details)
  values ('USER_REGISTERED', 'New user registered: ' || coalesce(new.email, new.phone, new.id::text));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 8. Claim admin role with the access code ----------------
create or replace function public.claim_admin_role(access_code text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  expected text;
begin
  if auth.uid() is null then
    return false;
  end if;

  select value into expected from public.admin_settings where key = 'admin_access_code';

  if expected is null or access_code is distinct from expected then
    return false;
  end if;

  update public.profiles set role = 'admin' where id = auth.uid();
  insert into public.activity_logs (action, details)
  values ('ADMIN_GRANTED', 'Admin role granted to user ' || auth.uid()::text);
  return true;
end;
$$;

-- ---------- 9. Admin dashboard stats --------------------------------
create or replace function public.admin_stats()
returns json
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin() then
    raise exception 'admin only';
  end if;

  return json_build_object(
    'totalUsers',    (select count(*) from public.profiles),
    'totalBookings', (select count(*) from public.tickets),
    'totalRevenue',  (select coalesce(sum(fare), 0) from public.tickets),
    'totalFeedback', (select count(*) from public.feedback),
    'logs', (
      select coalesce(json_agg(l), '[]'::json) from (
        select action, details, created_at
        from public.activity_logs
        order by created_at desc
        limit 15
      ) l
    )
  );
end;
$$;

-- ---------- 10. Log ticket & feedback events ------------------------
create or replace function public.log_ticket()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.activity_logs (action, details)
  values ('TICKET_BOOKED', 'Ticket ' || new.ticket_no || ' booked for Rs.' || new.fare);
  return new;
end; $$;

create or replace function public.log_feedback()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.activity_logs (action, details)
  values ('FEEDBACK_SUBMITTED', 'Feedback submitted under category: ' || new.category);
  return new;
end; $$;

drop trigger if exists on_ticket_created on public.tickets;
create trigger on_ticket_created after insert on public.tickets
  for each row execute function public.log_ticket();

drop trigger if exists on_feedback_created on public.feedback;
create trigger on_feedback_created after insert on public.feedback
  for each row execute function public.log_feedback();

-- ---------- 11. Row Level Security ----------------------------------
alter table public.profiles       enable row level security;
alter table public.admin_settings enable row level security;   -- no policies = no browser access
alter table public.tickets        enable row level security;
alter table public.feedback       enable row level security;
alter table public.activity_logs  enable row level security;

-- profiles: read/update own row (role column is protected below)
drop policy if exists "profiles read own"   on public.profiles;
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles read own"   on public.profiles for select using (auth.uid() = id or public.is_admin());
create policy "profiles update own" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

-- stop users from changing their own role through a normal update
revoke update on public.profiles from authenticated, anon;
grant  update (name, phone, email) on public.profiles to authenticated;

-- tickets
drop policy if exists "tickets insert own" on public.tickets;
drop policy if exists "tickets read own"   on public.tickets;
create policy "tickets insert own" on public.tickets for insert to authenticated with check (user_id = auth.uid());
create policy "tickets read own"   on public.tickets for select to authenticated using (user_id = auth.uid() or public.is_admin());

-- feedback
drop policy if exists "feedback insert" on public.feedback;
drop policy if exists "feedback read"   on public.feedback;
create policy "feedback insert" on public.feedback for insert to anon, authenticated with check (true);
create policy "feedback read"   on public.feedback for select to authenticated using (user_id = auth.uid() or public.is_admin());

-- activity logs: admins only (written by triggers)
drop policy if exists "logs admin read" on public.activity_logs;
create policy "logs admin read" on public.activity_logs for select to authenticated using (public.is_admin());

-- function permissions
revoke all on function public.claim_admin_role(text) from public, anon;
grant execute on function public.claim_admin_role(text) to authenticated;
revoke all on function public.admin_stats() from public, anon;
grant execute on function public.admin_stats() to authenticated;
