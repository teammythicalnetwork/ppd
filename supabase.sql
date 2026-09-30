create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  display_name text,
  created_at timestamptz not null default now()
);

create table if not exists public.diary_entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  entry_date date not null,
  content text not null,
  is_public boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, entry_date)
);

alter table public.profiles enable row level security;
alter table public.diary_entries enable row level security;

drop policy if exists "Public profiles readable" on public.profiles;
create policy "Public profiles readable" on public.profiles for select using (true);

drop policy if exists "Users create own profile" on public.profiles;
create policy "Users create own profile" on public.profiles for insert with check (auth.uid() = id);

drop policy if exists "Users update own profile" on public.profiles;
create policy "Users update own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "Public entries readable" on public.diary_entries;
create policy "Public entries readable" on public.diary_entries for select using (is_public = true or auth.uid() = user_id);

drop policy if exists "Users create own entries" on public.diary_entries;
create policy "Users create own entries" on public.diary_entries for insert with check (auth.uid() = user_id);

drop policy if exists "Users update own entries" on public.diary_entries;
create policy "Users update own entries" on public.diary_entries for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "Users delete own entries" on public.diary_entries;
create policy "Users delete own entries" on public.diary_entries for delete using (auth.uid() = user_id);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare requested_username text;
begin
  requested_username := lower(coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)));
  if requested_username !~ '^[a-z0-9_]{3,24}$' then
    requested_username := 'user_' || substr(replace(new.id::text,'-',''),1,12);
  end if;
  if exists(select 1 from public.profiles where username = requested_username) then
    requested_username := requested_username || '_' || substr(replace(new.id::text,'-',''),1,6);
  end if;
  insert into public.profiles(id, username, display_name)
  values(new.id, requested_username, coalesce(new.raw_user_meta_data->>'display_name', requested_username))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create index if not exists diary_entries_public_date_idx on public.diary_entries(is_public, entry_date desc);
create index if not exists diary_entries_user_date_idx on public.diary_entries(user_id, entry_date desc);