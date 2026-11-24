-- ATENÇÃO PRO — base inicial segura para Supabase
-- Execute este arquivo inteiro no SQL Editor do projeto correto.
-- Não armazene nomes completos, diagnósticos ou outros dados clínicos desnecessários.

create extension if not exists pgcrypto;

do $$ begin
  create type public.atencao_user_role as enum ('responsible', 'psychologist');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.atencao_link_status as enum ('active', 'revoked');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.atencao_progress_status as enum ('in_progress', 'completed', 'paused');
exception when duplicate_object then null; end $$;

create table if not exists public.atencao_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role public.atencao_user_role not null default 'responsible',
  display_name text,
  created_at timestamptz not null default now(),
  constraint atencao_profiles_display_name_length check (display_name is null or char_length(display_name) <= 60)
);

create table if not exists public.atencao_children (
  id uuid primary key default gen_random_uuid(),
  guardian_id uuid not null references auth.users(id) on delete restrict,
  nickname text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint atencao_children_nickname_length check (char_length(nickname) between 1 and 40)
);

create table if not exists public.atencao_invite_codes (
  id uuid primary key default gen_random_uuid(),
  psychologist_id uuid not null references auth.users(id) on delete cascade,
  code_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now(),
  constraint atencao_invite_hash_length check (char_length(code_hash) = 64)
);

create table if not exists public.atencao_child_access (
  id uuid primary key default gen_random_uuid(),
  child_id uuid not null references public.atencao_children(id) on delete cascade,
  psychologist_id uuid not null references auth.users(id) on delete cascade,
  status public.atencao_link_status not null default 'active',
  authorized_by_guardian uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (child_id, psychologist_id)
);

create table if not exists public.atencao_progress (
  id uuid primary key default gen_random_uuid(),
  child_id uuid not null references public.atencao_children(id) on delete cascade,
  activity_key text not null,
  status public.atencao_progress_status not null default 'in_progress',
  stage integer not null default 0,
  total_stages integer not null default 0,
  score integer not null default 0,
  duration_seconds integer not null default 0,
  started_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz,
  constraint atencao_progress_activity_length check (char_length(activity_key) between 1 and 60),
  constraint atencao_progress_stage_check check (stage >= 0 and total_stages >= 0 and stage <= total_stages),
  constraint atencao_progress_numbers_check check (score >= 0 and duration_seconds >= 0)
);

create table if not exists public.atencao_progress_events (
  id uuid primary key default gen_random_uuid(),
  child_id uuid not null references public.atencao_children(id) on delete cascade,
  activity_key text not null,
  event_type text not null,
  stage integer not null default 0,
  total_stages integer not null default 0,
  score integer not null default 0,
  duration_seconds integer not null default 0,
  occurred_at timestamptz not null default now(),
  constraint atencao_events_activity_length check (char_length(activity_key) between 1 and 60),
  constraint atencao_events_type_length check (char_length(event_type) between 1 and 30),
  constraint atencao_events_numbers_check check (stage >= 0 and total_stages >= 0 and stage <= total_stages and score >= 0 and duration_seconds >= 0)
);

create index if not exists atencao_children_guardian_idx on public.atencao_children(guardian_id);
create index if not exists atencao_access_psychologist_idx on public.atencao_child_access(psychologist_id, status);
create index if not exists atencao_progress_child_updated_idx on public.atencao_progress(child_id, updated_at desc);
create index if not exists atencao_events_child_date_idx on public.atencao_progress_events(child_id, occurred_at desc);

-- Cria perfil básico para novas contas. O papel inicial é sempre responsável.
create or replace function public.atencao_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.atencao_profiles(user_id, role)
  values (new.id, 'responsible')
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists atencao_on_auth_user_created on auth.users;
create trigger atencao_on_auth_user_created
after insert on auth.users
for each row execute procedure public.atencao_handle_new_user();

-- Função auxiliar: não expõe dados e evita recursão nas políticas RLS.
create or replace function public.atencao_can_view_child(p_child_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.atencao_children c
    where c.id = p_child_id and c.guardian_id = auth.uid()
  ) or exists (
    select 1 from public.atencao_child_access a
    where a.child_id = p_child_id
      and a.psychologist_id = auth.uid()
      and a.status = 'active'
  );
$$;

revoke all on function public.atencao_can_view_child(uuid) from public;
grant execute on function public.atencao_can_view_child(uuid) to authenticated;

-- Responsável reivindica um convite usando SHA-256 do código digitado.
-- A chamada só funciona para criança que pertence à conta autenticada.
create or replace function public.atencao_claim_psychologist_invite(
  p_child_id uuid,
  p_code_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_psychologist_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Autenticação necessária';
  end if;

  if not exists (
    select 1 from public.atencao_profiles p
    where p.user_id = auth.uid() and p.role = 'responsible'
  ) then
    raise exception 'Somente a conta responsável pode autorizar o vínculo';
  end if;

  if not exists (
    select 1 from public.atencao_children c
    where c.id = p_child_id and c.guardian_id = auth.uid()
  ) then
    raise exception 'Perfil não pertence à conta responsável';
  end if;

  select i.psychologist_id into v_psychologist_id
  from public.atencao_invite_codes i
  join public.atencao_profiles p on p.user_id = i.psychologist_id and p.role = 'psychologist'
  where i.code_hash = p_code_hash
    and i.used_at is null
    and i.expires_at > now()
  for update of i;

  if v_psychologist_id is null then
    raise exception 'Código inválido, expirado ou já utilizado';
  end if;

  insert into public.atencao_child_access(child_id, psychologist_id, authorized_by_guardian, status)
  values (p_child_id, v_psychologist_id, auth.uid(), 'active')
  on conflict (child_id, psychologist_id)
  do update set status = 'active', authorized_by_guardian = auth.uid(), revoked_at = null;

  update public.atencao_invite_codes
  set used_at = now()
  where code_hash = p_code_hash and used_at is null;

  return true;
end;
$$;

revoke all on function public.atencao_claim_psychologist_invite(uuid, text) from public;
grant execute on function public.atencao_claim_psychologist_invite(uuid, text) to authenticated;

alter table public.atencao_profiles enable row level security;
alter table public.atencao_children enable row level security;
alter table public.atencao_invite_codes enable row level security;
alter table public.atencao_child_access enable row level security;
alter table public.atencao_progress enable row level security;
alter table public.atencao_progress_events enable row level security;

drop policy if exists "profile read self" on public.atencao_profiles;
create policy "profile read self" on public.atencao_profiles
for select to authenticated using (user_id = auth.uid());

drop policy if exists "profile insert self as responsible" on public.atencao_profiles;
create policy "profile insert self as responsible" on public.atencao_profiles
for insert to authenticated with check (user_id = auth.uid() and role = 'responsible');

drop policy if exists "profile update self without role change" on public.atencao_profiles;
create policy "profile update self without role change" on public.atencao_profiles
for update to authenticated using (user_id = auth.uid())
with check (user_id = auth.uid() and role = (select p.role from public.atencao_profiles p where p.user_id = auth.uid()));

drop policy if exists "guardian manages own child profiles" on public.atencao_children;
create policy "guardian manages own child profiles" on public.atencao_children
for all to authenticated
using (guardian_id = auth.uid())
with check (guardian_id = auth.uid());

drop policy if exists "psychologist manages own invite codes" on public.atencao_invite_codes;
create policy "psychologist manages own invite codes" on public.atencao_invite_codes
for all to authenticated
using (psychologist_id = auth.uid() and exists (
  select 1 from public.atencao_profiles p where p.user_id = auth.uid() and p.role = 'psychologist'
))
with check (psychologist_id = auth.uid() and exists (
  select 1 from public.atencao_profiles p where p.user_id = auth.uid() and p.role = 'psychologist'
));

drop policy if exists "guardian and linked psychologist read access" on public.atencao_child_access;
create policy "guardian and linked psychologist read access" on public.atencao_child_access
for select to authenticated
using (
  exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid())
  or psychologist_id = auth.uid()
);

drop policy if exists "guardian revokes own child access" on public.atencao_child_access;
create policy "guardian revokes own child access" on public.atencao_child_access
for update to authenticated
using (exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid()))
with check (exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid()));

drop policy if exists "read progress for authorized child" on public.atencao_progress;
create policy "read progress for authorized child" on public.atencao_progress
for select to authenticated using (public.atencao_can_view_child(child_id));

drop policy if exists "guardian writes progress" on public.atencao_progress;
create policy "guardian writes progress" on public.atencao_progress
for all to authenticated
using (exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid()))
with check (exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid()));

drop policy if exists "read events for authorized child" on public.atencao_progress_events;
create policy "read events for authorized child" on public.atencao_progress_events
for select to authenticated using (public.atencao_can_view_child(child_id));

drop policy if exists "guardian records progress events" on public.atencao_progress_events;
create policy "guardian records progress events" on public.atencao_progress_events
for insert to authenticated
with check (exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid()));

-- Não conceder acesso anônimo às tabelas.
revoke all on public.atencao_profiles, public.atencao_children, public.atencao_invite_codes,
  public.atencao_child_access, public.atencao_progress, public.atencao_progress_events from anon;

grant select, insert, update on public.atencao_profiles to authenticated;
grant select, insert, update, delete on public.atencao_children to authenticated;
grant select, insert, update, delete on public.atencao_invite_codes to authenticated;
grant select, update on public.atencao_child_access to authenticated;
grant select, insert, update, delete on public.atencao_progress to authenticated;
grant select, insert on public.atencao_progress_events to authenticated;

-- IMPORTANTE: contas de psicólogos devem ser promovidas manualmente pelo administrador
-- após verificar a identidade e a autorização profissional:
-- update public.atencao_profiles set role = 'psychologist' where user_id = '<UUID_DA_CONTA>';
