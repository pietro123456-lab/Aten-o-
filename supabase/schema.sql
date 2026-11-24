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
create policy "profile update self" on public.atencao_profiles
for update to authenticated using (user_id = auth.uid())
with check (user_id = auth.uid());

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
with check (
  status = 'revoked'
  and revoked_at is not null
  and exists (select 1 from public.atencao_children c where c.id = child_id and c.guardian_id = auth.uid())
);

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

grant select, insert on public.atencao_profiles to authenticated;
grant update(display_name) on public.atencao_profiles to authenticated;
grant select, insert, update, delete on public.atencao_children to authenticated;
grant select, insert, update, delete on public.atencao_invite_codes to authenticated;
grant select on public.atencao_child_access to authenticated;
grant update(status, revoked_at) on public.atencao_child_access to authenticated;
grant select, insert, update, delete on public.atencao_progress to authenticated;
grant select, insert on public.atencao_progress_events to authenticated;

-- IMPORTANTE: contas de psicólogos devem ser promovidas manualmente pelo administrador
-- após verificar a identidade e a autorização profissional:
-- update public.atencao_profiles set role = 'psychologist' where user_id = '<UUID_DA_CONTA>';

-- Permite que o psicólogo vinculado consulte somente o apelido do perfil autorizado.
drop policy if exists "linked psychologist reads child nickname" on public.atencao_children;
create policy "linked psychologist reads child nickname" on public.atencao_children
for select to authenticated
using (exists (
  select 1 from public.atencao_child_access a
  where a.child_id = id and a.psychologist_id = auth.uid() and a.status = 'active'
));


-- Painel de aprovação profissional: somente este e-mail é administrador.
-- A identidade é conferida no banco usando o e-mail confirmado do Supabase Auth.
create table if not exists public.atencao_professional_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null check (char_length(display_name) between 2 and 60),
  note text not null default '' check (char_length(note) <= 500),
  status text not null default 'pending'
    check (status in ('pending','approved','rejected','blocked')),
  submitted_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id)
);
create index if not exists atencao_professional_requests_status_idx
  on public.atencao_professional_requests(status, submitted_at desc);

create or replace function public.atencao_is_admin()
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from auth.users u
    where u.id = auth.uid()
      and lower(u.email) = 'pietromo2015@gmail.com'
      and u.email_confirmed_at is not null
  );
$$;
revoke all on function public.atencao_is_admin() from public;
grant execute on function public.atencao_is_admin() to authenticated;

create or replace function public.atencao_submit_professional_request(p_display_name text,p_note text default '')
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_id uuid; v_email text; v_role public.atencao_user_role;
begin
  if auth.uid() is null then raise exception 'Autenticação necessária'; end if;
  select u.email into v_email from auth.users u
    where u.id=auth.uid() and u.email_confirmed_at is not null;
  if v_email is null then raise exception 'Confirme seu e-mail antes de solicitar acesso'; end if;
  select p.role into v_role from public.atencao_profiles p where p.user_id=auth.uid();
  if v_role is distinct from 'responsible'::public.atencao_user_role then
    raise exception 'Esta conta não pode solicitar acesso profissional';
  end if;
  if p_display_name is null or char_length(trim(p_display_name)) not between 2 and 60 then
    raise exception 'Nome de exibição inválido';
  end if;
  if char_length(coalesce(p_note,''))>500 then raise exception 'Texto muito longo'; end if;
  insert into public.atencao_professional_requests(user_id,email,display_name,note,status)
  values(auth.uid(),v_email,trim(p_display_name),coalesce(p_note,''),'pending')
  on conflict(user_id) do update set email=excluded.email,display_name=excluded.display_name,
    note=excluded.note,status='pending',submitted_at=now(),reviewed_at=null,reviewed_by=null
    where public.atencao_professional_requests.status='rejected'
  returning id into v_id;
  if v_id is null then raise exception 'Já existe uma solicitação ativa ou esta conta foi bloqueada'; end if;
  return v_id;
end;
$$;

create or replace function public.atencao_review_professional_request(p_user_id uuid,p_decision text)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_status text;
begin
  if not public.atencao_is_admin() then raise exception 'Acesso administrativo não autorizado'; end if;
  if p_decision not in ('approved','rejected','blocked') then raise exception 'Decisão inválida'; end if;
  select r.status into v_status from public.atencao_professional_requests r
    where r.user_id=p_user_id for update;
  if v_status is null then raise exception 'Solicitação não encontrada'; end if;
  if p_decision='approved' and v_status not in ('pending','rejected') then
    raise exception 'Esta solicitação não pode ser aprovada';
  end if;
  if p_decision='rejected' and v_status<>'pending' then
    raise exception 'Somente solicitações pendentes podem ser recusadas';
  end if;
  if p_decision='blocked' and v_status<>'approved' then
    raise exception 'Somente psicólogos aprovados podem ser bloqueados';
  end if;
  if p_decision='approved' then
    update public.atencao_profiles set role='psychologist' where user_id=p_user_id;
  elsif p_decision='blocked' then
    update public.atencao_profiles set role='responsible' where user_id=p_user_id;
  end if;
  update public.atencao_professional_requests set status=p_decision,reviewed_at=now(),reviewed_by=auth.uid()
    where user_id=p_user_id;
  return true;
end;
$$;
revoke all on function public.atencao_submit_professional_request(text,text) from public;
revoke all on function public.atencao_review_professional_request(uuid,text) from public;
grant execute on function public.atencao_submit_professional_request(text,text) to authenticated;
grant execute on function public.atencao_review_professional_request(uuid,text) to authenticated;

alter table public.atencao_professional_requests enable row level security;
drop policy if exists "user reads own professional request or admin reads all" on public.atencao_professional_requests;
create policy "user reads own professional request or admin reads all"
on public.atencao_professional_requests for select to authenticated
using(user_id=auth.uid() or public.atencao_is_admin());
revoke all on public.atencao_professional_requests from anon;
grant select on public.atencao_professional_requests to authenticated;
