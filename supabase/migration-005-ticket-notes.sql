-- Migration 005: daily ticket notes (plain-text export of the last 24 h)
create table if not exists ticket_notes (
  note_date date primary key,
  note text not null,
  counts jsonb,
  created_at timestamptz default now()
);
alter table ticket_notes enable row level security;
drop policy if exists "public read ticket_notes" on ticket_notes;
create policy "public read ticket_notes" on ticket_notes for select using (true);
