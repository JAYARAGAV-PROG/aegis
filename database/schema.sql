-- ============================================
-- AEGIS Firewall — Supabase Schema
-- Run this in Supabase SQL Editor
-- ============================================

create extension if not exists "uuid-ossp";

-- ── 1. ENDPOINTS ──────────────────────────────
-- Each monitored machine (your friends' laptops)
create table endpoints (
  id          uuid default uuid_generate_v4() primary key,
  name        text not null,
  hostname    text,
  ip_address  text,
  os_info     text,
  status      text default 'offline',   -- online | offline
  agent_version text default '1.0',
  last_seen   timestamptz default now(),
  created_at  timestamptz default now()
);

-- ── 2. CONNECTIONS ────────────────────────────
-- Every real network connection captured by agent
create table connections (
  id            uuid default uuid_generate_v4() primary key,
  endpoint_id   uuid references endpoints(id) on delete cascade,
  process_name  text not null,
  process_pid   integer,
  process_path  text,
  local_ip      text,
  local_port    integer,
  remote_ip     text,
  remote_port   integer,
  remote_host   text,
  protocol      text default 'TCP',
  conn_status   text,
  abuse_score   integer default 0,      -- 0-100 from AbuseIPDB
  is_flagged    boolean default false,   -- abuse_score > 25
  is_blocked    boolean default false,   -- rule says block
  created_at    timestamptz default now()
);

-- Index for fast queries
create index idx_connections_endpoint on connections(endpoint_id);
create index idx_connections_created  on connections(created_at desc);
create index idx_connections_flagged  on connections(is_flagged) where is_flagged = true;

-- ── 3. RULES ──────────────────────────────────
-- Block/allow rules set from dashboard
create table rules (
  id            uuid default uuid_generate_v4() primary key,
  endpoint_id   uuid references endpoints(id) on delete cascade,  -- null = global
  process_name  text,         -- null = all processes
  remote_ip     text,
  remote_host   text,
  action        text not null check (action in ('block','allow')),
  reason        text,
  created_at    timestamptz default now()
);

-- ── 4. ALERTS ─────────────────────────────────
-- AI-generated security alerts
create table alerts (
  id              uuid default uuid_generate_v4() primary key,
  endpoint_id     uuid references endpoints(id) on delete cascade,
  process_name    text,
  remote_ip       text,
  alert_type      text,   -- suspicious_ip | anomaly | high_volume | blocked
  severity        text default 'medium' check (severity in ('low','medium','high','critical')),
  description     text,
  gemini_analysis text,   -- Gemini AI analysis text
  is_resolved     boolean default false,
  created_at      timestamptz default now()
);

-- ── 5. Enable Realtime ────────────────────────
-- So frontend gets live updates from Supabase
alter publication supabase_realtime add table connections;
alter publication supabase_realtime add table alerts;
alter publication supabase_realtime add table endpoints;
alter publication supabase_realtime add table rules;
