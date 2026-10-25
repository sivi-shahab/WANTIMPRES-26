-- Incidents (spec §4.10, §6). Idempotent: applied by incident.Open.
CREATE SCHEMA IF NOT EXISTS incident;

CREATE TABLE IF NOT EXISTS incident.incidents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid        NOT NULL,
  dedup_key         text        NOT NULL,
  title             text        NOT NULL,
  state             text        NOT NULL CHECK (state IN ('New','Triaged','Investigating','Contained','Resolved','Closed')),
  severity          text        NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  max_risk          int         NOT NULL,
  event_count       int         NOT NULL,
  first_event_at    timestamptz NOT NULL,
  last_event_at     timestamptz NOT NULL,
  opened_at         timestamptz NOT NULL DEFAULT now(),
  ack_deadline      timestamptz,
  acknowledged_at   timestamptz,
  resolved_at       timestamptz,
  closed_at         timestamptz,
  assignee          text,
  dek_wrapped       bytea       NOT NULL  -- per-incident evidence key, wrapped by the KEK (KMS in production)
);
CREATE INDEX IF NOT EXISTS incidents_dedup ON incident.incidents (tenant_id, dedup_key, last_event_at DESC);
CREATE INDEX IF NOT EXISTS incidents_queue ON incident.incidents (state, severity, opened_at);

-- Redacted evidence: the decision event as it arrived (metadata, hashes, redacted snippet; spec FR-INC-4).
CREATE TABLE IF NOT EXISTS incident.incident_events (
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  event_id    uuid        NOT NULL UNIQUE,  -- an event joins one incident, once (redelivery is a no-op)
  ts          timestamptz NOT NULL,
  risk_score  int         NOT NULL,
  event       jsonb       NOT NULL,
  PRIMARY KEY (incident_id, event_id)
);

-- Raw evidence: only under forensic_capture, encrypted with the incident's DEK, deleted at expires_at (§10.2: 30 days).
CREATE TABLE IF NOT EXISTS incident.evidence (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  kind        text        NOT NULL,
  ciphertext  bytea       NOT NULL,
  sha256      text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS incident.transitions (
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text        NOT NULL,
  from_state  text        NOT NULL,
  to_state    text        NOT NULL,
  note        text        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS transitions_incident ON incident.transitions (incident_id, at);

-- FR-INC-1 chain: events of one trace (an agent session at the MCP gateway) land in one incident.
ALTER TABLE incident.incident_events ADD COLUMN IF NOT EXISTS trace_id text;
CREATE INDEX IF NOT EXISTS incident_events_trace ON incident.incident_events (trace_id, ts) WHERE trace_id IS NOT NULL;

-- FR-INC-6 breach workflow (UU PDP Pasal 46): the 3×24 h notification timer.
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_started_at   timestamptz;
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_deadline     timestamptz;
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_basis        text;  -- auto (personal data allowed out) | declared
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_escalated_at timestamptz;
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_drafted_at   timestamptz;  -- first draft report
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_closed_at    timestamptz;  -- notified or dismissed
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS breach_outcome      text CHECK (breach_outcome IN ('notified', 'dismissed'));
CREATE INDEX IF NOT EXISTS incidents_breach_open ON incident.incidents (breach_deadline) WHERE breach_started_at IS NOT NULL AND breach_closed_at IS NULL;

-- FR-INC-5 containment actions taken on an incident (and what they returned: kill id, ticket number, …).
CREATE TABLE IF NOT EXISTS incident.actions (
  id          bigserial PRIMARY KEY,
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  action      text        NOT NULL,
  params      jsonb       NOT NULL,
  result      jsonb       NOT NULL,
  actor       text        NOT NULL,
  at          timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_incident ON incident.actions (incident_id, at);

-- Containment block: this principal may not reach this app until expires_at or lifted (data.wantimpres26.containment).
CREATE TABLE IF NOT EXISTS incident.blocks (
  id           bigserial PRIMARY KEY,
  tenant_id    uuid        NOT NULL,
  incident_id  uuid        NOT NULL REFERENCES incident.incidents(id),
  principal_id text        NOT NULL,
  app_id       text        NOT NULL,
  expires_at   timestamptz NOT NULL,
  created_by   text        NOT NULL,
  created_at   timestamptz NOT NULL,
  lifted_by    text,
  lifted_at    timestamptz
);

-- ITSM ticket per incident (ServiceNow / Jira SM): one, reused.
CREATE TABLE IF NOT EXISTS incident.tickets (
  incident_id uuid        PRIMARY KEY REFERENCES incident.incidents(id),
  system      text        NOT NULL,
  ref         text        NOT NULL,
  url         text        NOT NULL,
  created_at  timestamptz NOT NULL
);

-- Ticket 45 ABAC: the business unit and region of the people involved (IdP groups bu:<unit>, region:<region>), and
-- the most sensitive content seen. Unmask compares them with the analyst's binding attributes.
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS business_unit text NOT NULL DEFAULT '';
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS region        text NOT NULL DEFAULT '';
ALTER TABLE incident.incidents ADD COLUMN IF NOT EXISTS sensitivity   text NOT NULL DEFAULT '';

-- Four-eyes for restricted evidence: a second analyst approves one unmask by the requester, valid for an hour.
CREATE TABLE IF NOT EXISTS incident.unmask_requests (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id   uuid        NOT NULL REFERENCES incident.incidents(id),
  evidence_id   uuid        NOT NULL,
  requester     text        NOT NULL,
  justification text        NOT NULL,
  created_at    timestamptz NOT NULL,
  approver      text,
  approved_at   timestamptz,
  used_at       timestamptz
);
CREATE INDEX IF NOT EXISTS unmask_requests_incident ON incident.unmask_requests (incident_id, created_at);
