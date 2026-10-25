-- Policy lifecycle (spec §4.7 FR-POL-5..7). Idempotent: applied by lifecycle.Open.
CREATE SCHEMA IF NOT EXISTS policy;

CREATE TABLE IF NOT EXISTS policy.policies (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL UNIQUE,
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- A version's rules are the engine's rule DSL (policy/wantimpres26/decision.rego), never raw Rego.
CREATE TABLE IF NOT EXISTS policy.versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id     uuid        NOT NULL REFERENCES policy.policies(id),
  version       int         NOT NULL,
  state         text        NOT NULL CHECK (state IN ('draft','simulated','pending_approval','active','retired')),
  rules         jsonb       NOT NULL,
  author        text        NOT NULL,
  approver      text,
  simulation_id uuid,
  created_at    timestamptz NOT NULL DEFAULT now(),
  published_at  timestamptz,
  retired_at    timestamptz,
  UNIQUE (policy_id, version)
);
-- At most one active version per policy.
CREATE UNIQUE INDEX IF NOT EXISTS versions_one_active ON policy.versions (policy_id) WHERE state = 'active';

-- An exception lifts named rules for a scope until expires_at (FR-POL-7). Expiry is mandatory.
CREATE TABLE IF NOT EXISTS policy.exceptions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rules         text[]      NOT NULL CHECK (cardinality(rules) > 0),
  scope         jsonb       NOT NULL,
  reason        text        NOT NULL,
  requested_by  text        NOT NULL,
  approver      text,
  state         text        NOT NULL CHECK (state IN ('pending','active','revoked','expired')),
  expires_at    timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  approved_at   timestamptz,
  notified_at   timestamptz
);

-- Every publish, rollback, retire and exception change is a release: the full snapshot sidecars run.
CREATE TABLE IF NOT EXISTS policy.releases (
  number      bigserial   PRIMARY KEY,
  rules       jsonb       NOT NULL,  -- data.wantimpres26.rules
  exceptions  jsonb       NOT NULL,  -- data.wantimpres26.exceptions
  data        jsonb       NOT NULL DEFAULT '{}',  -- other documents by dotted path, e.g. wantimpres26.catalog (ticket 16)
  reason      text        NOT NULL,
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE policy.releases ADD COLUMN IF NOT EXISTS data jsonb NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS policy.simulations (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version_id     uuid        NOT NULL REFERENCES policy.versions(id),
  rules_digest   text        NOT NULL,
  state          text        NOT NULL CHECK (state IN ('running','done','failed')),
  window_from    timestamptz NOT NULL,
  window_to      timestamptz NOT NULL,
  include_corpus boolean     NOT NULL,
  result         jsonb,
  error          text,
  created_by     text        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz
);
