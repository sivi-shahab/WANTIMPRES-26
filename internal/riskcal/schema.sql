-- Risk weight calibration (ticket 25, spec FR-RISK-3). Idempotent: applied by riskcal.Open.
CREATE SCHEMA IF NOT EXISTS riskcal;

-- A version of data.wantimpres26.risk.config. At most one is active; none active = the built-in config in the bundle.
CREATE TABLE IF NOT EXISTS riskcal.versions (
  tenant_id    uuid        NOT NULL,
  version      int         NOT NULL,
  state        text        NOT NULL CHECK (state IN ('draft', 'simulated', 'pending_approval', 'active', 'retired')),
  config       jsonb       NOT NULL,
  basis        jsonb,       -- how a proposed version was fitted (labels, coefficients)
  report       jsonb,       -- the last simulation
  author       text        NOT NULL,
  approver     text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  PRIMARY KEY (tenant_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS versions_one_active ON riskcal.versions (tenant_id) WHERE state = 'active';
