-- Reference migration for PostgreSQL deployments. The local MVP uses the same
-- logical schema in SQLite so it can start without external credentials.
CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY, timestamp TIMESTAMPTZ NOT NULL, site_id TEXT NOT NULL,
  source_ip INET NOT NULL, path TEXT NOT NULL, method TEXT NOT NULL,
  event_type TEXT NOT NULL, alerts JSONB NOT NULL, severity TEXT NOT NULL,
  action TEXT NOT NULL, rule_id TEXT, reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS security_events_site_time ON security_events(site_id, timestamp DESC);
