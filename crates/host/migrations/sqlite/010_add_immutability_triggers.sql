-- SQLite immutability triggers for agent_events.
-- Mirrors the Postgres prevent_updates() trigger from migration 20250219000001.
-- SQLite supports BEFORE UPDATE / BEFORE DELETE triggers natively since 3.8.3.

-- Block UPDATE on agent_events — ledger rows are append-only.
CREATE TRIGGER IF NOT EXISTS agent_events_no_update
  BEFORE UPDATE ON agent_events
  FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'agent_events is append-only; UPDATE is not allowed.');
END;

-- Block DELETE on agent_events — ledger rows are append-only.
CREATE TRIGGER IF NOT EXISTS agent_events_no_delete
  BEFORE DELETE ON agent_events
  FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'agent_events is append-only; DELETE is not allowed.');
END;

-- Block UPDATE on agent_event_signatures — signatures are immutable.
CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_update
  BEFORE UPDATE ON agent_event_signatures
  FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'agent_event_signatures is append-only; UPDATE is not allowed.');
END;

-- Block DELETE on agent_event_signatures — signatures are immutable.
CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_delete
  BEFORE DELETE ON agent_event_signatures
  FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'agent_event_signatures is append-only; DELETE is not allowed.');
END;
