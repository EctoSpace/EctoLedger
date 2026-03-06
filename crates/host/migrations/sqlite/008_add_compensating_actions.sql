-- Compensating actions / rollback protocol (SQLite).
--
-- Mirrors PostgreSQL migration 20260222000011_add_compensating_actions.sql.
-- Extends agent_action_log so that each executed intent can carry a linked
-- compensating (rollback) action.
ALTER TABLE agent_action_log
    ADD COLUMN compensating_action TEXT;

ALTER TABLE agent_action_log
    ADD COLUMN compensation_status TEXT
        CHECK (compensation_status IN ('proposed', 'executing', 'executed', 'failed', 'skipped'));
