-- Compensating actions / rollback protocol.
--
-- Extends agent_action_log so that each executed intent can carry a linked
-- compensating (rollback) action that is proposed and optionally auto-executed
-- when a tripwire or policy violation detected the action after execution.
--
-- Lifecycle:
--   1. Agent proposes and executes an action.
--   2. Tripwire / policy detects a violation AFTER execution (e.g. a banned
--      pattern that could not be caught pre-execution).
--   3. CompensationPlanner looks up a rollback rule matching the action type.
--   4. If found, the compensating_action JSONB is populated and
--      compensation_status moves from NULL to 'proposed'.
--   5. On successful compensating execution: 'executed'.
--   6. On failure or no matching rule: 'skipped' / 'failed'.
ALTER TABLE agent_action_log
    ADD COLUMN IF NOT EXISTS compensating_action   JSONB,
    ADD COLUMN IF NOT EXISTS compensation_status   VARCHAR(16)
        CHECK (compensation_status IN ('proposed', 'executing', 'executed', 'failed', 'skipped'));
