-- The current connection of a source is the one with the highest sync epoch (allocated
-- under the source row lock), not the latest `opened_at` (the transaction start time).
DROP INDEX agent_connections_source_id_idx;
CREATE INDEX agent_connections_source_epoch_idx ON agent_connections (source_id, sync_epoch DESC);
