-- 0029 advisor last result.  See the SQLite copy for the reasoning.
CREATE TABLE IF NOT EXISTS unmask_advisor_result (
    key_hash CHAR(40) NOT NULL COMMENT 'sha1 hex of result_key (the key can be long: it carries the endpoint)',
    result_key VARCHAR(1024) NOT NULL COMMENT 'window|provider|model|endpoint|lang, readable',
    ran_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) the run finished',
    model VARCHAR(128) NOT NULL COMMENT 'model id the answer came from',
    payload MEDIUMTEXT NOT NULL COMMENT 'JSON: reviews, nominated rows, reverse DNS',
    err TEXT NOT NULL COMMENT 'non-empty when the run failed (payload then empty)',
    PRIMARY KEY (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='The advisor model''s last answer per window, kept across restarts';
