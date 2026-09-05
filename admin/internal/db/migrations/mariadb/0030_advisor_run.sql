-- 0030 advisor run log.  See the SQLite copy for the reasoning.
CREATE TABLE IF NOT EXISTS unmask_advisor_run (
    id BIGINT NOT NULL AUTO_INCREMENT COMMENT 'row id',
    ran_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) the attempt finished',
    result_key VARCHAR(1024) NOT NULL COMMENT 'window|provider|model|endpoint|lang, readable',
    model VARCHAR(128) NOT NULL COMMENT 'model id the attempt used',
    reviewed INT NOT NULL DEFAULT 0 COMMENT 'candidates sent to the model',
    kept INT NOT NULL DEFAULT 0 COMMENT 'candidates whose review was carried over (nothing sent)',
    in_tokens INT NOT NULL DEFAULT 0 COMMENT 'input tokens the provider reported (0 = not reported)',
    out_tokens INT NOT NULL DEFAULT 0 COMMENT 'output tokens the provider reported',
    err TEXT NOT NULL COMMENT 'non-empty when the attempt failed',
    PRIMARY KEY (id),
    KEY idx_unmask_advisor_run_ran_at (ran_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='One row per advisor model call (or failed attempt): what the last 30 days cost in tokens';
