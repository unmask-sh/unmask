-- 0027 advisor dismiss list.  See the SQLite copy for the reasoning.
CREATE TABLE IF NOT EXISTS unmask_advisor_dismiss (
    id BIGINT NOT NULL AUTO_INCREMENT,
    target_type VARCHAR(8) NOT NULL COMMENT 'advisor candidate type: ip | ja4',
    target VARCHAR(64) NOT NULL COMMENT 'the dismissed address / fingerprint',
    dismissed_by VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'admin username that clicked dismiss',
    dismissed_at BIGINT NOT NULL COMMENT 'unix seconds (UTC)',
    PRIMARY KEY (id),
    UNIQUE KEY uq_advisor_dismiss (target_type, target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Operator-dismissed advisor ban candidates (suppresses re-proposal)';
