-- 0028 advisor notified list.  See the SQLite copy for the reasoning.
CREATE TABLE IF NOT EXISTS unmask_advisor_notified (
    id BIGINT NOT NULL AUTO_INCREMENT,
    target_type VARCHAR(8) NOT NULL COMMENT 'advisor candidate type: ip | ja4',
    target VARCHAR(64) NOT NULL COMMENT 'the announced address / fingerprint',
    notified_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) of the digest that carried it',
    PRIMARY KEY (id),
    UNIQUE KEY uq_advisor_notified (target_type, target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Advisor candidates already carried in a scheduled digest (so the next one reports only what is new)';
