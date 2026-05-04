-- MariaDB / MySQL 版.  SQLite 版と列構成は揃える.
-- 文字 set は utf8mb4. ja4 / ja4_verdict 等は ASCII のみだが UA は絵文字等含み得る.

CREATE TABLE IF NOT EXISTS unmask_event (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address      VARBINARY(16) NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    phase           VARCHAR(16) NOT NULL,
    flags           INT NOT NULL DEFAULT 0,
    reload_count    INT NOT NULL DEFAULT 0,
    cookie_bv       VARCHAR(80),
    cookie_br       VARCHAR(8),
    payload_json    LONGTEXT,
    date_created    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_date     (date_created),
    KEY idx_ip_date  (ip_address, date_created),
    KEY idx_phase    (phase, date_created),
    KEY idx_verdict  (ja4_verdict, date_created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_aggregate (
    bucket_date     DATE NOT NULL,
    bucket_kind     VARCHAR(16) NOT NULL,
    bucket_key      VARCHAR(64) NOT NULL,
    cnt             INT NOT NULL,
    PRIMARY KEY (bucket_date, bucket_kind, bucket_key),
    KEY idx_date (bucket_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_aggregate_state (
    name            VARCHAR(32) NOT NULL,
    last_id         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
