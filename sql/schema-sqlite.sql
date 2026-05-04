-- unmask_event: challenge funnel + behavioral beacon
--
-- phase の取りうる値:
--   serve       admin が challenge HTML を 403 で返した瞬間
--   load        challenge HTML 上で JS が起動した
--   pow         PoW 計算完了 (= djb2 hash 一致)
--   captcha     CAPTCHA UI 表示 (= JA4 hit or PoW skip)
--   verify_ok   verify endpoint で _bv 発行成功
--   verify_ng   verify endpoint で score 不足 / answer 不正
--   cookie_err  reload 後も _bv が読めず loop 検知
--   error       JS 内 try/catch 等で例外捕捉
--
-- ip_address は IPv4=4byte / IPv6=16byte の packed binary.
-- SQLite は BLOB で受ける. MariaDB 側は VARBINARY(16).
CREATE TABLE IF NOT EXISTS unmask_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site            VARCHAR(64) NOT NULL DEFAULT 'default',
    ip_address      BLOB NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    phase           VARCHAR(16) NOT NULL,
    flags           INTEGER NOT NULL DEFAULT 0,
    reload_count    INTEGER NOT NULL DEFAULT 0,
    cookie_bv       VARCHAR(80),
    cookie_br       VARCHAR(8),
    payload_json    TEXT,
    date_created    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_unmask_event_date     ON unmask_event(date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_ip_date  ON unmask_event(ip_address, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_phase    ON unmask_event(phase, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_verdict  ON unmask_event(ja4_verdict, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_site     ON unmask_event(site, date_created);

-- unmask_aggregate: 日次集計の cache. dashboard を毎回 full scan させないため.
-- unmask-cli aggregate コマンドで前日分以前を埋める.
CREATE TABLE IF NOT EXISTS unmask_aggregate (
    bucket_date     DATE NOT NULL,
    bucket_kind     VARCHAR(16) NOT NULL,   -- 'phase' / 'verdict' / 'verdict_phase'
    bucket_key      VARCHAR(64) NOT NULL,
    cnt             INTEGER NOT NULL,
    PRIMARY KEY (bucket_date, bucket_kind, bucket_key)
);

CREATE INDEX IF NOT EXISTS idx_unmask_aggregate_date ON unmask_aggregate(bucket_date);

-- unmask_aggregate_state: aggregate が「どこまで処理したか」の state (id 単調増加前提)
CREATE TABLE IF NOT EXISTS unmask_aggregate_state (
    name            VARCHAR(32) PRIMARY KEY,
    last_id         INTEGER NOT NULL DEFAULT 0,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
