CREATE TABLE IF NOT EXISTS raw_logs (
 id BIGINT PRIMARY KEY AUTO_INCREMENT,
 received_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 event_time VARCHAR(64) NOT NULL, host_ip VARCHAR(45) NOT NULL,
 hostname VARCHAR(255) NOT NULL, facility VARCHAR(32), severity VARCHAR(32),
 program VARCHAR(255), message LONGTEXT NOT NULL, raw_line LONGTEXT NOT NULL,
 normalized_id BIGINT NULL,
 INDEX idx_raw_pending(normalized_id,id), INDEX idx_raw_host(host_ip,id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS events (
 id BIGINT PRIMARY KEY AUTO_INCREMENT,
 time VARCHAR(64) NOT NULL, time_jd DOUBLE NULL, raw_id BIGINT NULL UNIQUE,
 host_ip VARCHAR(45), hostname VARCHAR(255), src_ip VARCHAR(45), dst_ip VARCHAR(45),
 event VARCHAR(64) NOT NULL DEFAULT 'LOG', user VARCHAR(255), program VARCHAR(255),
 facility VARCHAR(32), severity VARCHAR(32), mitre VARCHAR(64), score INT NOT NULL DEFAULT 0,
 message LONGTEXT NOT NULL, raw_line LONGTEXT,
 INDEX idx_events_time(time_jd), INDEX idx_events_host_ip(host_ip,id),
 INDEX idx_events_src_ip(src_ip,id), INDEX idx_events_dst_ip(dst_ip,id),
 INDEX idx_events_event(event,id), INDEX idx_events_rule_time(host_ip,time_jd)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS anchors (
 id BIGINT PRIMARY KEY AUTO_INCREMENT, event_id BIGINT NOT NULL UNIQUE, held_at VARCHAR(64) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS soc_holds (event_id BIGINT PRIMARY KEY, held_at VARCHAR(64) NOT NULL) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS soc_bookmarks (
 event_id BIGINT PRIMARY KEY, saved_at VARCHAR(64) NOT NULL, event_json LONGTEXT NOT NULL,
 host_ip VARCHAR(45), src_ip VARCHAR(45), dst_ip VARCHAR(45), user VARCHAR(255), program VARCHAR(255),
 event VARCHAR(64), mitre VARCHAR(64), message LONGTEXT,
 INDEX idx_bookmarks_saved(saved_at,event_id), INDEX idx_bookmarks_host(host_ip)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS monitored_hosts (
 id BIGINT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255) NOT NULL, ip VARCHAR(45) NOT NULL UNIQUE,
 os_type VARCHAR(255) NOT NULL DEFAULT '', role VARCHAR(255) NOT NULL DEFAULT '', note TEXT NOT NULL,
 enabled INT NOT NULL DEFAULT 1, created_at VARCHAR(64) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS detection_rules (
 id BIGINT PRIMARY KEY AUTO_INCREMENT, host_id BIGINT NOT NULL,
 name VARCHAR(255) NOT NULL, attack VARCHAR(255) NOT NULL, reason TEXT NOT NULL,
 points INT NOT NULL, enabled INT NOT NULL DEFAULT 1, conditions LONGTEXT NOT NULL,
 match_mode VARCHAR(8) NOT NULL, min_hits INT NOT NULL, window_seconds INT NOT NULL,
 group_by VARCHAR(32) NOT NULL, created_at VARCHAR(64) NOT NULL, updated_at VARCHAR(64) NOT NULL,
 INDEX idx_detection_rules_host(host_id,enabled)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS analysis_results (
 event_id BIGINT PRIMARY KEY, raw_id BIGINT NULL, host_ip VARCHAR(45), src_ip VARCHAR(45),
 event VARCHAR(64), hour_key VARCHAR(13) NOT NULL, time_jd DOUBLE NULL,
 total_score INT NOT NULL, payload_json LONGTEXT NOT NULL, content_hash CHAR(64) NOT NULL,
 rules_version CHAR(64) NOT NULL, analyzed_at VARCHAR(64) NOT NULL,
 revision BIGINT NOT NULL DEFAULT 1, exported_revision BIGINT NOT NULL DEFAULT 0,
 INDEX idx_analysis_macro(host_ip,hour_key,event_id),
 INDEX idx_analysis_micro_src(src_ip,time_jd,event_id),
 INDEX idx_analysis_micro_event(event,time_jd,event_id),
 INDEX idx_analysis_risk(total_score,time_jd,event_id),
 INDEX idx_analysis_export(exported_revision,revision)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS analysis_rule_index (
 rule_id BIGINT NOT NULL, event_id BIGINT NOT NULL, time_jd DOUBLE NULL,
 PRIMARY KEY(rule_id,event_id), INDEX idx_rule_time(rule_id,time_jd,event_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS analysis_export_paths (
 event_id BIGINT PRIMARY KEY, paths_json LONGTEXT NOT NULL
) ENGINE=InnoDB;
