# PurpleLoop Zeek config.
@load policy/tuning/json-logs          # emit every log as JSON (Wazuh reads JSON)
@load protocols/ssh
@load protocols/http
@load frameworks/notice

# Disable rotation so filenames stay stable (conn.log, ssh.log, ...) and Wazuh
# can tail them continuously instead of chasing hourly rotated subdirectories.
redef Log::default_rotation_interval = 0 secs;
