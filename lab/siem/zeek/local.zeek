# Zeek config for the lab sensor.
# Keep it minimal: Zeek's default scripts already produce conn.log / ssh.log /
# http.log / notice.log. We only change two things:
#   1. emit logs as JSON (Wazuh ingests JSON), and
#   2. disable rotation so filenames stay stable (conn.log, not hourly subdirs)
#      which lets Wazuh tail them continuously.
# NOTE: do NOT `@load protocols/ssh` etc. by short name — those paths don't
# resolve (the scripts live under base/ and are auto-loaded) and Zeek fatal-exits.
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0 secs;
