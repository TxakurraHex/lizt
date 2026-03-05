#!/usr/bin/env bash

sudo -u postgres psql lizt <<'EOF'
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
ALTER SCHEMA public OWNER TO lizt;
EOF
