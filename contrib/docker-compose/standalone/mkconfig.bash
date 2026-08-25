#!/bin/bash

HERE=$(cd "$(dirname "$0")"; pwd)
set -eua

[ -f "$HERE/.env" ] || { echo "Environment file not found; you must run ./mksite.bash first" ; exit 1; }

# Check for migrations
if ! grep -q PG_DATA_MOUNT= "$HERE/.env"; then
	cat <<EOF

-----------------------------------------------------------------------
WARNING: Site configuration migration is required.

Please run 'mksite.bash' to update your site configuration.
-----------------------------------------------------------------------

EOF
	exit 1
fi

if ! grep -q responseTemplate "$HERE/hockeypuck/etc/hockeypuck.conf"; then
	sed -i '/statsTemplate=/a \
responseTemplate="/hockeypuck/lib/templates/response.html.tmpl"' "$HERE/hockeypuck/etc/hockeypuck.conf"
fi
