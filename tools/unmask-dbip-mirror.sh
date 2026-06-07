#!/bin/bash
# Mirror the current DB-IP Lite country + ASN mmdb into unmask.sh /dl/ipgeo/.
#
# DB-IP Lite is CC BY 4.0 -- redistribution is allowed with attribution (see the
# NOTICE.txt this script writes alongside the data).  We re-host the unmodified
# monthly snapshot so `unmask install-ipgeo` can pull from a stable unmask.sh URL
# instead of depending on db-ip.com's month-stamped path (which 404s for a few
# days at each month boundary).
#
# Runs monthly from /etc/cron.d/unmask-dbip-mirror.  Atomic: each file is written
# to a temp name in the destination dir and renamed, so nginx never serves a
# half-written file.  On a failed/invalid download the previous file is kept.
set -eu

DEST=${UNMASK_IPGEO_DIR:-/var/www/unmask.sh/dl/ipgeo}
mkdir -p "$DEST"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ym=$(date -u +%Y-%m)
pm=$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)

ok=1
for kind in country asn; do
	out="$TMP/dbip-${kind}-lite.mmdb.gz"
	# current month, falling back to the previous month (new months publish a
	# few days late).
	if curl -fsSL "https://download.db-ip.com/free/dbip-${kind}-lite-${ym}.mmdb.gz" -o "$out" \
		|| curl -fsSL "https://download.db-ip.com/free/dbip-${kind}-lite-${pm}.mmdb.gz" -o "$out"; then
		if gzip -t "$out" 2>/dev/null && [ "$(stat -c%s "$out")" -gt 100000 ]; then
			cp "$out" "$DEST/.dbip-${kind}-lite.mmdb.gz.tmp"
			chmod 0644 "$DEST/.dbip-${kind}-lite.mmdb.gz.tmp"
			mv -f "$DEST/.dbip-${kind}-lite.mmdb.gz.tmp" "$DEST/dbip-${kind}-lite.mmdb.gz"
			echo "dbip-mirror: ${kind} ok ($(stat -c%s "$out") bytes)"
		else
			echo "dbip-mirror: ${kind} downloaded but invalid (gzip/size) -- keeping previous" >&2
			ok=0
		fi
	else
		echo "dbip-mirror: ${kind} download failed for $ym and $pm -- keeping previous" >&2
		ok=0
	fi
done

# Attribution / license notice required by CC BY 4.0.
cat > "$DEST/NOTICE.txt" <<'NOTICE'
This directory re-hosts the DB-IP Lite IP geolocation databases:

  dbip-country-lite.mmdb.gz  - IP to Country Lite
  dbip-asn-lite.mmdb.gz      - IP to ASN Lite

Attribution:  IP Geolocation by DB-IP -- https://db-ip.com
License:      Creative Commons Attribution 4.0 International (CC BY 4.0)
              https://creativecommons.org/licenses/by/4.0/

These are UNMODIFIED copies of the upstream DB-IP Lite databases, re-hosted for
reliability and refreshed monthly. The originals (and the commercial databases,
which carry no attribution requirement) are at https://db-ip.com .
NOTICE
chmod 0644 "$DEST/NOTICE.txt"

if [ "$ok" = 1 ]; then
	date -u +%Y-%m-%dT%H:%M:%SZ > "$DEST/LAST_MIRRORED"
	chmod 0644 "$DEST/LAST_MIRRORED"
	echo "dbip-mirror: done ($ym)"
else
	echo "dbip-mirror: completed with errors (previous files kept)" >&2
	exit 1
fi
