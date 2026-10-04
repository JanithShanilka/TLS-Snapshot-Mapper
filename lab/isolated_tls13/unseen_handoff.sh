#!/bin/sh
# One-time gate: audit both transfer pilots before launching the frozen 40 cases.
set -eu
umask 077

controller=$1
pilot=$2
full=$3
historical=$4
volume=$5
pilot_unit=$6
full_unit=$7
selection=$controller/../selection.json
builds=$volume/firefox-unseen-builds

elapsed=0
while [ ! -f "$pilot/campaign-summary.json" ]; do
    source=$(findmnt -n -o SOURCE --target "$volume")
    fstype=$(findmnt -n -o FSTYPE --target "$volume")
    if [ "$source" != /dev/sdb ] || [ "$fstype" != ext4 ]; then
        systemctl stop "$pilot_unit" || true
        echo 'Separate evidence volume is not mounted; stopped the pilot.' >&2
        exit 1
    fi
    if ! systemctl is-active --quiet "$pilot_unit"; then
        echo 'Pilot stopped without a signed campaign summary; full campaign remains gated.' >&2
        exit 1
    fi
    if [ "$elapsed" -ge 3600 ]; then
        echo 'Pilot exceeded one-hour handoff wait; full campaign remains gated.' >&2
        exit 1
    fi
    sleep 10
    elapsed=$((elapsed + 10))
done

audit=$pilot/audit-final-20261004.json
test ! -e "$audit"
python3 "$controller/audit_unseen.py" --study "$pilot" --historical "$historical" \
    --selection "$selection" --controller "$controller" > "$audit.tmp"
python3 - "$audit.tmp" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1]))
if result['case_count'] != 2 or result['counts'] != {
        'scored': 2, 'failed': 0, 'captured': 0, 'attempted': 0, 'planned': 0} \
        or not result['summary_present']:
    raise SystemExit('Pilot seal audit or case accounting did not pass')
if any(any(method['false_assignments'] for method in row['methods'].values())
       for row in result['cases']):
    raise SystemExit('Pilot has a false assignment')
PY
mv "$audit.tmp" "$audit"

source=$(findmnt -n -o SOURCE --target "$volume")
fstype=$(findmnt -n -o FSTYPE --target "$volume")
if [ "$source" != /dev/sdb ] || [ "$fstype" != ext4 ]; then
    echo 'Separate evidence volume disappeared before full-campaign start.' >&2
    exit 1
fi
systemd-run --unit="$full_unit" --collect -p MemoryMax=14G -p MemorySwapMax=0 \
    -p TasksMax=512 -p RuntimeMaxSec=57600 /usr/bin/python3 "$controller/unseen_build.py" \
    --study "$full" --historical "$historical" --selection "$selection" \
    --builds "$builds" --volume "$volume" --run
echo 'Both pilots audited; frozen 40-case transfer campaign launched.'
