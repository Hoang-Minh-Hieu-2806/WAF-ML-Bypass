#!/bin/sh
# Run once as root in a network-disabled init container; never truncate evidence.
set -eu
mkdir -p /evidence
touch /evidence/audit.log
chown 101:101 /evidence /evidence/audit.log
chmod 0750 /evidence
chmod 0640 /evidence/audit.log
