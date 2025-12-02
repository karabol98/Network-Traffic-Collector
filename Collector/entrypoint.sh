#!/bin/bash

log() {
    local level="$1"
    shift
    local message="$@"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message"
}

log INFO "Starting Litestream restore of ${LITESTREAM_LOCAL_DB_PATH}" && \
tmpfile=$(mktemp -u) && \
log INFO "Restoring backup to $tmpfile" && \
(timeout 10 litestream restore -o $tmpfile ${LITESTREAM_LOCAL_DB_PATH} || true) && \
if [ -f $tmpfile -a -s $tmpfile ]; then
    log INFO "Restored backup to $tmpfile, moving to ${LITESTREAM_LOCAL_DB_PATH}"
    mv $tmpfile ${LITESTREAM_LOCAL_DB_PATH}
else
    log WARNING "No backup retrieved, using the original database"
    test -f $tmpfile && rm $tmpfile || true
fi && \
log INFO "Starting database migrations" && \
alembic upgrade head && \
log INFO "Database migrations completed" && \
log INFO "Starting Litestream replication and application" && \
litestream replicate -exec "python3 collector.py"