#!/usr/bin/env bash
set -euo pipefail

# sync_www.sh - safe rsync helper for olsrd-status-plugin www assets
#
# Usage:
#   ./scripts/sync_www.sh check [remote[:path]]    # show what would change (dry-run)
#   ./scripts/sync_www.sh push  [remote[:path]]    # push local -> remote (dry-run)
#   ./scripts/sync_www.sh pull  [remote[:path]]    # pull remote -> local (dry-run)
#
# To actually apply the changes, add --run before the remote argument:
#   ./scripts/sync_www.sh push --run user@193.238.158.74:/path/to/remote/www
#
# Defaults:
#   local path: lib/olsrd-status-plugin/www
#   remote default host: 193.238.158.74
#   remote default path: /usr/share/www

LOCAL_DIR="lib/olsrd-status-plugin/www"
DEFAULT_REMOTE_HOST="193.238.158.74"
DEFAULT_REMOTE_PATH="/usr/share/www"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 {check|push|pull} [--run] [remote[:path]]"
  exit 2
fi

MODE="$1"; shift
DO_RUN=false
if [ "${1:-}" = "--run" ]; then
  DO_RUN=true
  shift || true
fi

REMOTE_ARG="${1:-}"

if [ -z "$REMOTE_ARG" ]; then
  REMOTE_HOST="$DEFAULT_REMOTE_HOST"
  REMOTE_PATH="$DEFAULT_REMOTE_PATH"
else
  # allow forms: host or host:/path or user@host or user@host:/path
  if [[ "$REMOTE_ARG" == *":"* ]]; then
    REMOTE_HOST="${REMOTE_ARG%%:*}"
    REMOTE_PATH="${REMOTE_ARG#*:}"
  else
    REMOTE_HOST="$REMOTE_ARG"
    REMOTE_PATH="$DEFAULT_REMOTE_PATH"
  fi
fi

# rsync options: archive, verbose, compress, preserve perms, numeric-ids
RSYNC_BASE_OPTS=( -avz --numeric-ids --delete --exclude '.git' --exclude '*.map' )
# Use checksum to better detect changed files (slower but safer)
RSYNC_CHECK_OPTS=( --checksum )

function dry_run_rsync() {
  local SRC="$1"
  local DST="$2"
  echo "DRY RUN: rsync ${RSYNC_BASE_OPTS[*]} ${RSYNC_CHECK_OPTS[*]} \"$SRC\" \"$DST\""
  rsync "${RSYNC_BASE_OPTS[@]}" "${RSYNC_CHECK_OPTS[@]}" --dry-run --itemize-changes --human-readable --progress "$SRC" "$DST"
}

function real_rsync() {
  local SRC="$1"
  local DST="$2"
  echo "RUN: rsync ${RSYNC_BASE_OPTS[*]} ${RSYNC_CHECK_OPTS[*]} \"$SRC\" \"$DST\""
  rsync "${RSYNC_BASE_OPTS[@]}" "${RSYNC_CHECK_OPTS[@]}" --human-readable --progress "$SRC" "$DST"
}

case "$MODE" in
  check)
    echo "=== Compare local -> remote (what would be pushed) ==="
    dry_run_rsync "$LOCAL_DIR/" "${REMOTE_HOST}:${REMOTE_PATH}/"
    echo
    echo "=== Compare remote -> local (what would be pulled) ==="
    dry_run_rsync "${REMOTE_HOST}:${REMOTE_PATH}/" "$LOCAL_DIR/"
    ;;

  push)
    if [ "$DO_RUN" = false ]; then
      echo "(dry-run) Showing what would be pushed from local to remote"
      dry_run_rsync "$LOCAL_DIR/" "${REMOTE_HOST}:${REMOTE_PATH}/"
      echo "To actually push, re-run with: $0 push --run ${REMOTE_HOST}:${REMOTE_PATH}"
      exit 0
    fi
    echo "Pushing local -> remote"
    real_rsync "$LOCAL_DIR/" "${REMOTE_HOST}:${REMOTE_PATH}/"
    ;;

  pull)
    if [ "$DO_RUN" = false ]; then
      echo "(dry-run) Showing what would be pulled from remote to local"
      dry_run_rsync "${REMOTE_HOST}:${REMOTE_PATH}/" "$LOCAL_DIR/"
      echo "To actually pull, re-run with: $0 pull --run ${REMOTE_HOST}:${REMOTE_PATH}"
      exit 0
    fi
    echo "Pulling remote -> local"
    real_rsync "${REMOTE_HOST}:${REMOTE_PATH}/" "$LOCAL_DIR/"
    ;;

  *)
    echo "Unknown mode: $MODE" >&2
    echo "Usage: $0 {check|push|pull} [--run] [remote[:path]]" >&2
    exit 2
    ;;
esac

echo "Done."
