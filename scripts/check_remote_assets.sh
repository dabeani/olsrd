#!/usr/bin/env bash
set -euo pipefail

LIVE_HOST="193.238.158.74"
# derive repo root from script location so paths work from anywhere
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WWW_DIR="$REPO_ROOT/lib/olsrd-status-plugin/www"
INDEX="$WWW_DIR/index.html"

if [ ! -f "$INDEX" ]; then
  echo "Local index.html not found at $INDEX" >&2
  exit 2
fi

TMPDIR=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

echo "Scanning $INDEX for local asset references..."

ASSETS=()
# Extract href/src attributes using grep+sed to avoid bash =~ portability issues
while IFS= read -r val; do
  ASSETS+=("$val")
done < <(grep -oE 'href="[^"]+"|src="[^"]+"' "$INDEX" | sed -E 's/^(href|src)="([^"]+)"$/\2/')

# Filter unique, local relative paths that start with css/ or js/ or fonts/ or img/
UNIQ_ASSETS=()
seen_file="$TMPDIR/seen.txt"
touch "$seen_file"
for a in "${ASSETS[@]}"; do
  case "$a" in
    css/*|js/*|fonts/*|img/*|images/*)
      if ! grep -Fxq "$a" "$seen_file" 2>/dev/null; then
        echo "$a" >> "$seen_file"
        UNIQ_ASSETS+=("$a")
      fi
      ;;
  esac
done

if [ ${#UNIQ_ASSETS[@]} -eq 0 ]; then
  echo "No local assets found in index.html"
  exit 0
fi

echo "Found ${#UNIQ_ASSETS[@]} assets to compare:"
for a in "${UNIQ_ASSETS[@]}"; do echo "  $a"; done

echo
echo "Downloading remote assets from http://$LIVE_HOST/..."

DIFFS=()
MISSING=()
OK=()

for rel in "${UNIQ_ASSETS[@]}"; do
  local_path="$WWW_DIR/$rel"
  remote_url="http://$LIVE_HOST/$rel"
  # create a safe unique tmp filename based on the relative path to avoid collisions
  # replace '/' and spaces with '__'
  safe_name="$(printf '%s' "$rel" | tr '/ ' '__')"
  tmpfile="$TMPDIR/$safe_name"

  echo -n "- Fetching $remote_url ... "
  if curl -sfL --max-time 15 -o "$tmpfile" "$remote_url"; then
    echo "done"
  else
    echo "failed (server error or not found)"
    MISSING+=("$rel")
    continue
  fi

  if [ -f "$local_path" ]; then
    if cmp -s "$local_path" "$tmpfile"; then
      OK+=("$rel")
      echo "  identical to local"
    else
      DIFFS+=("$rel")
      echo "  differs from local"
    fi
  else
    echo "  local file missing: $local_path"
    MISSING+=("$rel")
  fi
done

echo
echo "Summary:"
echo "  identical: ${#OK[@]}"
if [ ${#OK[@]} -gt 0 ]; then
  for x in "${OK[@]}"; do echo "    $x"; done
fi
echo "  different: ${#DIFFS[@]}"
if [ ${#DIFFS[@]} -gt 0 ]; then
  for x in "${DIFFS[@]}"; do echo "    $x"; done
fi
echo "  missing/failed: ${#MISSING[@]}"
if [ ${#MISSING[@]} -gt 0 ]; then
  for x in "${MISSING[@]}"; do echo "    $x"; done
fi

if [ ${#DIFFS[@]} -gt 0 ]; then
  echo
  echo "Differing files (remote != local):"
  for f in "${DIFFS[@]}"; do
    echo "  $f"
  done
  exit 3
fi

if [ ${#MISSING[@]} -gt 0 ]; then
  echo
  echo "Some remote files were missing or could not be fetched."
  exit 4
fi

echo "All compared assets are identical to the remote copies."
exit 0
exit 0
