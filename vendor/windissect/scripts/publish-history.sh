#!/usr/bin/env bash
# Records one or more IR builds into a target's ReWindows repo checkout so the
# repo accumulates every observed build (not just the latest), letting anyone
# clone it and diff whichever two builds they want:
#
#   windissect diff history/<target>/builds/<A>/ir.json history/<target>/builds/<B>/ir.json
#
# Usage: publish-history.sh <windissect-exe> <repo-dir> <ir-json> [<ir-json> ...]
#
# <repo-dir> must be a git checkout of the ReWindows/<target> repo. This
# script only stages the recorded history locally -- it never commits or
# pushes, so the caller reviews `git status`/`git diff` before doing either.
set -euo pipefail

WINDISSECT="$1"; shift
REPO_DIR="$1"; shift

if [ "$#" -eq 0 ]; then
  echo "usage: publish-history.sh <windissect-exe> <repo-dir> <ir-json> [<ir-json> ...]" >&2
  exit 1
fi

mkdir -p "$REPO_DIR/history"

for ir in "$@"; do
  echo "[*] recording $ir into $REPO_DIR/history"
  "$WINDISSECT" record-build "$ir" --history "$REPO_DIR/history"
done

echo "[*] done. review with: git -C \"$REPO_DIR\" status"
