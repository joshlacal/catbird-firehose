#!/usr/bin/env bash
# Fail-closed check that the sibling checkouts Cargo builds against are exactly the commits
# recorded in scripts/canonical-sibling-provenance.env, with no local changes.
#
# Cargo.toml reaches Petrel and PetrelCatbird through `path = "../..."`, so without this
# check a build silently uses whatever happens to be checked out next door. Run it before
# every build that will be deployed, and in CI.
#
# A sibling may be a Git checkout (CI) or a jj checkout (local, colocated or a jj workspace):
#   Git: HEAD must equal the recorded commit and `git status --porcelain` must be empty.
#   jj:  the working copy must be the recorded commit, or an empty change directly on it.
# No path overrides are accepted; the siblings are the ones Cargo resolves from this
# repository's own manifest.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/scripts/canonical-sibling-provenance.env"

fail() {
  printf 'sibling provenance check FAILED: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || { printf 'usage: %s\n' "$0" >&2; exit 2; }
[[ -f "$manifest" ]] || fail "manifest not found: $manifest"
[[ -f "$repo_root/Cargo.lock" ]] || fail "Cargo.lock not found"
command -v jq >/dev/null || fail "jq is required"

manifest_value() {
  local value
  value=$(awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || fail "missing $1 in $manifest"
  printf '%s' "$value"
}

metadata=$(mktemp)
metadata_err=$(mktemp)
trap 'rm -f "$metadata" "$metadata_err"' EXIT
if ! cargo metadata --manifest-path "$repo_root/Cargo.toml" --format-version 1 --locked \
  >"$metadata" 2>"$metadata_err"; then
  cat "$metadata_err" >&2
  fail "locked cargo metadata failed"
fi

# verify_sibling <label> <dir-key> <commit-key> <package>...
verify_sibling() {
  local label=$1 dir_key=$2 commit_key=$3
  shift 3
  local rel root physical expected pkg resolved head status parent diff
  rel=$(manifest_value "$dir_key")
  expected=$(manifest_value "$commit_key")
  [[ "$expected" =~ ^[0-9a-f]{40}$ ]] || fail "$commit_key is not a full 40-character commit id: $expected"
  [[ -d "$repo_root/$rel" ]] || fail "$label sibling not found at $repo_root/$rel"
  root=$(cd "$repo_root/$rel" && pwd)
  physical=$(cd "$repo_root/$rel" && pwd -P)

  for pkg in "$@"; do
    resolved=$(jq -er --arg n "$pkg" \
      '[.packages[] | select(.name == $n) | .manifest_path] | if length == 1 then .[0] else error("expected exactly one package named " + $n) end' \
      "$metadata") || fail "Cargo did not resolve exactly one $pkg"
    if [[ "$resolved" != "$root"/* && "$resolved" != "$physical"/* ]]; then
      fail "Cargo resolved $pkg at $resolved, outside the checked $label sibling $root"
    fi
  done

  if [[ -d "$root/.jj" ]]; then
    # jj checkout (colocated or a secondary workspace). Checked before Git because
    # `git` in a secondary jj workspace walks up to an unrelated parent repository.
    head=$(cd "$root" && jj log -r @ --no-graph -T 'commit_id')
    parent=$(cd "$root" && jj --ignore-working-copy log -r '@-' --no-graph -T 'commit_id')
    if [[ "$head" != "$expected" && "$parent" != "$expected" ]]; then
      fail "$label is at @=$head (@-=$parent), expected $expected"
    fi
    diff=$(cd "$root" && jj diff --from "$expected" --to @ --summary)
    [[ -z "$diff" ]] || fail "$label has changes relative to $expected:
$diff"
  elif [[ -e "$root/.git" ]]; then
    head=$(git -C "$root" rev-parse HEAD)
    [[ "$head" == "$expected" ]] || fail "$label HEAD is $head, expected $expected"
    status=$(git -C "$root" status --porcelain --untracked-files=normal)
    [[ -z "$status" ]] || fail "$label working tree is not clean:
$status"
  else
    fail "$label at $root is neither a Git nor a jj checkout"
  fi
  printf '  %s %s (%s)\n' "$label" "$expected" "$root"
}

printf 'Checking sibling provenance for %s\n' "$repo_root"
verify_sibling Petrel PETREL_SIBLING_DIR PETREL_COMMIT petrel-core petrel-firehose petrel-api
verify_sibling PetrelCatbird PETREL_CATBIRD_SIBLING_DIR PETREL_CATBIRD_COMMIT petrel-catbird
printf 'sibling provenance verified\n'
