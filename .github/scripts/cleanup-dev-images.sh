#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME="${PACKAGE_NAME:-uscf}"
KEEP_COUNT="${KEEP_COUNT:-10}"
OWNER="${OWNER:-${GITHUB_REPOSITORY_OWNER:-}}"
EVENT_PATH="${GITHUB_EVENT_PATH:-}"
PACKAGE_VERSIONS_FILE="${PACKAGE_VERSIONS_FILE:-}"
DRY_RUN="${DRY_RUN:-false}"

if [[ -z "$OWNER" ]]; then
  echo "OWNER or GITHUB_REPOSITORY_OWNER must be set" >&2
  exit 1
fi

if ! [[ "$KEEP_COUNT" =~ ^[0-9]+$ ]]; then
  echo "KEEP_COUNT must be a non-negative integer, got: $KEEP_COUNT" >&2
  exit 1
fi

resolve_owner_type() {
  if [[ -n "${OWNER_TYPE:-}" ]]; then
    printf '%s\n' "$OWNER_TYPE"
    return
  fi

  if [[ -n "$EVENT_PATH" && -f "$EVENT_PATH" ]]; then
    local owner_type
    owner_type="$(
      jq -r '
        .workflow_run.repository.owner.type //
        .repository.owner.type //
        empty
      ' "$EVENT_PATH"
    )"
    if [[ -n "$owner_type" ]]; then
      printf '%s\n' "$owner_type"
      return
    fi
  fi

  printf 'User\n'
}

fetch_versions_json() {
  if [[ -n "$PACKAGE_VERSIONS_FILE" ]]; then
    jq -c '.[]' "$PACKAGE_VERSIONS_FILE"
    return
  fi

  local owner_type api_root endpoint
  owner_type="$(resolve_owner_type)"

  if [[ "$owner_type" == "Organization" ]]; then
    api_root="/orgs/${OWNER}"
  else
    api_root="/users/${OWNER}"
  fi

  endpoint="${api_root}/packages/container/${PACKAGE_NAME}/versions?per_page=100"

  echo "Owner: ${OWNER}" >&2
  echo "Owner type: ${owner_type}" >&2
  echo "Package: ${PACKAGE_NAME}" >&2
  echo "Fetching package versions from: ${endpoint}" >&2

  gh api \
    --method GET \
    --paginate \
    -H "Accept: application/vnd.github+json" \
    "$endpoint" \
    --jq '.[]'
}

VERSIONS_JSON="$(
  fetch_versions_json | jq -s '
    map(select((.metadata.container.tags // []) | length > 0))
  '
)"

export KEEP_COUNT

analyze_bucket() {
  local bucket_name="$1"
  local tag_pattern="$2"

  VERSIONS_JSON="$VERSIONS_JSON" BUCKET_NAME="$bucket_name" TAG_PATTERN="$tag_pattern" \
  jq -r '
    def tags: (.metadata.container.tags // []);
    def protected_tag:
      . == "latest" or
      . == "wg-latest" or
      test("^[0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?$") or
      test("^wg-[0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?$");
    def deletable_for_bucket:
      (tags | length > 0) and
      (tags | all(test(env.TAG_PATTERN))) and
      (tags | all(protected_tag | not));
    [ .[] | select(deletable_for_bucket) ]
    | sort_by(.created_at)
    | reverse as $candidates
    | (env.BUCKET_NAME + "_candidates\t" + ($candidates | length | tostring)),
      (env.BUCKET_NAME + "_kept\t" + ($candidates[:(env.KEEP_COUNT | tonumber)] | length | tostring)),
      (env.BUCKET_NAME + "_deleted\t" + ($candidates[(env.KEEP_COUNT | tonumber):] | length | tostring)),
      ($candidates[(env.KEEP_COUNT | tonumber):][] | @base64)
  ' <<<"$VERSIONS_JSON"
}

delete_version() {
  local version_id="$1"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN delete version id=${version_id}"
    return
  fi

  local owner_type api_root endpoint
  owner_type="$(resolve_owner_type)"
  if [[ "$owner_type" == "Organization" ]]; then
    api_root="/orgs/${OWNER}"
  else
    api_root="/users/${OWNER}"
  fi
  endpoint="${api_root}/packages/container/${PACKAGE_NAME}/versions/${version_id}"

  gh api \
    --method DELETE \
    -H "Accept: application/vnd.github+json" \
    "$endpoint"
}

decode_base64() {
  if base64 --help >/dev/null 2>&1; then
    printf '%s' "$1" | base64 --decode
  else
    printf '%s' "$1" | base64 -D
  fi
}

process_bucket() {
  local bucket_name="$1"
  local tag_pattern="$2"
  local line key value

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue

    if [[ "$line" == *$'\t'* ]]; then
      key="${line%%$'\t'*}"
      value="${line#*$'\t'}"
      case "$key" in
        "${bucket_name}_candidates")
          echo "${bucket_name}: candidates=${value}"
          ;;
        "${bucket_name}_kept")
          echo "${bucket_name}: keeping=${value}"
          ;;
        "${bucket_name}_deleted")
          echo "${bucket_name}: deleting=${value}"
          ;;
      esac
      continue
    fi

    local decoded version_id created_at tags_csv
    decoded="$(decode_base64 "$line")"
    version_id="$(jq -r '.id' <<<"$decoded")"
    created_at="$(jq -r '.created_at' <<<"$decoded")"
    tags_csv="$(jq -r '(.metadata.container.tags // []) | join(",")' <<<"$decoded")"

    echo "${bucket_name}: deleting version_id=${version_id} created_at=${created_at} tags=${tags_csv}"
    delete_version "$version_id"
  done < <(analyze_bucket "$bucket_name" "$tag_pattern")
}

process_bucket "dev" '^dev-[0-9a-f]{7,}$'
process_bucket "wg-dev" '^wg-dev-[0-9a-f]{7,}$'
