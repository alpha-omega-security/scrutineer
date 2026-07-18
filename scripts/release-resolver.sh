#!/usr/bin/env bash
# Pure release cadence and CalVer resolution. Keep this compatible with macOS
# bash 3.2 and BSD userland so it can be exercised locally as well as in CI.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  release-resolver.sh cadence EVENT CREATED_AT [LAST_PUBLISHED_AT]
  release-resolver.sh version VERSION_DATE COMMIT_SHA < tags.tsv
  release-resolver.sh validate-tag TAG COMMIT_SHA [EXISTING_COMMIT_SHA]

tags.tsv columns:
  ref  object_sha  object_type  commit_sha  release_state

object_type is commit or tag. commit_sha must be the peeled commit for annotated
tags. release_state is published, unpublished, or unknown.
EOF
  exit 2
}

fail() {
  printf '%s\n' "error: $*" >&2
  exit 1
}

date_fields() {
  printf '%s\n' "$1" | awk '
    match($0, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) != 1 { exit 1 }
    {
      y = substr($0, 1, 4) + 0
      m = substr($0, 6, 2) + 0
      d = substr($0, 9, 2) + 0
      leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))
      max = 31
      if (m == 4 || m == 6 || m == 9 || m == 11) max = 30
      if (m == 2) max = 28 + leap
      if (m < 1 || m > 12 || d < 1 || d > max) exit 1

      # Howard Hinnant civil-date conversion, yielding comparable day numbers.
      yy = y - (m <= 2)
      era = int(yy / 400)
      yoe = yy - era * 400
      mp = m + (m > 2 ? -3 : 9)
      doy = int((153 * mp + 2) / 5) + d - 1
      doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
      days = era * 146097 + doe
      printf "%04d-%02d-%02d\t%04d.%02d.%02d\t%d\n", y, m, d, y, m, d, days
    }
  '
}

cadence() {
  [ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
  event=$1
  created_at=$2
  last_published_at=${3-}

  run_fields=$(date_fields "$created_at") || fail "invalid run created_at: $created_at"
  run_date=$(printf '%s\n' "$run_fields" | awk -F '\t' '{ print $1 }')
  version_date=$(printf '%s\n' "$run_fields" | awk -F '\t' '{ print $2 }')
  run_days=$(printf '%s\n' "$run_fields" | awk -F '\t' '{ print $3 }')

  release_due=true
  if [ "$event" = schedule ] && [ -n "$last_published_at" ]; then
    published_fields=$(date_fields "$last_published_at") || \
      fail "invalid last published_at: $last_published_at"
    published_days=$(printf '%s\n' "$published_fields" | awk -F '\t' '{ print $3 }')
    if [ "$run_days" -lt $((published_days + 14)) ]; then
      release_due=false
    fi
  fi

  printf 'run_date=%s\nversion_date=%s\nrelease_due=%s\n' \
    "$run_date" "$version_date" "$release_due"
}

version() {
  [ "$#" -eq 2 ] || usage
  version_date=$1
  commit_sha=$2
  case "$version_date" in
    ????\.??\.??) ;;
    *) fail "invalid version date: $version_date" ;;
  esac
  date_fields=$(date_fields "$(printf '%s' "$version_date" | tr . -)") || \
    fail "invalid version date: $version_date"
  normalized=$(printf '%s\n' "$date_fields" | awk -F '\t' '{ print $2 }')
  [ "$normalized" = "$version_date" ] || fail "invalid version date: $version_date"

  awk -F '\t' -v version_date="$version_date" -v wanted_sha="$commit_sha" '
    function valid_tag(tag) {
      return tag ~ /^v[0-9][0-9][0-9][0-9]\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[1-9][0-9]*$/
    }
    function numeric_sequence(tag, prefix, value) {
      value = substr(tag, length(prefix) + 1)
      if (value !~ /^[1-9][0-9]*$/) return -1
      # Force decimal arithmetic; awk has no shell-style octal interpretation.
      return value + 0
    }
    BEGIN {
      prefix = "v" version_date "."
      max_sequence = 0
      same_date_sequence = 0
      recover_tag = ""
    }
    NF == 0 { next }
    NF != 5 { print "error: malformed tag row at line " NR > "/dev/stderr"; exit 1 }
    {
      ref = $1
      object_sha = $2
      object_type = $3
      tag_sha = $4
      release_state = $5
      if (ref !~ /^refs\/tags\//) { print "error: invalid tag ref: " ref > "/dev/stderr"; exit 1 }
      if (object_type != "commit" && object_type != "tag") {
        print "error: invalid object type for " ref ": " object_type > "/dev/stderr"; exit 1
      }
      if (object_type == "commit" && object_sha != tag_sha) {
        print "error: lightweight tag was not resolved directly: " ref > "/dev/stderr"; exit 1
      }
      tag = substr(ref, 11)
      if (!valid_tag(tag)) next

      sequence = index(tag, prefix) == 1 ? numeric_sequence(tag, prefix) : -1
      if (sequence >= 0) {
        if (sequence > max_sequence) max_sequence = sequence
        if (tag_sha == wanted_sha && sequence > same_date_sequence) {
          same_date_sequence = sequence
        }
      }

      if (tag_sha == wanted_sha && release_state == "unpublished") {
        split(substr(tag, 2), parts, ".")
        newer = recover_tag == "" || parts[1] > recover_y || \
          (parts[1] == recover_y && parts[2] > recover_m) || \
          (parts[1] == recover_y && parts[2] == recover_m && parts[3] > recover_d) || \
          (parts[1] == recover_y && parts[2] == recover_m && parts[3] == recover_d && parts[4] > recover_n)
        if (newer) {
          recover_y = parts[1]
          recover_m = parts[2]
          recover_d = parts[3]
          recover_n = parts[4]
          recover_tag = tag
        }
      } else if (release_state != "published" && release_state != "unpublished" && release_state != "unknown") {
        print "error: invalid release state for " tag ": " release_state > "/dev/stderr"; exit 1
      }
    }
    END {
      if (same_date_sequence > 0) {
        tag = prefix same_date_sequence
      } else if (recover_tag != "") {
        tag = recover_tag
      } else {
        tag = prefix (max_sequence + 1)
      }
      print "version=" substr(tag, 2)
      print "tag=" tag
    }
  '
}

validate_tag() {
  [ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
  tag=$1
  commit_sha=$2
  existing_sha=${3-}
  if [ -n "$existing_sha" ] && [ "$existing_sha" != "$commit_sha" ]; then
    fail "tag $tag already points to $existing_sha, not $commit_sha"
  fi
  printf 'tag_valid=true\n'
}

[ "$#" -gt 0 ] || usage
command=$1
shift
case "$command" in
  cadence) cadence "$@" ;;
  version) version "$@" ;;
  validate-tag) validate_tag "$@" ;;
  *) usage ;;
esac
