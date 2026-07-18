#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
resolver="$root/scripts/release-resolver.sh"
tests=0

fail() {
  printf 'not ok %s - %s\n' "$tests" "$1" >&2
  exit 1
}

assert_eq() {
  expected=$1
  actual=$2
  label=$3
  tests=$((tests + 1))
  if [ "$actual" != "$expected" ]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "$label"
  fi
  printf 'ok %s - %s\n' "$tests" "$label"
}

resolve() {
  printf '%b' "$3" | "$resolver" version "$1" "$2"
}

sha_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

output=$(resolve 2026.07.17 "$sha_a" '')
assert_eq $'version=2026.07.17.1\ntag=v2026.07.17.1' "$output" 'no tags starts at one'

rows="refs/tags/v2026.07.17.2\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.9\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.4\t$sha_b\tcommit\t$sha_b\tpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.10\ntag=v2026.07.17.10' "$output" 'multiple tags increment maximum'

rows="refs/tags/v2026.07.17.2\t$sha_a\tcommit\t$sha_a\tpublished
refs/tags/v2026.07.17.5\t$sha_a\tcommit\t$sha_a\tunpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.5\ntag=v2026.07.17.5' "$output" 'same-day commit reuses highest tag'

rows="refs/tags/v2026.07.01.1\t$sha_a\tcommit\t$sha_a\tpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.1\ntag=v2026.07.17.1' "$output" 'older published tag does not block new version'

rows="refs/tags/v2026.07.01.3\t$sha_a\tcommit\t$sha_a\tunpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.01.3\ntag=v2026.07.01.3' "$output" 'older unpublished tag is recovered'

rows="refs/tags/v2026.07.17.1\tannotated-object\ttag\t$sha_a\tunpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.1\ntag=v2026.07.17.1' "$output" 'annotated tag uses peeled commit'

rows="refs/tags/v2026.07.17.1\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.2\tannotated-object\ttag\t$sha_a\tpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.2\ntag=v2026.07.17.2' "$output" 'lightweight and annotated tags compare correctly'

rows="refs/tags/v2026.07.17.01\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.nope\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.08\t$sha_b\tcommit\t$sha_b\tpublished
refs/tags/v2026.07.17.8\t$sha_b\tcommit\t$sha_b\tpublished\n"
output=$(resolve 2026.07.17 "$sha_a" "$rows")
assert_eq $'version=2026.07.17.9\ntag=v2026.07.17.9' "$output" 'sequence parsing rejects invalid suffixes and is decimal safe'

output=$("$resolver" cadence schedule 2026-07-17T00:01:00Z '')
assert_eq $'run_date=2026-07-17\nversion_date=2026.07.17\nrelease_due=true' "$output" 'first scheduled release is due'

output=$("$resolver" cadence schedule 2026-07-14T00:00:00Z 2026-07-01T23:59:59Z)
assert_eq $'run_date=2026-07-14\nversion_date=2026.07.14\nrelease_due=false' "$output" 'scheduled release is not due before UTC boundary'

output=$("$resolver" cadence schedule 2026-07-15T00:00:00Z 2026-07-01T23:59:59Z)
assert_eq $'run_date=2026-07-15\nversion_date=2026.07.15\nrelease_due=true' "$output" 'scheduled release is due at fourteen calendar days'

output=$("$resolver" cadence workflow_dispatch 2026-07-02T00:00:00Z 2026-07-01T23:59:59Z)
assert_eq $'run_date=2026-07-02\nversion_date=2026.07.02\nrelease_due=true' "$output" 'manual dispatch is always due'

tests=$((tests + 1))
if "$resolver" validate-tag v2026.07.17.1 "$sha_a" "$sha_b" >/dev/null 2>&1; then
  fail 'candidate tag owned by another commit fails'
fi
printf 'ok %s - candidate tag owned by another commit fails\n' "$tests"

printf '1..%s\n' "$tests"
