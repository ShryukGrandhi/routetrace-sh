#!/usr/bin/env bash
# Minimal test runner: every function named test_* in tests/test_*.sh runs in
# its own subshell so global topology state never leaks between tests.
set -u
TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$TESTS/.." && pwd)
RT="$ROOT/bin/routetrace"
FIX="$TESTS/fixtures"
CAMPUS="$ROOT/examples/campus"
export ROOT RT FIX CAMPUS

# shellcheck source=/dev/null
. "$ROOT/lib/ipv4.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/cidr.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/rib.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/acl.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/topo.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/trace.sh"

fail() {
  echo "    FAIL: $*" >&2
  exit 1
}
assert_eq() { [[ "$1" == "$2" ]] || fail "${3:-assert_eq}: expected [$1] got [$2]"; }
assert_ok() { "$@" || fail "command failed: $*"; }
assert_fail() { ! "$@" >/dev/null 2>&1 || fail "command unexpectedly succeeded: $*"; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "${3:-assert_contains}: [$2] not found in [$1]"; }

pass=0 failed=0 failures=""
files=("$TESTS"/test_*.sh)
[[ $# -gt 0 ]] && files=("$@")
echo "bash $BASH_VERSION"
for f in "${files[@]}"; do
  before=$(declare -F | awk '{print $3}' | grep '^test_' | sort)
  # shellcheck source=/dev/null
  . "$f"
  after=$(declare -F | awk '{print $3}' | grep '^test_' | sort)
  for t in $(comm -13 <(echo "$before") <(echo "$after")); do
    if (set -u; "$t"); then
      pass=$((pass + 1))
      echo "  ok   ${f##*/} $t"
    else
      failed=$((failed + 1))
      failures+="  ${f##*/} $t"$'\n'
      echo "  FAIL ${f##*/} $t"
    fi
    unset -f "$t"
  done
done
echo "$pass passed, $failed failed"
[[ $failed -eq 0 ]] || { printf 'failures:\n%s' "$failures"; exit 1; }
