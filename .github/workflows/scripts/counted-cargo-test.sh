#!/bin/sh
# Run a cargo test invocation, print its output UNCONDITIONALLY, then assert the
# number of tests it ran.
#
# The output must be printed before anything is asserted, and that is the whole
# reason this is a script rather than five copies of a shell block. A workflow
# `run:` step executes under `-e`, and `out=$(cargo test ...)` carries the
# command's status into the assignment - so a RED run terminates the step AT the
# assignment and the captured diagnosis is never echoed. A Miri UB report, a
# panic, or a new unsupported foreign call reaches the log as nothing but
# "Process completed with exit code 101". That is the failure mode these lanes
# exist to report, and it was the one mode that printed nothing.
#
# Usage:
#   counted-cargo-test.sh <expected> <label> -- <cargo args...>
#   counted-cargo-test.sh any        <label> -- <cargo args...>
#
# `any` asserts only that a `test result:` line was produced, for a run whose
# count is not fixed (a many-seeds sweep interleaves its libtest lines, so no
# line-shaped count is reliable there).

set -eu

expected="${1:?expected count or 'any'}"
label="${2:?label}"
shift 2
[ "${1:-}" = "--" ] || { echo "::error::$label: expected -- before cargo args"; exit 1; }
shift

# The one place the status is allowed to be deferred, so the output survives it.
set +e
out=$("$@" 2>&1)
rc=$?
set -e

# printf, not echo: /bin/sh's echo interprets backslash escapes, and a
# panic message quoting source can carry them.
printf '%s\n' "$out"

if [ "$rc" -ne 0 ]; then
    echo "::error::$label: the run itself failed (exit $rc); its output is above"
    exit 1
fi

n=$(printf '%s' "$out" | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' | head -1)

if [ -z "$n" ]; then
    echo "::error::$label: no 'test result: ok. N passed' line - a filter that matches nothing exits 0"
    exit 1
fi

if [ "$expected" = "any" ]; then
    echo "$label: ran $n tests"
    exit 0
fi

if [ "$n" -ne "$expected" ]; then
    echo "::error::$label: ran $n tests, expected exactly $expected"
    # A bare integer does not say WHAT changed, so name the roster.
    echo "--- tests the filter selected ---"
    printf '%s' "$out" | sed -n 's/^test \(.*\) \.\.\. .*/\1/p' | sort
    exit 1
fi

echo "$label: ran $n tests, as expected"
