#!/bin/sh
# Run a cargo test invocation, print its output UNCONDITIONALLY, then assert the
# number of tests it ran.
#
# The output must reach the log whatever happens to the run, and that is the
# whole reason this is a script rather than five copies of a shell block. Two
# ways a shell block loses it, both of which these lanes hit:
#
#   * A workflow `run:` step executes under `-e`, so `out=$(cargo test ...)`
#     carries the command's status into the assignment and a RED run terminates
#     the step AT the assignment, with the captured diagnosis never echoed.
#   * `timeout-minutes` signals the step while a capture is still unprinted, so
#     a lane that emits a UB report and then deadlocks logs only the
#     cancellation notice.
#
# A Miri UB report, a panic, or a new unsupported foreign call is the failure
# mode these lanes exist to report. Hence: streamed through `tee`, never
# captured, with the run's status recorded to a file - an ABSENT status is
# itself an error, since a killed run has no exit code to assert against.
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

log=$(mktemp)
# EXIT only. Trapping the fatal signals as well would keep the script
# alive past a `timeout-minutes` kill and have it carry on against files
# it had just deleted; two temp files left on an ephemeral runner are the
# cheaper end of that trade.
trap 'rm -f "$log" "$log.rc"' EXIT
: > "$log.rc"

# `set +e` goes INSIDE the group, which is the pipeline's subshell: without it
# the command's own non-zero status trips `-e` there before `$?` is recorded,
# and the status file is left empty by a run that merely failed. That is the
# same `set -e`-plus-capture interaction as the header's first bullet, one
# layer down.
{ set +e; "$@" 2>&1; echo "$?" > "$log.rc"; } | tee "$log"
rc=$(cat "$log.rc")
if [ -z "$rc" ]; then
    echo "::error::$label: the run was killed before it reported a status;" \
         "its output is above"
    exit 1
fi

if [ "$rc" -ne 0 ]; then
    echo "::error::$label: the run itself failed (exit $rc); its output is above"
    exit 1
fi

counts=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' "$log")
n=$(printf '%s\n' "$counts" | head -1)

if [ -z "$n" ]; then
    echo "::error::$label: no 'test result: ok. N passed' line - a filter that matches nothing exits 0"
    exit 1
fi

# `any` first, then refuse anything that is not a plain count. `[ "$n" -ne
# "$expected" ]` answers 2 - not 1 - on a non-numeric operand, and a non-zero
# status in an `if` CONDITION is exempt from `set -e`, so a typo'd count skips
# the assertion body and falls through to "as expected", exit 0. The gate
# policing the one hand-edited constant would then pass vacuously on a typo in
# it, which is the drift it exists to catch.
case "$expected" in
    any)
        echo "$label: ran $n tests"
        exit 0
        ;;
    '' | *[!0-9]*)
        echo "::error::$label: expected must be a plain count or 'any'," \
             "got '$expected'"
        exit 1
        ;;
esac

# One count per test binary, so a run of several has no single figure to
# assert - taking the first would police one binary and wave the rest through.
# Every call site is `--lib` today; this is what makes adding one that is not
# a loud error rather than a quiet narrowing.
if [ "$(printf '%s\n' "$counts" | wc -l)" -gt 1 ]; then
    echo "::error::$label: the run produced more than one 'test result' line," \
         "so a single expected count cannot assert it; narrow the invocation" \
         "or use 'any'"
    exit 1
fi

if [ "$n" -ne "$expected" ]; then
    echo "::error::$label: ran $n tests, expected exactly $expected"
    # A bare integer does not say WHAT changed, so name the roster.
    echo "--- tests the filter selected ---"
    sed -n 's/^test \(.*\) \.\.\. .*/\1/p' "$log" | sort
    exit 1
fi

echo "$label: ran $n tests, as expected"
