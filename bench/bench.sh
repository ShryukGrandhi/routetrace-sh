#!/usr/bin/env bash
# Measures the hot paths of routetrace and prints a markdown report.
#   bench/bench.sh            full run
#   bench/bench.sh --quick    smaller sizes (used in CI)
# Every section runs in its own subshell so routing state never accumulates.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for m in ipv4 cidr rib acl topo trace; do
  # shellcheck source=/dev/null
  . "$ROOT/lib/$m.sh"
done

QUICK=0
[[ ${1-} == --quick ]] && QUICK=1
SIZES="100 1000 10000"
LOOKUPS=2000
((QUICK)) && SIZES="100 1000" LOOKUPS=500

# now_us -> REPLY=wall clock in microseconds
if [[ -n ${EPOCHREALTIME-} ]]; then
  now_us() { local t=${EPOCHREALTIME/[.,]/}; REPLY=$((10#$t)); }
else
  now_us() { REPLY=$(perl -MTime::HiRes=time -e 'printf "%d", time * 1e6'); }
fi

rand32() { REPLY=$(( (RANDOM << 17) | (RANDOM << 2) | (RANDOM & 3) )); }

# rate COUNT MICROSECONDS -> REPLY="ops/s" with one decimal, RATE10=10*ops/s
rate() {
  RATE10=$(( $1 * 10000000 / ($2 > 0 ? $2 : 1) ))
  REPLY="$((RATE10 / 10)).$((RATE10 % 10))"
}

# Prefix length mix loosely shaped like an enterprise/BGP table: mostly /24.
LENS=(8 12 16 16 19 20 21 22 22 23 24 24 24 24 24 24 24 24 25 26 27 28 29 30)

bench_lpm() {
  local n=$1 i t0 t1 hits=0 lin_n lin_us hash_us ins_us
  RANDOM=42
  now_us; t0=$REPLY
  for ((i = 0; i < n; i++)); do
    local len=${LENS[RANDOM % ${#LENS[@]}]}
    rand32
    rib_add 0 $(( REPLY & MASK[len] )) "$len" S 1 "" 1 0
  done
  now_us; ins_us=$((REPLY - t0))

  # Half the probes target addresses inside a stored prefix, half are random.
  local probes=()
  for ((i = 0; i < LOOKUPS; i++)); do
    if ((i % 2)); then
      rand32; probes[i]=$REPLY
    else
      local r=$((RANDOM * n / 32768)) l
      l=${RT_LEN[r]}
      probes[i]=$(( RT_NET[r] | (RANDOM & ~MASK[l] & 0xFFFF) ))
    fi
  done

  now_us; t0=$REPLY
  for ((i = 0; i < LOOKUPS; i++)); do
    rib_lookup 0 "${probes[i]}" && hits=$((hits + 1))
  done
  now_us; hash_us=$((REPLY - t0))

  # The linear scan is O(routes) per lookup; sample fewer probes for big tables.
  lin_n=$((LOOKUPS * 100 / n))
  ((lin_n > LOOKUPS)) && lin_n=$LOOKUPS
  ((lin_n < 10)) && lin_n=10
  local mismatches=0 a b
  now_us; t0=$REPLY
  for ((i = 0; i < lin_n; i++)); do
    rib_lookup_linear 0 "${probes[i]}"
  done
  now_us; lin_us=$((REPLY - t0))
  for ((i = 0; i < lin_n; i++)); do
    a=none b=none
    rib_lookup 0 "${probes[i]}" && a="${RT_NET[REPLY]}/${RT_LEN[REPLY]}"
    rib_lookup_linear 0 "${probes[i]}" && b="${RT_NET[REPLY]}/${RT_LEN[REPLY]}"
    [[ $a == "$b" ]] || mismatches=$((mismatches + 1))
  done

  local lens=$_RL_0 nl=0 l
  for l in $lens; do nl=$((nl + 1)); done
  rate "$n" "$ins_us"; local ins_rate=$REPLY
  rate "$LOOKUPS" "$hash_us"; local hash_rate=$REPLY hash10=$RATE10
  rate "$lin_n" "$lin_us"; local lin_rate=$REPLY lin10=$RATE10
  ((lin10 > 0)) || lin10=1
  printf '| %6d | %2d | %9s | %9s | %7s | %d.%dx | %d/%d |\n' "$n" "$nl" "$ins_rate" \
    "$hash_rate" "$lin_rate" $((hash10 / lin10)) $((hash10 * 10 / lin10 % 10)) "$mismatches" "$lin_n"
}

bench_acl() {
  local n=$1 i acl t0 us evals=1000 permits=0
  ((QUICK)) && evals=300
  RANDOM=7
  acl_get 0 BENCH ext
  acl=$REPLY
  for ((i = 0; i < n - 1; i++)); do
    int_to_ip $(( (10 << 24) | (i << 8) )); local net=$REPLY
    acl_add_entry "$acl" "deny tcp $net 0.0.0.255 any eq $((1000 + i))"
  done
  acl_add_entry "$acl" "permit ip any any"
  local src=() dst=() dp=()
  # Half the packets hit a uniformly random deny entry, half fall through to
  # the final permit, so on average about 3/4 of the list is scanned.
  local k
  for ((i = 0; i < evals; i++)); do
    k=$((RANDOM % (n - 1)))
    ((i % 2)) || k=$((n + 5))
    src[i]=$(( (10 << 24) | (k << 8) | (RANDOM & 255) ))
    rand32; dst[i]=$REPLY
    dp[i]=$((1000 + k))
  done
  now_us; t0=$REPLY
  for ((i = 0; i < evals; i++)); do
    acl_eval "$acl" 6 "${src[i]}" "${dst[i]}" 40000 "${dp[i]}" 0
    [[ $REPLY == permit ]] && permits=$((permits + 1))
  done
  now_us; us=$((REPLY - t0))
  rate "$evals" "$us"
  printf '| %4d | %6d | %8s | %4d%% |\n' "$n" "$evals" "$REPLY" $((permits * 100 / evals))
}

bench_summarize() {
  local n=$1 i list=() t0 us
  RANDOM=11
  for ((i = 0; i < n; i++)); do
    # Random /24s inside 10.0.0.0/14 (1024 possible) so many become adjacent.
    int_to_ip $(( (10 << 24) | ((RANDOM % 1024) << 8) ))
    list[i]="$REPLY/24"
  done
  now_us; t0=$REPLY
  cidr_summarize "${list[@]}"
  now_us; us=$((REPLY - t0))
  printf '| %5d | %5d | %7d |\n' "$n" "${#SUMMARY[@]}" $((us / 1000))
}

bench_trace() {
  local n=200 i t0 us delivered=0 TRACE_QUIET=1
  ((QUICK)) && n=60
  topo_load "$ROOT/examples/campus" || exit 1
  local flows=(
    "10.1.0.20 10.3.0.20 tcp 22"
    "10.1.0.20 10.2.0.10 tcp 443"
    "10.3.0.20 10.2.0.10 tcp 3389"
    "10.3.0.5 198.51.100.1 icmp 0"
    "10.1.0.5 10.99.1.1 icmp 0"
  )
  now_us; t0=$REPLY
  for ((i = 0; i < n; i++)); do
    # shellcheck disable=SC2086
    set -- ${flows[i % ${#flows[@]}]}
    trace_packet "$1" "$2" "$3" 40000 "$4" 0 "" && delivered=$((delivered + 1))
  done
  now_us; us=$((REPLY - t0))
  rate "$n" "$us"
  printf '| in-process trace_packet, 4-router campus | %d | %s traces/s | %d delivered |\n' "$n" "$REPLY" "$delivered"

  local runs=20
  ((QUICK)) && runs=5
  now_us; t0=$REPLY
  for ((i = 0; i < runs; i++)); do
    "$ROOT/bin/routetrace" trace "$ROOT/examples/campus" 10.1.0.20 10.3.0.20 -p tcp -d 22 -q >/dev/null
  done
  now_us; us=$((REPLY - t0))
  printf '| CLI process (config parse + trace) | %d | %d ms/run | |\n' "$runs" $((us / runs / 1000))
}

echo "## routetrace benchmark"
echo
echo "bash $BASH_VERSION, $(uname -sm)$( ((QUICK)) && echo ', --quick')"
echo
echo "### Longest-prefix match ($LOOKUPS lookups per table)"
echo
echo "| routes | prefix lengths | inserts/s | hash LPM lookups/s | linear scan lookups/s | speedup | linear disagreements / probes checked |"
echo "|-------:|---:|---:|---:|---:|---:|---|"
for n in $SIZES; do (bench_lpm "$n"); done
echo
echo "### ACL evaluation (tcp, first match; half the packets hit a random deny, half reach the final permit)"
echo
echo "| entries | packets | evals/s | permitted |"
echo "|---:|---:|---:|---:|"
for n in 10 100; do (bench_acl "$n"); done
echo
echo "### Route summarization (random /24s inside 10.0.0.0/14)"
echo
echo "| input prefixes | output prefixes | ms |"
echo "|---:|---:|---:|"
for n in 500 2000; do (bench_summarize "$n"); done
echo
echo "### End-to-end packet trace"
echo
echo "| what | runs | rate | |"
echo "|---|---:|---:|---|"
(bench_trace)
