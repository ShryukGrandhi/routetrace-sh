# shellcheck shell=bash
# Prefix-set algorithms: exact route summarization and VLSM allocation.
# Requires lib/ipv4.sh.

# range_to_cidrs START END -> appends the minimal list of "net/len" blocks
# that exactly cover [START, END] to the array RANGE_CIDRS.
range_to_cidrs() {
  local start=$1 end=$2 k
  while ((start <= end)); do
    # Largest block aligned at start: count trailing zero bits.
    if ((start == 0)); then
      k=32
    else
      k=0
      while (( ((start >> k) & 1) == 0 )); do k=$((k + 1)); done
    fi
    # Shrink until the block fits inside the range.
    while (( start + (1 << k) - 1 > end )); do k=$((k - 1)); done
    cidr_format "$start" $((32 - k))
    RANGE_CIDRS[${#RANGE_CIDRS[@]}]=$REPLY
    start=$((start + (1 << k)))
  done
}

# cidr_summarize CIDR... -> SUMMARY array with the smallest set of prefixes
# covering exactly the same addresses as the input (no over-summarization).
cidr_summarize() {
  local c lines="" s e cur_s=-1 cur_e=-1
  SUMMARY=()
  RANGE_CIDRS=()
  for c in "$@"; do
    cidr_parse "$c" || { echo "invalid prefix: $c" >&2; return 1; }
    lines+="$CIDR_NET $(( CIDR_NET + (1 << (32 - CIDR_LEN)) - 1 ))"$'\n'
  done
  [[ -n $lines ]] || return 0
  # Sort by start address, then merge overlapping or adjacent ranges.
  while read -r s e; do
    if ((cur_s < 0)); then
      cur_s=$s cur_e=$e
    elif ((s <= cur_e + 1)); then
      ((e > cur_e)) && cur_e=$e
    else
      range_to_cidrs "$cur_s" "$cur_e"
      cur_s=$s cur_e=$e
    fi
  done < <(printf '%s' "$lines" | sort -n -k1,1 -k2,2)
  range_to_cidrs "$cur_s" "$cur_e"
  SUMMARY=("${RANGE_CIDRS[@]}")
}

# hosts_to_len HOSTS -> REPLY=longest prefix with at least HOSTS usable hosts
hosts_to_len() {
  local need=$1 h=2
  [[ $need =~ ^[0-9]+$ ]] && ((need >= 1)) || return 1
  while (( (1 << h) - 2 < need )); do
    h=$((h + 1))
    ((h <= 32)) || return 1
  done
  REPLY=$((32 - h))
}

# cidr_vlsm PARENT NAME:HOSTS... -> prints one allocation per line:
#   name  hosts_wanted  subnet  usable  first-last
# Largest requests are placed first, which keeps every block naturally aligned
# when allocating sequentially. Returns 1 if the parent block is too small.
cidr_vlsm() {
  cidr_parse "$1" || { echo "invalid parent prefix: $1" >&2; return 1; }
  local pnet=$CIDR_NET plen=$CIDR_LEN
  local pend=$(( pnet + (1 << (32 - plen)) - 1 ))
  local next=$pnet req name hosts len size sorted="" first last
  shift
  for req in "$@"; do
    [[ $req == *:* ]] || { echo "bad request '$req' (want name:hosts)" >&2; return 1; }
    hosts_to_len "${req##*:}" || { echo "bad host count in '$req'" >&2; return 1; }
    sorted+="$req"$'\n'
  done
  while IFS=: read -r name hosts; do
    hosts_to_len "$hosts"
    len=$REPLY
    size=$((1 << (32 - len)))
    if ((len < plen || next + size - 1 > pend)); then
      cidr_format "$pnet" "$plen"
      echo "out of space: $name needs /$len, $REPLY exhausted" >&2
      return 1
    fi
    int_to_ip $((next + 1)); first=$REPLY
    int_to_ip $((next + size - 2)); last=$REPLY
    cidr_format "$next" "$len"
    printf '%-12s %6s  %-18s %6s  %s-%s\n' "$name" "$hosts" "$REPLY" $((size - 2)) "$first" "$last"
    next=$((next + size))
  done < <(printf '%s' "$sorted" | sort -s -t: -k2,2nr)
}
