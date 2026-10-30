# shellcheck shell=bash
# Routing table (RIB) per router with longest-prefix-match lookup.
# Requires lib/ipv4.sh.
#
# Routes live in parallel global arrays indexed by route id. The forwarding
# index is a set of shell variables named _RB_<router>_<len>_<network> whose
# value is the best route id for that exact prefix. Bash stores variables in a
# hash table, so each probe is O(1) and a lookup costs one probe per distinct
# prefix length present in the table (at most 33), independent of route count.
# Indexed arrays would not work for this: they are linked lists in bash.

RT_RTR=() RT_NET=() RT_LEN=() RT_TYPE=() RT_NH=() RT_IF=() RT_AD=() RT_METRIC=()
RT_UNRESOLVED=() # 1 for static routes stored but not installed (next hop unreachable)
NULL_IF=-1 # RT_IF value for "ip route ... Null0"

# rib_add ROUTER NET LEN TYPE NEXTHOP IFIDX AD METRIC [unresolved]
#   TYPE is C (connected) or S (static). NEXTHOP/IFIDX may be "" when unused.
# The route is always stored; it becomes the forwarding entry for its prefix
# only if it beats the current one on (administrative distance, metric) and
# the 9th argument is not "unresolved".
rib_add() {
  local rid=$1 net=$2 len=$3 id=${#RT_NET[@]}
  RT_RTR[id]=$rid RT_NET[id]=$net RT_LEN[id]=$len RT_TYPE[id]=$4
  RT_NH[id]=$5 RT_IF[id]=$6 RT_AD[id]=$7 RT_METRIC[id]=$8 RT_UNRESOLVED[id]=0
  if [[ ${9-} == unresolved ]]; then
    RT_UNRESOLVED[id]=1
    return 0
  fi

  local key="_RB_${rid}_${len}_${net}"
  local cur=${!key-}
  if [[ -n $cur ]]; then
    if (( RT_AD[cur] < $7 || (RT_AD[cur] == $7 && RT_METRIC[cur] <= $8) )); then
      return 0
    fi
  else
    _rib_add_len "$rid" "$len"
  fi
  printf -v "$key" '%s' "$id"
}

# Keep _RL_<router> as a space separated list of prefix lengths, longest first.
_rib_add_len() {
  local var="_RL_$1" l out="" placed=0
  for l in ${!var-}; do
    ((l == $2)) && return 0
    if ((!placed && $2 > l)); then out+="$2 "; placed=1; fi
    out+="$l "
  done
  ((placed)) || out+="$2 "
  printf -v "$var" '%s' "$out"
}

# rib_lookup ROUTER ADDR -> REPLY=route id of the longest matching prefix.
rib_lookup() {
  local lens="_RL_$1" len key
  for len in ${!lens-}; do
    key="_RB_${1}_${len}_$(( $2 & MASK[len] ))"
    if [[ -n ${!key-} ]]; then
      REPLY=${!key}
      return 0
    fi
  done
  return 1
}

# rib_lookup_linear ROUTER ADDR -> same result as rib_lookup by scanning every
# route. Kept as the reference implementation for tests and the benchmark.
rib_lookup_linear() {
  local i n=${#RT_NET[@]} best=-1 len
  for ((i = 0; i < n; i++)); do
    ((RT_RTR[i] == $1 && RT_UNRESOLVED[i] == 0)) || continue
    len=${RT_LEN[i]} # bash 5.2 rejects nested subscripts like MASK[RT_LEN[i]] here
    (( ($2 & MASK[len]) == RT_NET[i] )) || continue
    if ((best < 0)); then
      best=$i
    elif ((RT_LEN[i] > RT_LEN[best] ||
      (RT_LEN[i] == RT_LEN[best] && (RT_AD[i] < RT_AD[best] ||
      (RT_AD[i] == RT_AD[best] && RT_METRIC[i] < RT_METRIC[best]))))); then
      best=$i
    fi
  done
  ((best >= 0)) || return 1
  REPLY=$best
}

# rib_resolve ROUTER ROUTE DST -> RES_IF (egress interface id, or NULL_IF) and
# RES_NH (address of the next device: DST itself for connected networks).
rib_resolve() {
  local r=$2
  if [[ -n ${RT_IF[r]} ]]; then
    RES_IF=${RT_IF[r]}
    RES_NH=${RT_NH[r]:-$3}
    return 0
  fi
  rib_resolve_nh "$1" "${RT_NH[r]}"
}

# rib_resolve_nh ROUTER NEXTHOP -> RES_IF/RES_NH for a next-hop address.
# A next hop reached through another static route is resolved recursively,
# like IOS does, up to 8 levels deep (which also stops resolution loops).
rib_resolve_nh() {
  local rid=$1 nh=$2 r depth=0
  while ((depth++ < 8)); do
    rib_lookup "$rid" "$nh" || return 1
    r=$REPLY
    if [[ -n ${RT_IF[r]} ]]; then
      [[ ${RT_IF[r]} != "$NULL_IF" ]] || return 1
      RES_IF=${RT_IF[r]}
      RES_NH=$nh
      [[ ${RT_TYPE[r]} == C || -z ${RT_NH[r]} ]] || RES_NH=${RT_NH[r]}
      return 0
    fi
    nh=${RT_NH[r]}
  done
  return 1
}

# rib_is_active ROUTE -> true if ROUTE is the forwarding entry for its prefix.
rib_is_active() {
  local key="_RB_${RT_RTR[$1]}_${RT_LEN[$1]}_${RT_NET[$1]}"
  [[ ${!key-} == "$1" ]]
}
