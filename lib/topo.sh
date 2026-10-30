# shellcheck shell=bash
# Topology loader: parses a directory of IOS-style router configs (*.cfg),
# builds interfaces, ACLs and per-router routing tables.
# Requires lib/ipv4.sh, lib/rib.sh, lib/acl.sh.
#
# Supported config subset:
#   hostname NAME
#   interface NAME
#    ip address A.B.C.D MASK | shutdown | no shutdown
#    ip access-group ACL in|out
#   ip route PREFIX MASK (NEXTHOP | IFACE [NEXTHOP] | Null0) [DISTANCE]
#   access-list <1-199|1300-2699> permit|deny ...
#   ip access-list standard|extended NAME   (followed by indented entries)
# Other commands are ignored and counted in TOPO_IGNORED.

R_NAME=() R_FILE=() # R_FILE: source path of each router, kept for callers
IF_RTR=() IF_NAME=() IF_ADDR=() IF_LEN=() IF_UP=() IF_ACLIN=() IF_ACLOUT=()
IF_ACLIN_ID=() IF_ACLOUT_ID=()
TOPO_IGNORED=0

_topo_err() {
  echo "$_TF:$_TL: $*" >&2
  return 1
}

# topo_router_id NAME -> REPLY
topo_router_id() {
  local i
  for ((i = 0; i < ${#R_NAME[@]}; i++)); do
    [[ ${R_NAME[i]} == "$1" ]] && { REPLY=$i; return 0; }
  done
  return 1
}

# topo_if_find ROUTER NAME -> REPLY=interface id (case-insensitive)
topo_if_find() {
  local i want
  want=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
  for ((i = 0; i < ${#IF_NAME[@]}; i++)); do
    ((IF_RTR[i] == $1)) || continue
    [[ ${IF_LOWER[i]} == "$want" ]] && { REPLY=$i; return 0; }
  done
  return 1
}
IF_LOWER=()

# topo_load_file FILE
topo_load_file() {
  local _TF=$1 _TL=0 raw line indented
  local rid=${#R_NAME[@]} cur_if=-1 cur_acl=-1 statics="" w kind
  local name=${1##*/}
  R_NAME[rid]=${name%.cfg}
  R_FILE[rid]=$1

  while IFS= read -r raw || [[ -n $raw ]]; do
    _TL=$((_TL + 1))
    raw=${raw%$'\r'}
    indented=0
    [[ $raw == [[:space:]]* ]] && indented=1
    read -r -a w <<<"$raw"
    line="${w[*]-}"
    [[ -z $line ]] && continue
    if [[ $line == '!'* ]]; then
      cur_if=-1 cur_acl=-1
      continue
    fi

    if ((indented && cur_if >= 0)); then
      case $line in
        "ip address "*)
          cidr_parse "${w[2]-}" "${w[3]-x}" || _topo_err "bad ip address: $line" || return 1
          IF_ADDR[cur_if]=$CIDR_ADDR IF_LEN[cur_if]=$CIDR_LEN
          ;;
        shutdown) IF_UP[cur_if]=0 ;;
        "no shutdown") IF_UP[cur_if]=1 ;;
        "ip access-group "*)
          case ${w[3]-} in
            in) IF_ACLIN[cur_if]=${w[2]} ;;
            out) IF_ACLOUT[cur_if]=${w[2]} ;;
            *) _topo_err "bad access-group: $line" || return 1 ;;
          esac
          ;;
        *) TOPO_IGNORED=$((TOPO_IGNORED + 1)) ;;
      esac
      continue
    fi
    if ((indented && cur_acl >= 0)); then
      [[ $line == remark* || $line == [0-9]*" remark"* ]] && continue
      acl_add_entry "$cur_acl" "$line" || _topo_err "bad access-list entry: $line" || return 1
      continue
    fi

    cur_if=-1 cur_acl=-1
    case $line in
      "hostname "*) R_NAME[rid]=${w[1]} ;;
      "interface "*)
        cur_if=${#IF_NAME[@]}
        IF_RTR[cur_if]=$rid IF_NAME[cur_if]=${w[1]} IF_UP[cur_if]=1
        IF_LOWER[cur_if]=$(printf '%s' "${w[1]}" | tr '[:upper:]' '[:lower:]')
        IF_ADDR[cur_if]="" IF_LEN[cur_if]="" IF_ACLIN[cur_if]="" IF_ACLOUT[cur_if]=""
        ;;
      "ip route "*) statics+="$_TL ${w[*]:2}"$'\n' ;;
      "access-list "*)
        [[ ${w[1]-} =~ ^[0-9]+$ ]] && acl_kind_for_number "${w[1]}" ||
          _topo_err "bad access-list number: $line" || return 1
        kind=$REPLY
        acl_get "$rid" "${w[1]}" "$kind"
        [[ ${w[2]-} == remark ]] && continue
        acl_add_entry "$REPLY" "${w[*]:2}" || _topo_err "bad access-list entry: $line" || return 1
        ;;
      "ip access-list standard "* | "ip access-list extended "*)
        kind=std
        [[ ${w[2]} == extended ]] && kind=ext
        acl_get "$rid" "${w[3]-}" "$kind"
        cur_acl=$REPLY
        ;;
      *) TOPO_IGNORED=$((TOPO_IGNORED + 1)) ;;
    esac
  done <"$1"

  # Connected routes for every interface that is up and addressed.
  local i
  for ((i = 0; i < ${#IF_NAME[@]}; i++)); do
    ((IF_RTR[i] == rid)) || continue
    [[ -n ${IF_ADDR[i]} && ${IF_UP[i]} == 1 ]] || continue
    rib_add "$rid" $(( IF_ADDR[i] & MASK[IF_LEN[i]] )) "${IF_LEN[i]}" C "" "$i" 0 0
    local own="_OWN_${IF_ADDR[i]}"
    [[ -z ${!own-} ]] && printf -v "$own" '%s' "$i"
  done

  # Static routes, now that every interface name is known. A route via a
  # next-hop address is installed only once that address resolves, so keep
  # retrying until no more routes can be installed (routes may depend on each
  # other). Whatever is left is stored as unresolved, as IOS would.
  local ln rest pending="" left progress=1
  while read -r ln rest; do
    [[ -n $ln ]] || continue
    _TL=$ln
    _topo_static "$rid" "$rest" || return 1
    [[ -n $REPLY ]] && pending+="$REPLY"$'\n'
  done <<<"$statics"
  local net len nh ifid ad
  while ((progress)); do
    progress=0 left=""
    while read -r net len nh ifid ad; do
      [[ -n $net ]] || continue
      if [[ $ifid == - ]] && ! rib_resolve_nh "$rid" "$nh"; then
        left+="$net $len $nh $ifid $ad"$'\n'
        continue
      fi
      [[ $nh == - ]] && nh=""
      [[ $ifid == - ]] && ifid=""
      rib_add "$rid" "$net" "$len" S "$nh" "$ifid" "$ad" 0
      progress=1
    done <<<"$pending"
    pending=$left
  done
  while read -r net len nh ifid ad; do
    [[ -n $net ]] && rib_add "$rid" "$net" "$len" S "$nh" "" "$ad" 0 unresolved
  done <<<"$pending"
  return 0
}

# _topo_static ROUTER "PREFIX MASK target [nexthop] [distance]"
#   -> REPLY="net len nexthop|- ifid|- distance", or "" if the exit interface is down
_topo_static() {
  local rid=$1 w nh=- ifid=- ad=1 p=2
  REPLY=""
  read -r -a w <<<"$2"
  cidr_parse "${w[0]-}" "${w[1]-x}" || _topo_err "bad static route prefix: ip route $2" || return 1
  local net=$CIDR_NET len=$CIDR_LEN
  if ip_to_int "${w[2]-}"; then
    nh=$REPLY
    p=3
  elif [[ ${w[2]-} == [Nn]ull0 ]]; then
    ifid=$NULL_IF
    p=3
  elif topo_if_find "$rid" "${w[2]-}"; then
    ifid=$REPLY
    p=3
    if ip_to_int "${w[3]-}"; then nh=$REPLY; p=4; fi
  else
    _topo_err "unknown next hop or interface '${w[2]-}': ip route $2" || return 1
  fi
  if [[ ${w[p]-} =~ ^[0-9]+$ ]]; then
    ((10#${w[p]} >= 1 && 10#${w[p]} <= 255)) || _topo_err "bad distance: ip route $2" || return 1
    ad=$((10#${w[p]}))
  fi
  # IOS withdraws a static route whose exit interface is down.
  if [[ $ifid != - && $ifid != "$NULL_IF" && ${IF_UP[ifid]} != 1 ]]; then
    REPLY=""
    return 0
  fi
  REPLY="$net $len $nh $ifid $ad"
}

# topo_load DIR -> loads DIR/*.cfg in name order.
topo_load() {
  local f found=0 i j
  for f in "$1"/*.cfg; do
    [[ -f $f ]] || continue
    found=1
    topo_load_file "$f" || return 1
  done
  ((found)) || { echo "no *.cfg files in $1" >&2; return 1; }
  for ((i = 0; i < ${#R_NAME[@]}; i++)); do
    for ((j = i + 1; j < ${#R_NAME[@]}; j++)); do
      [[ ${R_NAME[i]} != "${R_NAME[j]}" ]] || { echo "duplicate hostname ${R_NAME[i]}" >&2; return 1; }
    done
  done
  # Bind applied ACL names to ACL ids. An undefined ACL permits everything (IOS).
  for ((i = 0; i < ${#IF_NAME[@]}; i++)); do
    IF_ACLIN_ID[i]=-1 IF_ACLOUT_ID[i]=-1
    if [[ -n ${IF_ACLIN[i]} ]] && acl_find "${IF_RTR[i]}" "${IF_ACLIN[i]}"; then IF_ACLIN_ID[i]=$REPLY; fi
    if [[ -n ${IF_ACLOUT[i]} ]] && acl_find "${IF_RTR[i]}" "${IF_ACLOUT[i]}"; then IF_ACLOUT_ID[i]=$REPLY; fi
  done
}

# topo_route_text ROUTE -> REPLY="S 10.3.0.0/16 [1/0] via 10.0.12.2" style text
topo_route_text() {
  local r=$1 pfx nh
  cidr_format "${RT_NET[r]}" "${RT_LEN[r]}"
  pfx=$REPLY
  if [[ ${RT_TYPE[r]} == C ]]; then
    REPLY="C $pfx is directly connected, ${IF_NAME[RT_IF[r]]}"
    return
  fi
  REPLY="S $pfx [${RT_AD[r]}/${RT_METRIC[r]}]"
  if [[ -n ${RT_NH[r]} ]]; then
    int_to_ip "${RT_NH[r]}"
    nh=$REPLY
    REPLY="S $pfx [${RT_AD[r]}/${RT_METRIC[r]}] via $nh"
    [[ -n ${RT_IF[r]} ]] && REPLY+=", ${IF_NAME[RT_IF[r]]}"
  elif [[ ${RT_IF[r]} == "$NULL_IF" ]]; then
    REPLY+=" is directly connected, Null0"
  else
    REPLY+=" is directly connected, ${IF_NAME[RT_IF[r]]}"
  fi
}

# topo_show_routes ROUTER -> prints the active routes like "show ip route".
topo_show_routes() {
  local r
  for ((r = 0; r < ${#RT_NET[@]}; r++)); do
    if ((RT_RTR[r] != $1)) || ! rib_is_active "$r"; then continue; fi
    topo_route_text "$r"
    printf '%s %s %s\n' "${RT_NET[r]}" "${RT_LEN[r]}" "$REPLY"
  done | sort -n -k1,1 -k2,2 | cut -d' ' -f3-
}

# topo_check -> prints configuration problems; REPLY=number found.
topo_check() {
  local i j r n=0 own name
  for ((i = 0; i < ${#IF_NAME[@]}; i++)); do
    [[ -n ${IF_ADDR[i]} && ${IF_UP[i]} == 1 ]] || continue
    name="${R_NAME[IF_RTR[i]]} ${IF_NAME[i]}"
    own="_OWN_${IF_ADDR[i]}"
    if [[ ${!own} != "$i" ]]; then
      int_to_ip "${IF_ADDR[i]}"
      echo "duplicate address $REPLY on $name and ${R_NAME[IF_RTR[${!own}]]} ${IF_NAME[${!own}]}"
      n=$((n + 1))
    fi
    for ((j = i + 1; j < ${#IF_NAME[@]}; j++)); do
      [[ -n ${IF_ADDR[j]} && ${IF_UP[j]} == 1 ]] || continue
      ((IF_RTR[i] != IF_RTR[j] && IF_LEN[i] != IF_LEN[j])) || continue
      if cidr_contains $((IF_ADDR[i] & MASK[IF_LEN[i]])) "${IF_LEN[i]}" "${IF_ADDR[j]}" ||
        cidr_contains $((IF_ADDR[j] & MASK[IF_LEN[j]])) "${IF_LEN[j]}" "${IF_ADDR[i]}"; then
        echo "mask mismatch: $name /${IF_LEN[i]} vs ${R_NAME[IF_RTR[j]]} ${IF_NAME[j]} /${IF_LEN[j]}"
        n=$((n + 1))
      fi
    done
    if [[ -n ${IF_ACLIN[i]} && ${IF_ACLIN_ID[i]} == -1 ]]; then
      echo "$name: inbound ACL ${IF_ACLIN[i]} is not defined (permits all)"
      n=$((n + 1))
    fi
    if [[ -n ${IF_ACLOUT[i]} && ${IF_ACLOUT_ID[i]} == -1 ]]; then
      echo "$name: outbound ACL ${IF_ACLOUT[i]} is not defined (permits all)"
      n=$((n + 1))
    fi
  done
  for ((r = 0; r < ${#RT_NET[@]}; r++)); do
    [[ ${RT_TYPE[r]} == S ]] || continue
    topo_route_text "$r"
    local text=$REPLY
    if ((RT_UNRESOLVED[r])); then
      echo "${R_NAME[RT_RTR[r]]}: '$text' not installed, next hop does not resolve"
      n=$((n + 1))
      continue
    fi
    [[ -n ${RT_NH[r]} && -z ${RT_IF[r]} ]] || continue
    # IOS resolves a next hop through the default route too, which silently
    # keeps a static route alive after the link it was meant for goes down.
    if rib_lookup "${RT_RTR[r]}" "${RT_NH[r]}" && ((RT_LEN[REPLY] == 0)); then
      int_to_ip "${RT_NH[r]}"
      echo "${R_NAME[RT_RTR[r]]}: next hop $REPLY of '$text' resolves only via the default route"
      n=$((n + 1))
    fi
    if rib_resolve "${RT_RTR[r]}" "$r" "${RT_NET[r]}"; then
      own="_OWN_${RES_NH}"
      if [[ -z ${!own-} ]]; then
        int_to_ip "$RES_NH"
        echo "${R_NAME[RT_RTR[r]]}: next hop $REPLY of '$text' is not a known router interface"
        n=$((n + 1))
      fi
    fi
  done
  REPLY=$n
}
