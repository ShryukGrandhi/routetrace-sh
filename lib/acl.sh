# shellcheck shell=bash
# Cisco IOS style standard and extended IPv4 access control lists.
# Requires lib/ipv4.sh.
#
# Semantics follow IOS: entries are evaluated top-down, the first match wins,
# and a packet that matches nothing hits the implicit "deny any" at the end.
# Wildcard masks may be non-contiguous (e.g. 0.0.255.0).

ACL_NAME=() ACL_RTR=() ACL_KIND=() ACL_ACES=()
ACE_ACT=() ACE_PROTO=() ACE_SNET=() ACE_SWC=() ACE_SLO=() ACE_SHI=() ACE_SNEQ=()
ACE_DNET=() ACE_DWC=() ACE_DLO=() ACE_DHI=() ACE_DNEQ=() ACE_EST=() ACE_TEXT=()
ACE_HITS=()

# acl_find ROUTER NAME -> REPLY=acl id
acl_find() {
  local i
  for ((i = 0; i < ${#ACL_NAME[@]}; i++)); do
    if [[ ${ACL_RTR[i]} == "$1" && ${ACL_NAME[i]} == "$2" ]]; then
      REPLY=$i
      return 0
    fi
  done
  return 1
}

# acl_get ROUTER NAME KIND -> REPLY=acl id, creating the ACL if needed.
acl_get() {
  acl_find "$1" "$2" && return 0
  REPLY=${#ACL_NAME[@]}
  ACL_NAME[REPLY]=$2 ACL_RTR[REPLY]=$1 ACL_KIND[REPLY]=$3 ACL_ACES[REPLY]=""
}

# acl_kind_for_number N -> REPLY=std|ext (IOS numbered ACL ranges)
acl_kind_for_number() {
  local n=$1
  if (( (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) )); then
    REPLY=std
  elif (( (n >= 100 && n <= 199) || (n >= 2000 && n <= 2699) )); then
    REPLY=ext
  else
    return 1
  fi
}

# proto_number NAME|NUMBER -> REPLY=IP protocol number (0 means "ip", any)
proto_number() {
  case $1 in
    ip) REPLY=0 ;;
    icmp) REPLY=1 ;;
    tcp) REPLY=6 ;;
    udp) REPLY=17 ;;
    gre) REPLY=47 ;;
    esp) REPLY=50 ;;
    ospf) REPLY=89 ;;
    *)
      [[ $1 =~ ^[0-9]{1,3}$ ]] && ((10#$1 <= 255)) || return 1
      REPLY=$((10#$1))
      ;;
  esac
}

# port_number NAME|NUMBER -> REPLY=port
port_number() {
  case $1 in
    ftp-data) REPLY=20 ;; ftp) REPLY=21 ;; ssh) REPLY=22 ;; telnet) REPLY=23 ;;
    smtp) REPLY=25 ;; domain) REPLY=53 ;; bootps) REPLY=67 ;; bootpc) REPLY=68 ;;
    tftp) REPLY=69 ;; www | http) REPLY=80 ;; pop3) REPLY=110 ;; ntp) REPLY=123 ;;
    snmp) REPLY=161 ;; bgp) REPLY=179 ;; https) REPLY=443 ;; syslog) REPLY=514 ;;
    *)
      [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 <= 65535)) || return 1
      REPLY=$((10#$1))
      ;;
  esac
}

# _ace_addr: consume an address spec from _T starting at _P.
# Sets _NET/_WC. Accepts "any", "host A", "A W" (and bare "A" if $1 == std).
_ace_addr() {
  local tok=${_T[_P]-}
  case $tok in
    any) _NET=0 _WC=0xFFFFFFFF; _P=$((_P + 1)) ;;
    host)
      ip_to_int "${_T[_P + 1]-}" || return 1
      _NET=$REPLY _WC=0; _P=$((_P + 2))
      ;;
    *)
      ip_to_int "$tok" || return 1
      local a=$REPLY
      if ip_to_int "${_T[_P + 1]-}"; then
        _WC=$REPLY; _P=$((_P + 2))
      elif [[ $1 == std ]]; then
        _WC=0; _P=$((_P + 1))
      else
        return 1
      fi
      _NET=$(( a & ~_WC & 0xFFFFFFFF ))
      ;;
  esac
}

# _ace_port: optionally consume "eq|neq|lt|gt P" or "range P1 P2".
# Sets _LO/_HI/_NEQ.
_ace_port() {
  _LO=0 _HI=65535 _NEQ=0
  local op=${_T[_P]-}
  case $op in
    eq | neq | lt | gt)
      port_number "${_T[_P + 1]-}" || return 1
      case $op in
        eq) _LO=$REPLY _HI=$REPLY ;;
        neq) _LO=$REPLY _HI=$REPLY _NEQ=1 ;;
        lt) _HI=$((REPLY - 1)) ;;
        gt) _LO=$((REPLY + 1)) ;;
      esac
      _P=$((_P + 2))
      ;;
    range)
      port_number "${_T[_P + 1]-}" || return 1; _LO=$REPLY
      port_number "${_T[_P + 2]-}" || return 1; _HI=$REPLY
      _P=$((_P + 3))
      ;;
  esac
  return 0
}

# acl_add_entry ACL_ID "permit tcp any host 10.0.0.1 eq 22 ..."
# An optional leading sequence number (named ACL syntax) is accepted.
acl_add_entry() {
  local acl=$1 kind=${ACL_KIND[$1]} act proto=0 est=0
  local snet swc slo=0 shi=65535 sneq=0
  local _T _P=0 _NET _WC _LO _HI _NEQ
  read -r -a _T <<<"$2"
  [[ ${_T[0]-} =~ ^[0-9]+$ ]] && _P=1
  act=${_T[_P]-}
  [[ $act == permit || $act == deny ]] || return 1
  _P=$((_P + 1))
  if [[ $kind == ext ]]; then
    proto_number "${_T[_P]-}" || return 1
    proto=$REPLY
    _P=$((_P + 1))
  fi
  _ace_addr "$kind" || return 1
  snet=$_NET swc=$_WC
  local dnet=0 dwc=0xFFFFFFFF dlo=0 dhi=65535 dneq=0
  if [[ $kind == ext ]]; then
    if ((proto == 6 || proto == 17)); then
      _ace_port || return 1
      slo=$_LO shi=$_HI sneq=$_NEQ
    fi
    _ace_addr ext || return 1
    dnet=$_NET dwc=$_WC
    if ((proto == 6 || proto == 17)); then
      _ace_port || return 1
      dlo=$_LO dhi=$_HI dneq=$_NEQ
    fi
    if [[ ${_T[_P]-} == established ]]; then
      ((proto == 6)) || return 1
      est=1
      _P=$((_P + 1))
    fi
  fi
  # Anything left must be a keyword we deliberately ignore.
  while ((_P < ${#_T[@]})); do
    case ${_T[_P]} in log | log-input) ;; *) return 1 ;; esac
    _P=$((_P + 1))
  done

  local id=${#ACE_ACT[@]}
  ACE_ACT[id]=$act ACE_PROTO[id]=$proto ACE_EST[id]=$est ACE_HITS[id]=0
  ACE_SNET[id]=$snet ACE_SWC[id]=$(( swc & 0xFFFFFFFF )) ACE_SLO[id]=$slo ACE_SHI[id]=$shi ACE_SNEQ[id]=$sneq
  ACE_DNET[id]=$dnet ACE_DWC[id]=$(( dwc & 0xFFFFFFFF )) ACE_DLO[id]=$dlo ACE_DHI[id]=$dhi ACE_DNEQ[id]=$dneq
  ACE_TEXT[id]=$2
  ACL_ACES[acl]+="$id "
}

# acl_eval ACL_ID PROTO SRC DST SPORT DPORT ESTABLISHED
#   -> REPLY=permit|deny, ACL_HIT=matching entry id (-1 = implicit deny)
acl_eval() {
  local proto=$2 src=$3 dst=$4 sport=$5 dport=$6 est=$7 i ports
  ports=$(( proto == 6 || proto == 17 ))
  for i in ${ACL_ACES[$1]}; do
    (( ACE_PROTO[i] == 0 || ACE_PROTO[i] == proto )) || continue
    (( (src & ~ACE_SWC[i]) == ACE_SNET[i] )) || continue
    (( (dst & ~ACE_DWC[i]) == ACE_DNET[i] )) || continue
    if ((ports)); then
      if ((ACE_SNEQ[i])); then
        ((sport != ACE_SLO[i])) || continue
      else
        ((sport >= ACE_SLO[i] && sport <= ACE_SHI[i])) || continue
      fi
      if ((ACE_DNEQ[i])); then
        ((dport != ACE_DLO[i])) || continue
      else
        ((dport >= ACE_DLO[i] && dport <= ACE_DHI[i])) || continue
      fi
    fi
    ((ACE_EST[i] == 0 || est)) || continue
    ACE_HITS[i]=$((ACE_HITS[i] + 1))
    ACL_HIT=$i
    REPLY=${ACE_ACT[i]}
    return 0
  done
  ACL_HIT=-1
  REPLY=deny
}
