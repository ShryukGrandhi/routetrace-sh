# shellcheck shell=bash
# IPv4 address arithmetic on 32-bit integers.
#
# Every function returns its result in REPLY (and sometimes extra globals)
# instead of printing it, so callers never pay for a $(...) subshell fork.
# Functions return non-zero on invalid input. Compatible with bash 3.2+.

# MASK[len] = netmask for prefix length len, as an integer.
MASK=()
_i=0
while ((_i <= 32)); do
  MASK[_i]=$(( _i == 0 ? 0 : (0xFFFFFFFF << (32 - _i)) & 0xFFFFFFFF ))
  _i=$((_i + 1))
done
unset _i

_IPV4_RE='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'

# ip_to_int A.B.C.D -> REPLY=integer
ip_to_int() {
  [[ $1 =~ $_IPV4_RE ]] || return 1
  local a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
  local c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
  ((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
  REPLY=$(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# int_to_ip N -> REPLY=A.B.C.D
int_to_ip() {
  local n=$1
  REPLY="$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

# mask_to_len A.B.C.D -> REPLY=prefix length (fails on non-contiguous masks)
mask_to_len() {
  ip_to_int "$1" || return 1
  local inv=$(( ~REPLY & 0xFFFFFFFF )) len=32
  (( (inv & (inv + 1)) == 0 )) || return 1
  while ((inv)); do
    inv=$((inv >> 1))
    len=$((len - 1))
  done
  REPLY=$len
}

# cidr_parse "A.B.C.D/len" | "A.B.C.D" "A.B.C.D-mask" | "A.B.C.D"
# Sets CIDR_ADDR (host bits kept), CIDR_LEN, CIDR_NET (host bits cleared).
cidr_parse() {
  local addr len
  if [[ $1 == */* ]]; then
    addr=${1%%/*}
    len=${1#*/}
    [[ $len =~ ^[0-9]{1,2}$ ]] && ((10#$len <= 32)) || return 1
    len=$((10#$len))
  elif [[ -n ${2-} ]]; then
    addr=$1
    mask_to_len "$2" || return 1
    len=$REPLY
  else
    addr=$1
    len=32
  fi
  ip_to_int "$addr" || return 1
  CIDR_ADDR=$REPLY
  CIDR_LEN=$len
  CIDR_NET=$(( REPLY & MASK[len] ))
}

# cidr_format NET LEN -> REPLY="A.B.C.D/len"
cidr_format() {
  int_to_ip "$1"
  REPLY="$REPLY/$2"
}

# cidr_contains NET LEN ADDR -> exit status
cidr_contains() {
  (( ($3 & MASK[$2]) == $1 ))
}

# cidr_info "A.B.C.D/len" -> prints a subnet-calculator style report.
cidr_info() {
  cidr_parse "$@" || { echo "invalid address: $*" >&2; return 1; }
  local net=$CIDR_NET len=$CIDR_LEN
  local bcast=$(( net | (~MASK[len] & 0xFFFFFFFF) ))
  local total=$(( 1 << (32 - len) )) first last usable
  if ((len >= 31)); then
    # RFC 3021 point-to-point /31 and host /32: every address is usable.
    first=$net last=$bcast usable=$total
  else
    first=$((net + 1)) last=$((bcast - 1)) usable=$((total - 2))
  fi
  int_to_ip "$CIDR_ADDR";                 printf '%-11s %s\n' address "$REPLY"
  cidr_format "$net" "$len";              printf '%-11s %s\n' network "$REPLY"
  int_to_ip "${MASK[len]}";               printf '%-11s %s\n' netmask "$REPLY"
  int_to_ip $(( ~MASK[len] & 0xFFFFFFFF )); printf '%-11s %s\n' wildcard "$REPLY"
  int_to_ip "$bcast";                     printf '%-11s %s\n' broadcast "$REPLY"
  int_to_ip "$first"; local f=$REPLY
  int_to_ip "$last"
  printf '%-11s %s - %s\n' hosts "$f" "$REPLY"
  printf '%-11s %s\n' usable "$usable"
}
