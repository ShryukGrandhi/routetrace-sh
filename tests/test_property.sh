# shellcheck shell=bash
# Randomized cross-checks against tests/oracle.py (Python ipaddress).

_rand32() { REPLY=$(( (RANDOM << 17) | (RANDOM << 2) | (RANDOM & 3) )); }

_oracle() { python3 "$ROOT/tests/oracle.py" "$1"; }

test_property_cidr_math_matches_python() {
  local i len out a n m b
  RANDOM=101
  out=$(
    for ((i = 0; i < 400; i++)); do
      _rand32; a=$REPLY
      len=$((RANDOM % 33))
      int_to_ip "$a"; local ip=$REPLY
      cidr_parse "$ip/$len"
      cidr_format "$CIDR_NET" "$len"; n=$REPLY
      int_to_ip "${MASK[len]}"; m=$REPLY
      int_to_ip $(( CIDR_NET | (~MASK[len] & 0xFFFFFFFF) )); b=$REPLY
      echo "$ip/$len $n $m $b"
    done | _oracle cidr
  ) || fail "$out"
}

test_property_summarize_matches_collapse_addresses() {
  local i j k out list
  RANDOM=202
  out=$(
    for ((i = 0; i < 150; i++)); do
      list=()
      k=$((RANDOM % 12 + 1))
      for ((j = 0; j < k; j++)); do
        # Cluster inside 10.0.0.0/20 so neighbours and overlaps are common.
        int_to_ip $(( (10 << 24) | ((RANDOM & 0xF) << 12) | (RANDOM & 0xFFF) ))
        list[j]="$REPLY/$((RANDOM % 9 + 20))"
      done
      cidr_summarize "${list[@]}"
      echo "${list[*]}|${SUMMARY[*]}"
    done | _oracle summarize
  ) || fail "$out"
}

test_property_lpm_matches_brute_force() {
  local i a len out routes=""
  RANDOM=303
  out=$({
    for ((i = 0; i < 250; i++)); do
      len=$((RANDOM % 17 + 8))
      a=$(( ((172 << 24) | (16 << 16) | (RANDOM << 1)) & MASK[len] ))
      # A few short prefixes (/0 - /4) so the default route path is covered.
      ((i % 50 == 0)) && { len=$((i / 50)); a=$(( (172 << 24) & MASK[len] )); }
      rib_add 0 "$a" "$len" S 1 "" 1 0
      cidr_format "$a" "$len"
      routes+="$REPLY "
    done
    echo "$routes"
    for ((i = 0; i < 600; i++)); do
      a=$(( (172 << 24) | (16 << 16) | (RANDOM << 1) | (RANDOM & 1) ))
      ((i % 7 == 0)) && { _rand32; a=$REPLY; }
      int_to_ip "$a"; local ip=$REPLY
      if rib_lookup 0 "$a"; then
        cidr_format "${RT_NET[REPLY]}" "${RT_LEN[REPLY]}"
        echo "$ip $REPLY"
      else
        echo "$ip none"
      fi
    done
  } | _oracle lpm) || fail "$out"
}

test_property_acl_wildcards_match_bitwise_reference() {
  local i out acl protos=(ip tcp udp icmp) p s sw d dw port act text dport
  RANDOM=404
  acl_get 0 P ext
  acl=$REPLY
  out=$({
    for ((i = 0; i < 60; i++)); do
      p=${protos[RANDOM % 4]}
      # Random (often non-contiguous) wildcards over a small address space.
      int_to_ip $(( (10 << 24) | (RANDOM & 0x0303) )); s=$REPLY
      int_to_ip $(( RANDOM & 0x0F0F )); sw=$REPLY
      int_to_ip $(( (10 << 24) | (RANDOM & 0x0303) )); d=$REPLY
      int_to_ip $(( RANDOM & 0x0F0F )); dw=$REPLY
      act=permit; ((RANDOM % 2)) && act=deny
      port=any; text="$act $p $s $sw $d $dw"
      if [[ $p == tcp || $p == udp ]] && ((RANDOM % 2)); then
        port=$((RANDOM % 4 + 20))
        text+=" eq $port"
      fi
      acl_add_entry "$acl" "$text" || { echo "rejected $text"; exit 1; }
      echo "ace $act $p $s $sw $d $dw $port"
    done
    for ((i = 0; i < 800; i++)); do
      p=${protos[RANDOM % 3 + 1]}
      int_to_ip $(( (10 << 24) | (RANDOM & 0x0F0F) )); s=$REPLY
      int_to_ip $(( (10 << 24) | (RANDOM & 0x0F0F) )); d=$REPLY
      dport=$((RANDOM % 4 + 20))
      proto_number "$p"; local pn=$REPLY
      ip_to_int "$s"; local si=$REPLY
      ip_to_int "$d"
      acl_eval "$acl" "$pn" "$si" "$REPLY" 1024 "$dport" 0
      echo "pkt $p $s $d $dport $REPLY"
    done
  } | _oracle acl) || fail "$out"
}
