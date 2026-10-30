# shellcheck shell=bash

# _acl KIND ENTRY... -> ACL id in A
_acl() {
  local kind=$1 e
  shift
  acl_get 0 T "$kind"
  A=$REPLY
  for e in "$@"; do acl_add_entry "$A" "$e" || fail "rejected: $e"; done
}

# _eval PROTO SRC DST [SPORT DPORT EST] -> prints permit/deny
_eval() {
  local p s d
  proto_number "$1"; p=$REPLY
  ip_to_int "$2"; s=$REPLY
  ip_to_int "$3"; d=$REPLY
  acl_eval "$A" "$p" "$s" "$d" "${4:-1024}" "${5:-0}" "${6:-0}"
  echo "$REPLY"
}

test_standard_acl_matches_source_only() {
  _acl std "deny host 10.0.0.5" "permit 10.0.0.0 0.0.0.255" "permit 172.16.1.1"
  assert_eq deny "$(_eval ip 10.0.0.5 1.1.1.1)"
  assert_eq permit "$(_eval ip 10.0.0.6 1.1.1.1)"
  assert_eq permit "$(_eval ip 172.16.1.1 1.1.1.1)"
  assert_eq deny "$(_eval ip 172.16.1.2 1.1.1.1)"
}

test_implicit_deny() {
  _acl ext "permit tcp any any eq 22"
  assert_eq deny "$(_eval udp 1.1.1.1 2.2.2.2 1024 22)"
  acl_eval "$A" 17 1 2 3 22 0
  assert_eq -1 "$ACL_HIT"
}

test_first_match_wins() {
  _acl ext "deny tcp any host 10.2.0.10 eq 80" "permit ip any any"
  assert_eq deny "$(_eval tcp 1.1.1.1 10.2.0.10 1024 80)"
  assert_eq permit "$(_eval tcp 1.1.1.1 10.2.0.10 1024 443)"
}

test_port_operators() {
  _acl ext "permit tcp any any range 8000 8080" "permit udp any any lt 100" \
    "permit tcp any any gt 60000" "permit udp any neq 53 any eq 5000"
  assert_eq permit "$(_eval tcp 1.1.1.1 2.2.2.2 1 8000)"
  assert_eq permit "$(_eval tcp 1.1.1.1 2.2.2.2 1 8080)"
  assert_eq deny "$(_eval tcp 1.1.1.1 2.2.2.2 1 8081)"
  assert_eq permit "$(_eval udp 1.1.1.1 2.2.2.2 1 99)"
  assert_eq deny "$(_eval udp 1.1.1.1 2.2.2.2 1 100)"
  assert_eq permit "$(_eval tcp 1.1.1.1 2.2.2.2 1 60001)"
  assert_eq deny "$(_eval tcp 1.1.1.1 2.2.2.2 1 60000)"
  assert_eq permit "$(_eval udp 1.1.1.1 2.2.2.2 1234 5000)"
  assert_eq deny "$(_eval udp 1.1.1.1 2.2.2.2 53 5000)"
}

test_named_ports_and_protocols() {
  _acl ext "permit tcp any any eq www" "permit udp any any eq domain" "permit 89 any any"
  assert_eq permit "$(_eval tcp 1.1.1.1 2.2.2.2 1 80)"
  assert_eq permit "$(_eval udp 1.1.1.1 2.2.2.2 1 53)"
  assert_eq permit "$(_eval ospf 1.1.1.1 224.0.0.5)"
  assert_eq deny "$(_eval icmp 1.1.1.1 2.2.2.2)"
}

test_ip_matches_every_protocol_and_ignores_ports() {
  _acl ext "permit ip 10.0.0.0 0.255.255.255 any"
  assert_eq permit "$(_eval icmp 10.9.9.9 2.2.2.2)"
  assert_eq permit "$(_eval udp 10.9.9.9 2.2.2.2 5 6)"
  assert_eq deny "$(_eval udp 11.9.9.9 2.2.2.2 5 6)"
}

test_non_contiguous_wildcard() {
  # Match x.y.Z.1 for any third octet: the "every site's .1 gateway" trick.
  _acl ext "permit ip any 10.20.0.1 0.0.255.0"
  assert_eq permit "$(_eval ip 1.1.1.1 10.20.0.1)"
  assert_eq permit "$(_eval ip 1.1.1.1 10.20.77.1)"
  assert_eq deny "$(_eval ip 1.1.1.1 10.20.77.2)"
  assert_eq deny "$(_eval ip 1.1.1.1 10.21.77.1)"
}

test_established_keyword() {
  _acl ext "permit tcp any any established"
  assert_eq deny "$(_eval tcp 1.1.1.1 2.2.2.2 80 40000 0)"
  assert_eq permit "$(_eval tcp 1.1.1.1 2.2.2.2 80 40000 1)"
}

test_hit_counters() {
  _acl ext "permit icmp any any" "deny ip any any"
  acl_eval "$A" 1 1 2 0 0 0
  acl_eval "$A" 1 1 2 0 0 0
  acl_eval "$A" 6 1 2 0 0 0
  local first=${ACL_ACES[A]%% *}
  assert_eq 2 "${ACE_HITS[first]}"
  assert_eq 1 "${ACE_HITS[first + 1]}"
}

test_invalid_entries_rejected() {
  acl_get 0 X ext
  local x=$REPLY e
  for e in "allow ip any any" "permit tcp any" "permit bogus any any" \
    "permit udp any any eq 70000" "permit icmp any any established" \
    "permit tcp any any eq 22 trailing" "permit ip 10.0.0.300 0.0.0.255 any"; do
    assert_fail acl_add_entry "$x" "$e"
  done
}

test_numbered_acl_ranges() {
  acl_kind_for_number 10; assert_eq std "$REPLY"
  acl_kind_for_number 1500; assert_eq std "$REPLY"
  acl_kind_for_number 110; assert_eq ext "$REPLY"
  acl_kind_for_number 2600; assert_eq ext "$REPLY"
  assert_fail acl_kind_for_number 200
}
