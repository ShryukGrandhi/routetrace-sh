# shellcheck shell=bash

_add() { # _add PREFIX TYPE NEXTHOP AD
  cidr_parse "$1"
  local nh=""
  [[ -n $3 ]] && { ip_to_int "$3"; nh=$REPLY; }
  rib_add 0 "$CIDR_NET" "$CIDR_LEN" "$2" "$nh" "" "$4" 0
}

_lookup() { # prints the matched prefix or "none"
  ip_to_int "$1"
  if rib_lookup 0 "$REPLY"; then
    cidr_format "${RT_NET[REPLY]}" "${RT_LEN[REPLY]}"
    echo "$REPLY"
  else
    echo none
  fi
}

test_longest_prefix_wins() {
  _add 10.0.0.0/8 S 1.1.1.1 1
  _add 10.1.0.0/16 S 1.1.1.2 1
  _add 10.1.2.0/24 S 1.1.1.3 1
  _add 0.0.0.0/0 S 1.1.1.4 1
  assert_eq 10.1.2.0/24 "$(_lookup 10.1.2.77)"
  assert_eq 10.1.0.0/16 "$(_lookup 10.1.3.1)"
  assert_eq 10.0.0.0/8 "$(_lookup 10.200.0.1)"
  assert_eq 0.0.0.0/0 "$(_lookup 11.0.0.1)"
}

test_no_default_means_no_route() {
  _add 10.0.0.0/8 S 1.1.1.1 1
  assert_eq none "$(_lookup 192.168.1.1)"
}

test_lower_admin_distance_wins_for_same_prefix() {
  _add 10.3.0.0/16 S 10.0.12.2 200
  _add 10.3.0.0/16 S 10.0.13.2 1
  ip_to_int 10.3.1.1; rib_lookup 0 "$REPLY"
  int_to_ip "${RT_NH[REPLY]}"
  assert_eq 10.0.13.2 "$REPLY"
  # Adding a worse route later must not displace the active one.
  _add 10.3.0.0/16 S 10.0.99.2 250
  ip_to_int 10.3.1.1; rib_lookup 0 "$REPLY"
  int_to_ip "${RT_NH[REPLY]}"
  assert_eq 10.0.13.2 "$REPLY"
}

test_prefix_lengths_kept_longest_first() {
  _add 10.0.0.0/8 S 1.1.1.1 1
  _add 10.1.2.0/24 S 1.1.1.1 1
  _add 0.0.0.0/0 S 1.1.1.1 1
  _add 10.1.0.0/16 S 1.1.1.1 1
  _add 10.1.2.0/24 S 1.1.1.9 5
  assert_eq "24 16 8 0" "${_RL_0% }"
}

test_prefix_length_list_has_no_duplicates() {
  _add 10.0.0.0/24 S 1.1.1.1 1
  _add 10.0.1.0/24 S 1.1.1.1 1
  _add 10.0.2.0/24 S 1.1.1.1 1
  _add 10.0.0.0/16 S 1.1.1.1 1
  _add 10.1.0.0/16 S 1.1.1.1 1
  assert_eq "24 16" "${_RL_0% }"
}

test_routers_have_separate_tables() {
  cidr_parse 10.0.0.0/8
  rib_add 0 "$CIDR_NET" 8 S 1 "" 1 0
  ip_to_int 10.1.1.1
  assert_ok rib_lookup 0 "$REPLY"
  assert_fail rib_lookup 1 "$REPLY"
}

test_linear_matches_hash_lookup() {
  local i a b
  RANDOM=7
  for ((i = 0; i < 200; i++)); do
    rib_add 0 $(( ((RANDOM << 17) | (RANDOM << 2)) & MASK[(i % 25) + 8] )) $(((i % 25) + 8)) S 1 "" $((RANDOM % 3 + 1)) 0
  done
  for ((i = 0; i < 300; i++)); do
    a=$(( (RANDOM << 17) | (RANDOM << 2) | (RANDOM & 3) ))
    b=none; rib_lookup 0 "$a" && b=$REPLY
    local c=none; rib_lookup_linear 0 "$a" && c=$REPLY
    if [[ $b != none ]]; then
      # Same prefix may be stored twice; compare the prefix and distance.
      assert_eq "${RT_NET[c]}/${RT_LEN[c]}/${RT_AD[c]}" "${RT_NET[b]}/${RT_LEN[b]}/${RT_AD[b]}"
    else
      assert_eq none "$c"
    fi
  done
}

test_recursive_next_hop_resolution() {
  # 10.0.0.0/30 connected on interface 3; 172.16.0.0/16 via 10.0.0.2;
  # 192.168.0.0/16 via 172.16.9.9 (recursive through the /16).
  cidr_parse 10.0.0.0/30; rib_add 0 "$CIDR_NET" 30 C "" 3 0 0
  _add 172.16.0.0/16 S 10.0.0.2 1
  _add 192.168.0.0/16 S 172.16.9.9 1
  ip_to_int 192.168.4.4; local dst=$REPLY
  rib_lookup 0 "$dst"
  assert_ok rib_resolve 0 "$REPLY" "$dst"
  assert_eq 3 "$RES_IF"
  int_to_ip "$RES_NH"; assert_eq 10.0.0.2 "$REPLY"
}

test_unresolvable_next_hop() {
  _add 192.168.0.0/16 S 172.16.9.9 1
  ip_to_int 192.168.4.4; local dst=$REPLY
  rib_lookup 0 "$dst"
  assert_fail rib_resolve 0 "$REPLY" "$dst"
}

test_recursion_loop_is_bounded() {
  _add 1.0.0.0/8 S 2.2.2.2 1
  _add 2.0.0.0/8 S 1.1.1.1 1
  ip_to_int 1.2.3.4; local dst=$REPLY
  rib_lookup 0 "$dst"
  assert_fail rib_resolve 0 "$REPLY" "$dst"
}
