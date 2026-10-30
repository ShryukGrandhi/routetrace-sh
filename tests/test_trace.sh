# shellcheck shell=bash

_trace() { # _trace DIR SRC DST [opts] -> RESULT line
  "$RT" trace "$@" -q
}

test_campus_loads_cleanly() {
  local out
  out=$("$RT" check "$CAMPUS")
  assert_eq "0 problem(s) found in 4 router(s)" "$out"
}

test_delivered_across_two_routers() {
  local out
  out=$(_trace "$CAMPUS" 10.1.0.20 10.3.0.20 -p tcp -d 22)
  assert_eq "RESULT DELIVERED to host 10.3.0.20 via R3 GigabitEthernet0/2 (hops: 2)" "$out"
}

test_full_trace_output() {
  local out
  out=$("$RT" trace "$CAMPUS" 10.3.0.5 198.51.100.1)
  assert_contains "$out" " 1  R3     in GigabitEthernet0/2  [S 0.0.0.0/0 [1/0] via 10.0.23.1]  out GigabitEthernet0/1 -> 10.0.23.1"
  assert_contains "$out" " 2  R2     in GigabitEthernet0/1  [S 0.0.0.0/0 [1/0] via 203.0.113.1, GigabitEthernet0/3]"
  assert_contains "$out" "RESULT DELIVERED to router ISP Loopback0 (hops: 3)"
}

test_outbound_acl_permits_web_denies_rdp() {
  assert_contains "$(_trace "$CAMPUS" 10.1.0.20 10.2.0.10 -p tcp -d 443)" "RESULT DELIVERED"
  assert_contains "$(_trace "$CAMPUS" 10.1.0.20 10.2.0.10 -p tcp -d https)" "RESULT DELIVERED"
  assert_eq "RESULT DROPPED denied by ACL SERVERS out on R2 GigabitEthernet0/2 (hops: 2)" \
    "$(_trace "$CAMPUS" 10.3.0.20 10.2.0.10 -p tcp -d 3389)"
}

test_ssh_to_servers_only_from_lan_a() {
  assert_contains "$(_trace "$CAMPUS" 10.1.0.20 10.2.0.30 -p tcp -d 22)" "RESULT DELIVERED"
  assert_contains "$(_trace "$CAMPUS" 10.3.0.20 10.2.0.30 -p tcp -d 22)" "RESULT DROPPED"
  # Return traffic of an established session is allowed by entry 40.
  assert_contains "$(_trace "$CAMPUS" 10.3.0.20 10.2.0.30 -p tcp -s 5555 -d 22 -e)" "RESULT DELIVERED"
}

test_inbound_acl_blocks_host() {
  assert_eq "RESULT DROPPED denied by ACL LAN_A_IN in on R1 GigabitEthernet0/0 (hops: 1)" \
    "$(_trace "$CAMPUS" 10.1.0.66 10.2.0.10 -p tcp -d 80)"
}

test_numbered_acl_blocks_telnet() {
  assert_contains "$(_trace "$CAMPUS" 10.3.0.9 10.1.0.20 -p tcp -d telnet)" "denied by ACL 110 in on R3"
  assert_contains "$(_trace "$CAMPUS" 10.3.0.9 10.1.0.20 -p tcp -d 22)" "RESULT DELIVERED"
}

test_spoofed_source_hits_implicit_deny() {
  local out
  out=$("$RT" trace "$CAMPUS" 10.3.0.9 10.1.0.20 -f R3 2>&1)
  assert_contains "$out" "RESULT DELIVERED"
  out=$("$RT" trace "$CAMPUS" 10.77.0.9 10.1.0.20 -f R3)
  assert_contains "$out" "RESULT DELIVERED" # no ingress interface -> router-originated
}

test_null_route() {
  assert_eq "RESULT DROPPED null route on R2 (hops: 2)" "$(_trace "$CAMPUS" 10.1.0.5 10.99.1.1)"
}

test_router_originated_and_local_delivery() {
  assert_eq "RESULT DELIVERED to router R3 GigabitEthernet0/1 (hops: 3)" \
    "$(_trace "$CAMPUS" 10.0.12.1 10.0.23.2)"
}

test_static_next_hop_resolves_via_default_when_link_is_down() {
  local tmp out
  tmp=$(mktemp -d)
  cp "$CAMPUS"/*.cfg "$tmp"/
  # Shut R1's link to R3. Like IOS, 10.3.0.0/16 via 10.0.13.2 stays installed
  # because 10.0.13.2 now resolves recursively through the default route.
  awk '/^interface GigabitEthernet0\/2/{print; print " shutdown"; next} {print}' "$CAMPUS/r1.cfg" >"$tmp/r1.cfg"
  assert_contains "$("$RT" routes "$tmp" R1)" "S 10.3.0.0/16 [1/0] via 10.0.13.2"
  out=$("$RT" trace "$tmp" 10.1.0.20 10.3.0.20 -p tcp -d 22)
  assert_contains "$out" "out GigabitEthernet0/1 -> 10.0.12.2"
  assert_contains "$out" "RESULT DELIVERED to host 10.3.0.20 via R3 GigabitEthernet0/2 (hops: 3)"
  out=$("$RT" check "$tmp")
  assert_contains "$out" "R1: next hop 10.0.13.2 of 'S 10.3.0.0/16 [1/0] via 10.0.13.2' resolves only via the default route"
  rm -rf "$tmp"
}

test_floating_static_takes_over_when_link_is_down() {
  local tmp out
  tmp=$(mktemp -d)
  cp "$CAMPUS"/*.cfg "$tmp"/
  # Same failure without a default route: the AD 200 backup becomes active.
  awk '/^interface GigabitEthernet0\/2/{print; print " shutdown"; next} /^ip route 0.0.0.0/{next} {print}' \
    "$CAMPUS/r1.cfg" >"$tmp/r1.cfg"
  out=$("$RT" routes "$tmp" R1)
  assert_contains "$out" "S 10.3.0.0/16 [200/0] via 10.0.12.2"
  out=$("$RT" check "$tmp")
  assert_contains "$out" "R1: 'S 10.3.0.0/16 [1/0] via 10.0.13.2' not installed, next hop does not resolve"
  out=$("$RT" trace "$tmp" 10.1.0.20 10.3.0.20 -p tcp -d 22)
  assert_contains "$out" " 2  R2 "
  assert_contains "$out" "RESULT DELIVERED to host 10.3.0.20 via R3 GigabitEthernet0/2 (hops: 3)"
  rm -rf "$tmp"
}

test_routing_loop_ttl_exceeded() {
  local out
  out=$(_trace "$FIX/loop" 192.168.1.10 8.8.8.8)
  assert_eq "RESULT DROPPED TTL exceeded at B (routing loop?) (hops: 64)" "$out"
  out=$(TRACE_TTL=5 "$RT" trace "$FIX/loop" 192.168.1.10 8.8.8.8 -q)
  assert_contains "$out" "(hops: 5)"
}

test_no_route() {
  assert_eq "RESULT DROPPED no route to 8.8.8.8 on X (hops: 1)" "$(_trace "$FIX/broken" 10.9.9.50 8.8.8.8 -f X)"
}

test_arp_failure_for_missing_next_hop() {
  assert_contains "$(_trace "$FIX/broken" 10.9.9.50 172.17.1.1 -f X)" \
    "next hop 10.0.0.77 not present on Gi0/0 segment (ARP failure)"
}

test_exit_codes() {
  "$RT" trace "$CAMPUS" 10.1.0.20 10.3.0.20 -q >/dev/null
  assert_eq 0 $?
  "$RT" trace "$CAMPUS" 10.1.0.5 10.99.1.1 -q >/dev/null
  assert_eq 1 $?
  "$RT" trace "$CAMPUS" 10.1.0.5 999.1.1.1 -q >/dev/null 2>&1
  assert_eq 2 $?
  "$RT" trace "$CAMPUS" 172.31.0.1 10.1.0.1 -q >/dev/null 2>&1
  assert_eq 2 $?
}

test_check_reports_problems() {
  local out
  out=$("$RT" check "$FIX/broken")
  assert_eq 1 $?
  assert_contains "$out" "duplicate address 10.9.9.1 on Y Gi0/1 and X Gi0/1"
  assert_contains "$out" "mask mismatch: X Gi0/0 /24 vs Y Gi0/0 /25"
  assert_contains "$out" "X Gi0/0: inbound ACL MISSING is not defined"
  assert_contains "$out" "X: 'S 172.16.0.0/16 [1/0] via 192.0.2.1' not installed, next hop does not resolve"
  assert_contains "$out" "X: next hop 10.0.0.77 of 'S 172.17.0.0/16 [1/0] via 10.0.0.77' is not a known router interface"
  assert_contains "$out" "5 problem(s) found in 2 router(s)"
}

test_parse_error_reports_file_and_line() {
  local out
  out=$("$RT" routes "$FIX/badsyntax" Z 2>&1)
  assert_eq 2 $?
  assert_contains "$out" "z.cfg:3: bad ip address"
}

test_lookup_and_acl_commands() {
  assert_eq "S 10.99.0.0/16 [1/0] is directly connected, Null0" "$("$RT" lookup "$CAMPUS" R2 10.99.3.3)"
  assert_eq "deny (matched: deny tcp any any eq telnet)" "$("$RT" acl "$CAMPUS" R3 110 tcp 10.3.0.4 10.1.0.1 1234 23)"
  assert_eq "deny (implicit deny)" "$("$RT" acl "$CAMPUS" R3 110 udp 10.4.0.4 10.1.0.1 1 53)"
}
