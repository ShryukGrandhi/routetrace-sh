# shellcheck shell=bash

test_ip_to_int_roundtrip() {
  local ip
  for ip in 0.0.0.0 255.255.255.255 10.1.2.3 192.168.100.200 1.0.0.1; do
    assert_ok ip_to_int "$ip"
    int_to_ip "$REPLY"
    assert_eq "$ip" "$REPLY" "roundtrip"
  done
  ip_to_int 10.0.0.1
  assert_eq 167772161 "$REPLY"
}

test_ip_to_int_rejects_garbage() {
  local bad
  for bad in 256.0.0.1 1.2.3 1.2.3.4.5 "" a.b.c.d "1.2.3.4 " -1.2.3.4 1.2.3.1000; do
    assert_fail ip_to_int "$bad"
  done
}

test_leading_zeros_are_decimal_not_octal() {
  ip_to_int 010.008.009.010
  int_to_ip "$REPLY"
  assert_eq 10.8.9.10 "$REPLY"
}

test_mask_to_len() {
  mask_to_len 255.255.255.0; assert_eq 24 "$REPLY"
  mask_to_len 255.255.255.252; assert_eq 30 "$REPLY"
  mask_to_len 0.0.0.0; assert_eq 0 "$REPLY"
  mask_to_len 255.255.255.255; assert_eq 32 "$REPLY"
  assert_fail mask_to_len 255.0.255.0
  assert_fail mask_to_len 255.255.255.1
}

test_cidr_parse_forms() {
  cidr_parse 10.1.2.3/20
  int_to_ip "$CIDR_NET"; assert_eq 10.1.0.0 "$REPLY"
  assert_eq 20 "$CIDR_LEN"
  cidr_parse 172.16.5.9 255.255.0.0
  int_to_ip "$CIDR_NET"; assert_eq 172.16.0.0 "$REPLY"
  assert_eq 16 "$CIDR_LEN"
  cidr_parse 8.8.8.8
  assert_eq 32 "$CIDR_LEN"
  assert_fail cidr_parse 10.0.0.0/33
  assert_fail cidr_parse 10.0.0.0/
  assert_fail cidr_parse 10.0.0.0 255.0.255.0
}

test_cidr_contains() {
  cidr_parse 10.0.0.0/8
  ip_to_int 10.200.1.1
  assert_ok cidr_contains "$CIDR_NET" "$CIDR_LEN" "$REPLY"
  ip_to_int 11.0.0.0
  assert_fail cidr_contains "$CIDR_NET" "$CIDR_LEN" "$REPLY"
  # /0 contains everything
  ip_to_int 255.255.255.255
  assert_ok cidr_contains 0 0 "$REPLY"
}

test_calc_report() {
  local out
  out=$("$RT" calc 192.168.10.77 255.255.255.224)
  assert_contains "$out" "network     192.168.10.64/27"
  assert_contains "$out" "broadcast   192.168.10.95"
  assert_contains "$out" "wildcard    0.0.0.31"
  assert_contains "$out" "hosts       192.168.10.65 - 192.168.10.94"
  assert_contains "$out" "usable      30"
}

test_calc_point_to_point_31() {
  local out
  out=$("$RT" calc 10.0.0.0/31)
  assert_contains "$out" "hosts       10.0.0.0 - 10.0.0.1"
  assert_contains "$out" "usable      2"
}

test_calc_rejects_bad_input() {
  assert_fail "$RT" calc 300.1.1.1/24
}
