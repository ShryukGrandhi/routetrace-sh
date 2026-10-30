# shellcheck shell=bash

_summary() { cidr_summarize "$@"; echo "${SUMMARY[*]-}"; }

test_summarize_adjacent_blocks() {
  assert_eq "10.1.0.0/22" "$(_summary 10.1.0.0/24 10.1.1.0/24 10.1.2.0/24 10.1.3.0/24)"
}

test_summarize_does_not_over_summarize() {
  # 10.0.1.0/24 + 10.0.2.0/24 are adjacent but not a valid /23 pair.
  assert_eq "10.0.1.0/24 10.0.2.0/24" "$(_summary 10.0.2.0/24 10.0.1.0/24)"
}

test_summarize_overlaps_and_duplicates() {
  assert_eq "192.168.0.0/16" "$(_summary 192.168.5.0/24 192.168.0.0/16 192.168.5.0/24 192.168.255.128/25)"
}

test_summarize_whole_space() {
  assert_eq "0.0.0.0/0" "$(_summary 128.0.0.0/1 0.0.0.0/1)"
  assert_eq "255.255.255.255/32" "$(_summary 255.255.255.255/32)"
}

test_summarize_odd_range() {
  # 10.0.0.1-10.0.0.6 as /32s collapses to the minimal exact cover.
  assert_eq "10.0.0.1/32 10.0.0.2/31 10.0.0.4/31 10.0.0.6/32" \
    "$(_summary 10.0.0.1/32 10.0.0.2/32 10.0.0.3/32 10.0.0.4/32 10.0.0.5/32 10.0.0.6/32)"
}

test_summarize_host_bits_are_cleared() {
  assert_eq "10.1.0.0/16" "$(_summary 10.1.2.3/16)"
}

test_summarize_cli_reads_stdin() {
  local out
  out=$(printf '172.16.0.0/25\n172.16.0.128/25\n' | "$RT" summarize)
  assert_eq "172.16.0.0/24" "$out"
}

test_hosts_to_len() {
  hosts_to_len 1; assert_eq 30 "$REPLY"
  hosts_to_len 2; assert_eq 30 "$REPLY"
  hosts_to_len 3; assert_eq 29 "$REPLY"
  hosts_to_len 254; assert_eq 24 "$REPLY"
  hosts_to_len 255; assert_eq 23 "$REPLY"
  assert_fail hosts_to_len 0
  assert_fail hosts_to_len x
}

test_vlsm_largest_first_and_aligned() {
  local out
  out=$(cidr_vlsm 10.10.0.0/22 lab:100 office:300 p2p:2 guest:50)
  assert_eq "office lab guest p2p" "$(echo "$out" | awk '{printf "%s%s", sep, $1; sep=" "}')"
  assert_eq "10.10.0.0/23 10.10.2.0/25 10.10.2.128/26 10.10.2.192/30" \
    "$(echo "$out" | awk '{printf "%s%s", sep, $3; sep=" "}')"
}

test_vlsm_out_of_space() {
  assert_fail cidr_vlsm 192.168.1.0/24 a:200 b:100
  assert_fail cidr_vlsm 192.168.1.0/24 big:300
}

test_vlsm_rejects_bad_request() {
  assert_fail cidr_vlsm 192.168.1.0/24 nocolon
  assert_fail cidr_vlsm 192.168.1.0/24 a:0
}
