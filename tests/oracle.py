"""Independent reference checks for the bash implementation.

Reads cases produced by tests/test_property.sh on stdin and verifies them with
Python's ipaddress module (or a deliberately different bit-by-bit algorithm
for ACL wildcards). Prints the number of cases checked; exits 1 on mismatch.
"""
import ipaddress
import sys


def check_cidr(lines):
    for line in lines:
        cidr, net, mask, bcast = line.split()
        n = ipaddress.ip_network(cidr, strict=False)
        got = (net, mask, bcast)
        want = (str(n), str(n.netmask), str(n.broadcast_address))
        if got != want:
            return f"{cidr}: bash {got} python {want}"


def check_summarize(lines):
    for line in lines:
        ins, outs = line.split("|")
        nets = [ipaddress.ip_network(c, strict=False) for c in ins.split()]
        want = [str(n) for n in ipaddress.collapse_addresses(nets)]
        if outs.split() != want:
            return f"{ins}: bash {outs.split()} python {want}"


def check_lpm(lines):
    routes = [ipaddress.ip_network(c) for c in lines[0].split()]
    for line in lines[1:]:
        addr, got = line.split()
        a = ipaddress.ip_address(addr)
        best = None
        for r in routes:
            if a in r and (best is None or r.prefixlen > best.prefixlen):
                best = r
        want = str(best) if best else "none"
        if got != want:
            return f"lookup {addr}: bash {got} python {want}"


def wildcard_match(addr, base, wildcard):
    a, b, w = (int(ipaddress.ip_address(x)) for x in (addr, base, wildcard))
    for bit in range(32):
        if not (w >> bit) & 1 and ((a >> bit) & 1) != ((b >> bit) & 1):
            return False
    return True


def check_acl(lines):
    # ACE lines: "ace action proto src swc dst dwc dport"
    # packet lines: "pkt proto src dst dport result"
    aces = []
    for line in lines:
        f = line.split()
        if f[0] == "ace":
            aces.append(f[1:])
            continue
        _, proto, src, dst, dport, got = f
        want = "deny"
        for action, aproto, s, sw, d, dw, ap in aces:
            if aproto != "ip" and aproto != proto:
                continue
            if not wildcard_match(src, s, sw) or not wildcard_match(dst, d, dw):
                continue
            if ap != "any" and proto in ("tcp", "udp") and ap != dport:
                continue
            want = action
            break
        if got != want:
            return f"packet {f[1:5]}: bash {got} python {want}"


def main():
    mode = sys.argv[1]
    lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
    err = {"cidr": check_cidr, "summarize": check_summarize,
           "lpm": check_lpm, "acl": check_acl}[mode](lines)
    if err:
        print(f"MISMATCH {mode}: {err}")
        sys.exit(1)
    print(f"{mode}: {len(lines)} lines agree")


if __name__ == "__main__":
    main()
