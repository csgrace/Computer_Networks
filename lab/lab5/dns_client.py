#!/usr/bin/env python3
import argparse
import random
import socket
import struct
import sys
import time

# DNS type codes
QTYPE_MAP = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "AAAA": 28,
}
QCLASS_IN = 1

# A small set of root servers (IPv4)
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
    "198.97.190.53",   # h.root-servers.net
    "192.36.148.17",   # i.root-servers.net
    "192.58.128.30",   # j.root-servers.net
    "193.0.14.129",    # k.root-servers.net
    "199.7.83.42",     # l.root-servers.net
    "202.12.27.33",    # m.root-servers.net
]

def encode_qname(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    parts = name.split(".")
    out = bytearray()
    for p in parts:
        if len(p) > 63:
            raise ValueError("Label too long")
        out.append(len(p))
        out.extend(p.encode("ascii"))
    out.append(0)
    return bytes(out)

def decode_name(buf: bytes, offset: int):
    labels = []
    orig = offset
    jumped = False
    while True:
        if offset >= len(buf):
            raise ValueError("decode_name overflow")
        length = buf[offset]
        if length & 0xC0 == 0xC0:  # pointer
            if offset + 1 >= len(buf):
                raise ValueError("bad pointer")
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                orig = offset + 2
            offset = ptr
            jumped = True
            continue
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            labels.append(buf[offset:offset+length].decode("ascii"))
            offset += length
    name = ".".join(labels) if labels else ""
    return name, (orig if jumped else offset)

def pack_query(qname: str, qtype: int, rd: int, txid=None):
    if txid is None:
        txid = random.getrandbits(16)
    flags = (0 << 15) | (0 << 11) | (0 << 10) | (0 << 9) | ((1 if rd else 0) << 8) \
            | (0 << 7) | (0 << 4) | 0
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    return txid, header + question

def parse_rr(buf: bytes, offset: int):
    name, offset = decode_name(buf, offset)
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    rdata_start = offset
    rdata = buf[offset:offset + rdlength]
    offset += rdlength

    def parse_rdata():
        if rtype == 1:  # A
            return socket.inet_ntop(socket.AF_INET, rdata)
        if rtype == 28:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (2, 5):  # NS or CNAME
            nm, _ = decode_name(buf, rdata_start)
            return nm
        if rtype == 15:  # MX
            pref = struct.unpack_from("!H", buf, rdata_start)[0]
            exch, _ = decode_name(buf, rdata_start + 2)
            return {"preference": pref, "exchange": exch}
        # default raw
        return rdata.hex()

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdata_raw": rdata,
        "rdata": parse_rdata(),
    }, offset

def parse_response(buf: bytes):
    (txid, flags, qdcount, ancount, nscount, arcount) = struct.unpack_from("!HHHHHH", buf, 0)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_name(buf, offset)
        qtype, qclass = struct.unpack_from("!HH", buf, offset)
        offset += 4
        questions.append({"qname": qname, "qtype": qtype, "qclass": qclass})

    answers = []
    for _ in range(ancount):
        rr, offset = parse_rr(buf, offset)
        answers.append(rr)

    authorities = []
    for _ in range(nscount):
        rr, offset = parse_rr(buf, offset)
        authorities.append(rr)

    additionals = []
    for _ in range(arcount):
        rr, offset = parse_rr(buf, offset)
        additionals.append(rr)

    return {
        "txid": txid,
        "flags": {"qr": qr, "opcode": opcode, "aa": aa, "tc": tc, "rd": rd, "ra": ra, "rcode": rcode},
        "question": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }

def udp_query(server_ip: str, qname: str, qtype: int, rd: int, timeout=3.0, tcp_fallback=True):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    txid, packet = pack_query(qname, qtype, rd)
    sock.sendto(packet, (server_ip, 53))
    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        raise TimeoutError(f"UDP query timeout to {server_ip}")
    finally:
        sock.close()

    resp = parse_response(data)
    # TCP fallback when TC=1 (truncated)
    if tcp_fallback and resp["flags"]["tc"] == 1:
        # TCP DNS: length-prefixed
        t = socket.create_connection((server_ip, 53), timeout=timeout)
        try:
            t.sendall(struct.pack("!H", len(packet)) + packet)
            ldata = t.recv(2)
            if len(ldata) < 2:
                raise IOError("short tcp length")
            (msg_len,) = struct.unpack("!H", ldata)
            data = b""
            while len(data) < msg_len:
                chunk = t.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            t.close()
        resp = parse_response(data)
    return resp, server_ip

def collect_glue_ips(additionals):
    ips = []
    for rr in additionals:
        if rr["type"] == 1:   # A
            ips.append(rr["rdata"])
    return ips

def rr_name_is_child_of(name: str, domain: str) -> bool:
    name = name.rstrip(".")
    domain = domain.rstrip(".")
    return name == domain or name.endswith("." + domain) if domain else True

def resolve_iterative(qname: str, qtype: int, max_steps=30):
    current_servers = ROOT_SERVERS[:]
    visited = []
    name_to_resolve = qname.rstrip(".") + "."

    for step in range(1, max_steps + 1):
        if not current_servers:
            raise RuntimeError("No name servers to query")

        server = random.choice(current_servers)
        resp, srv_ip = udp_query(server, name_to_resolve, qtype, rd=0)
        visited.append({"server": srv_ip, "resp": resp})

        flags = resp["flags"]
        answers = resp["answers"]
        auths = resp["authorities"]
        adds = resp["additionals"]

        # If we got the desired answer from authoritative server
        if len(answers) > 0:
            # If contains CNAME and not the desired final type, follow CNAME
            cname_target = None
            for rr in answers:
                if rr["type"] == 5:  # CNAME
                    cname_target = rr["rdata"]
            # If we already have target type in answers and AA=1 -> success
            have_target = any(rr["type"] == qtype for rr in answers)
            if have_target and flags["aa"] == 1:
                return visited  # success with authoritative answer
            # Follow CNAME
            if cname_target and cname_target != name_to_resolve:
                name_to_resolve = cname_target
                # continue querying from root or try same server set first
                continue

        # No final answer yet: use referrals in authority + additional (glue)
        ns_names = [rr["rdata"] for rr in auths if rr["type"] == 2]  # NS records
        glue_ips = collect_glue_ips(adds)
        if glue_ips:
            current_servers = glue_ips
            continue

        # No glue: resolve NS names to IPs using a temporary recursive query
        resolved_ips = []
        for ns in ns_names:
            try:
                r, _ = udp_query("8.8.8.8", ns, QTYPE_MAP["A"], rd=1)
                for rr in r["answers"]:
                    if rr["type"] == 1:
                        resolved_ips.append(rr["rdata"])
            except Exception:
                pass
        if resolved_ips:
            current_servers = resolved_ips
            continue

        # Fallback to roots again
        current_servers = ROOT_SERVERS[:]

    raise RuntimeError("Max steps reached without final authoritative answer")

def pretty_print_trace(trace, qname, qtype_str):
    print(f"=== Iterative resolution trace for {qname} {qtype_str} (RD=0) ===")
    for i, hop in enumerate(trace, 1):
        srv = hop["server"]
        flags = hop["resp"]["flags"]
        ans = hop["resp"]["answers"]
        auth = hop["resp"]["authorities"]
        add = hop["resp"]["additionals"]
        print(f"[{i}] from {srv}  AA={flags['aa']} RA={flags['ra']} RD={flags['rd']} RCODE={flags['rcode']}")
        if ans:
            print("  Answers:")
            for rr in ans:
                print(f"    {rr['name']}  type={rr['type']}  ttl={rr['ttl']}  rdata={rr['rdata']}")
        if auth:
            print("  Authority:")
            for rr in auth:
                print(f"    {rr['name']}  NS={rr['rdata']}" if rr["type"] == 2 else f"    {rr}")
        if add:
            print("  Additional:")
            for rr in add:
                if rr["type"] in (1, 28):
                    print(f"    {rr['name']}  {('A' if rr['type']==1 else 'AAAA')}={rr['rdata']}")
    print("=== End trace ===")

def main():
    parser = argparse.ArgumentParser(description="Simple DNS client (RD=0 iterative and RD=1 single-hop)")
    parser.add_argument("qname", help="query name, e.g., www.sina.com.cn")
    parser.add_argument("qtype", choices=list(QTYPE_MAP.keys()), help="A/AAAA/CNAME/NS/MX")
    parser.add_argument("--rd", type=int, choices=[0,1], default=0, help="Recursion Desired bit (0 iterative, 1 recursive)")
    parser.add_argument("--server", default=None, help="DNS server for RD=1 mode (default 8.8.8.8)")
    args = parser.parse_args()

    qname = args.qname
    qtype_str = args.qtype.upper()
    qtype = QTYPE_MAP[qtype_str]

    if args.rd == 1:
        server = args.server or "8.8.8.8"
        resp, srv_ip = udp_query(server, qname, qtype, rd=1)
        flags = resp["flags"]
        print(f"Server: {srv_ip}  AA={flags['aa']} RA={flags['ra']} RD={flags['rd']} RCODE={flags['rcode']}")
        print("Answers:")
        for rr in resp["answers"]:
            print(f"  {rr['name']}  type={rr['type']}  ttl={rr['ttl']}  rdata={rr['rdata']}")
        if not resp["answers"]:
            print("  <no answers>")
        print("Authority/Additional (if any) shown for reference:")
        for rr in resp["authorities"]:
            if rr["type"] == 2:
                print(f"  AUTH NS: {rr['rdata']}")
        for rr in resp["additionals"]:
            if rr["type"] in (1, 28):
                print(f"  ADDR: {rr['name']} -> {rr['rdata']}")
    else:
        trace = resolve_iterative(qname, qtype)
        pretty_print_trace(trace, qname, qtype_str)
        last = trace[-1]
        flags = last["resp"]["flags"]
        final_answers = last["resp"]["answers"]
        print(f"\nFinal server: {last['server']}  AA={flags['aa']} RA={flags['ra']} RD={flags['rd']} RCODE={flags['rcode']}")
        if final_answers:
            print("Final Answers:")
            for rr in final_answers:
                print(f"  {rr['name']}  type={rr['type']}  ttl={rr['ttl']}  rdata={rr['rdata']}")
        else:
            print("Final answer set is empty (may be CNAME-only, NXDOMAIN, or need another follow-up).")

if __name__ == "__main__":
    main()