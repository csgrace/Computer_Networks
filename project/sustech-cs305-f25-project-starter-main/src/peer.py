import sys
import os
import select
import struct
import socket
import hashlib
import argparse
import pickle
import time

from typing import Dict, List, Tuple

# Ensure project root in sys.path so "utils" can be imported regardless of cwd
_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_this_dir, ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

"""
This is CS305 project skeleton code. Please refer to the example files -
  example/dump_receiver.py and
  example/dump_sender.py 
- to learn how to play with this skeleton.

The sample code is for reference only.
The given function is only one possible design, you are not required to follow it strictly.
We allow you to use better code design that conforms to best practices.
But ensure that your program's entry point is `peer.py` .
"""

BUF_SIZE: int = 1400
CHUNK_DATA_SIZE: int = 512 * 1024
MAX_PAYLOAD: int = 1024

HEADER_FMT: str = "BBHII"
HEADER_LEN: int = struct.calcsize(HEADER_FMT)

class PktType:
    WHOHAS = 0
    IHAVE = 1
    GET = 2
    DATA = 3
    ACK = 4
    DENIED = 5

# Global context
g_context: PeerContext | None = None

# Downloads in progress: chunkhash -> byte buffer (collector)
g_receiving: Dict[str, bytes] = {}

# Downloads metadata: mapping from source addr (ip,port) -> session
# each session: {'chunk': hex, 'expected_seq': int, 'total_segs': int}
g_downloading: Dict[Tuple[str, int], Dict] = {}

# Chunks we want (set by DOWNLOAD): list of chunk hex
g_want_chunks: List[str] = []

# Candidate map (chunk -> list of candidate addrs)
g_candidates: Dict[str, List[Tuple[str, int]]] = {}

# Upload sessions: chunkhash -> session dict
# session: {'addr': (ip,port), 'chunk_bytes': bytes, 'last_sent_seq': int,
#           'total_segs': int, 'last_sent_time': float, 'timeout': float}
g_uploads: Dict[str, Dict] = {}

# Active upload count
g_active_uploads: int = 0

# Output map: chunkhash -> output filename
g_output_map: Dict[str, str] = {}

# RTT params (as specified)
ALPHA = 0.15
BETA = 0.3

def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def _bytes_to_hex(b: bytes) -> str:
    return b.hex()

def _pack_header(ptype: int, plen: int, seq: int = 0, ack: int = 0) -> bytes:
    return struct.pack(
        HEADER_FMT, ptype, HEADER_LEN, socket.htons(plen), socket.htonl(seq), socket.htonl(ack)
    )

def process_download(
    sock: simsocket.SimSocket, chunk_file: str, output_file: str
) -> None:
    """
    Initiates and manages the download of one or more chunks.

    This function is called when a 'DOWNLOAD' command is received. It is
    responsible for reading the chunk hashes from the ``chunk_file``,
    orchestrating the network requests (e.g., sending WHOHAS, GET) to
    retrieve all necessary chunks, and saving the completed data to
    the ``output_file``.

    :param sock: The :class:`simsocket.SimSocket` for network communication.
    :param chunk_file: Path to the file containing hashes of chunks to download.
    :param output_file: Path to the file to save the downloaded chunk data.
    """
    global g_want_chunks, g_receiving, g_candidates, g_output_map, g_downloading

    g_want_chunks = []
    g_candidates = {}
    g_receiving = {}
    g_output_map = {}
    g_downloading = {}

    try:
        with open(chunk_file, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    _, ch = parts[0], parts[1]
                    g_want_chunks.append(ch)
                    g_receiving[ch] = b""
                    g_candidates[ch] = []
                    g_output_map[ch] = output_file
    except Exception as e:
        print(f"process_download: failed to read {chunk_file}: {e}", file=sys.stderr)
        return

    if not g_want_chunks:
        return

    # Build WHOHAS payload (concatenate 20-byte sha1 binary)
    payload = b"".join(_hex_to_bytes(h) for h in g_want_chunks)
    pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

    # Flood to all peers except self
    for p in g_context.peers:
        try:
            pid = int(p[0])
            if pid == g_context.identity:
                continue
            peer_ip = p[1]
            peer_port = int(p[2])
            sock.sendto(pkt, (peer_ip, peer_port))
        except Exception:
            continue
    # print("PROCESS DOWNLOAD SKELETON CODE CALLED.  Fill me in!")

def _start_upload_session(chunk_hex: str, addr: Tuple[str, int], sock: simsocket.SimSocket) -> None:
    """
    Initialize an upload session and send first DATA segment.
    """
    global g_uploads, g_active_uploads, g_context

    chunk_bytes = g_context.has_chunks[chunk_hex]
    total_segs = (len(chunk_bytes) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
    # timeout = getattr(g_context, "timeout", 0) or 0.5  # prefer context timeout if set, else 0.5s

    # If user specified timeout via context.args, respect it as a fixed starting timeout.
    preset_timeout = getattr(g_context, "timeout", 0) or 0
    if preset_timeout:
        initial_timeout = float(preset_timeout)
    else:
        initial_timeout = 0.5  # default initial timeout

    session = {
        "addr": addr,
        "chunk_bytes": chunk_bytes,
        "last_sent_seq": 0,  # last seq we have sent
        "total_segs": total_segs,
        "last_sent_time": 0.0,
        "timeout": initial_timeout,
        # New fields for RDT:
        "sent_times": {},  # seq -> last sent time
        "last_acked": 0,  # highest cumulative ack seen
        "dup_ack_counts": {},  # ack_num -> count
        "fast_retransmitted": set(),  # ack_nums that have triggered fast retransmit
        # RTT estimation fields
        "estimatedRTT": initial_timeout,
        "devRTT": initial_timeout / 2.0,
        "timeoutInterval": initial_timeout,
    }
    g_uploads[chunk_hex] = session
    g_active_uploads += 1

    # Send first segment
    next_seq = 1
    start = (next_seq - 1) * MAX_PAYLOAD
    part = chunk_bytes[start:start + MAX_PAYLOAD]
    pkt = _pack_header(PktType.DATA, HEADER_LEN + len(part), seq=next_seq, ack=0) + part
    sock.sendto(pkt, addr)
    now = time.time()

    now = time.time()
    session["last_sent_seq"] = next_seq
    session["last_sent_time"] = now
    session["sent_times"][next_seq] = now
    # timeoutInterval initially equals timeout (or estimated)
    session["timeoutInterval"] = session["timeout"] if session["timeout"] else session["estimatedRTT"]


def _send_data_segment_for_session(chunk_hex: str, sock: simsocket.SimSocket, seq: int = None) -> None:
    """(Re)send specific segment for an upload session."""
    session = g_uploads.get(chunk_hex)
    if not session:
        return
    addr = session["addr"]
    chunk_bytes = session["chunk_bytes"]
    total_segs = session["total_segs"]
    if seq is None:
        seq = session["last_sent_seq"]
    if seq < 1 or seq > total_segs:
        return
    start = (seq - 1) * MAX_PAYLOAD
    part = chunk_bytes[start:start + MAX_PAYLOAD]
    pkt = _pack_header(PktType.DATA, HEADER_LEN + len(part), seq=seq, ack=0) + part
    sock.sendto(pkt, addr)
    now = time.time()
    session["last_sent_time"] = now
    session["last_sent_seq"] = seq
    # record last send time for this seq (used to compute SampleRTT upon ACK)
    session["sent_times"][seq] = now
    # If timeoutInterval is not defined, ensure there's a value
    if "timeoutInterval" not in session or not session["timeoutInterval"]:
        session["timeoutInterval"] = session.get("timeout", 0.5)


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function should receive data, unpack the standard header,
    and then use the packet type to route the packet to the appropriate
    handling logic (e.g., for WHOHAS, IHAVE, GET, DATA, ACK).

    :param sock: The :class:`simsocket.SimSocket` with a pending packet.
    :type sock: simsocket.SimSocket
    """
    global g_context, g_active_uploads, g_candidates, g_receiving, g_want_chunks, g_uploads, g_downloading

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    try:
        pkg_type, hlen, plen, seq, ack = struct.unpack(HEADER_FMT, pkt[:HEADER_LEN])
    except Exception:
        return

    data = pkt[HEADER_LEN:]
    try:
        seq_h = socket.ntohl(seq)
        ack_h = socket.ntohl(ack)
    except Exception:
        seq_h = seq
        ack_h = ack

    # WHOHAS
    if pkg_type == PktType.WHOHAS:
        have_hashes = []
        for i in range(0, len(data), 20):
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            if hhex in g_context.has_chunks:
                have_hashes.append(hbytes)

        max_conn = getattr(g_context, "max_conn", None)
        if max_conn is None:
            max_conn = getattr(getattr(g_context, "args", None), "max_conn", None)
        can_upload = (g_active_uploads < max_conn) if isinstance(max_conn, int) else True

        if have_hashes and can_upload:
            payload = b"".join(have_hashes)
            pkt_ihave = _pack_header(PktType.IHAVE, HEADER_LEN + len(payload), seq=0, ack=0) + payload
            sock.sendto(pkt_ihave, from_addr)
        else:
            pkt_denied = _pack_header(PktType.DENIED, HEADER_LEN, seq=0, ack=0)
            sock.sendto(pkt_denied, from_addr)

    # IHAVE -> send GET and create downloading session
    elif pkg_type == PktType.IHAVE:
        for i in range(0, len(data), 20):
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            if hhex in g_want_chunks:
                # 在 IHAVE 处理里，发送 GET 之前：
                addr = (from_addr[0], from_addr[1])
                # 如果已经在下载该 addr 的另一chunk，跳过（保证一对一会话）
                if addr in g_downloading:
                    continue
                # 之后再发送 GET 并创建下载 session
                g_candidates.setdefault(hhex, []).append(addr)
                pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(hbytes), seq=0, ack=0) + hbytes
                sock.sendto(pkt_get, from_addr)
                g_downloading[addr] = {"chunk": hhex, "expected_seq": 1, "total_segs": None}

    # DENIED: ignore for now
    elif pkg_type == PktType.DENIED:
        pass

    # GET: start upload session (if have chunk and under max_conn)
    elif pkg_type == PktType.GET:
        if len(data) < 20:
            return
        requested_hex = _bytes_to_hex(data[:20])
        if requested_hex in g_context.has_chunks:
            max_conn = getattr(g_context, "max_conn", None)
            if max_conn is None:
                max_conn = getattr(getattr(g_context, "args", None), "max_conn", None)
            if isinstance(max_conn, int) and g_active_uploads >= max_conn:
                pkt_denied = _pack_header(PktType.DENIED, HEADER_LEN, seq=0, ack=0)
                sock.sendto(pkt_denied, from_addr)
            else:
                _start_upload_session(requested_hex, (from_addr[0], from_addr[1]), sock)

    # DATA: receiving side
    elif pkg_type == PktType.DATA:
        addr_key = (from_addr[0], from_addr[1])
        session = g_downloading.get(addr_key)
        if not session:
            return

        chunk_hex = session["chunk"]
        expected = session["expected_seq"]
        seq_num = seq_h

        if seq_num == expected:
            # append payload and ack
            g_receiving[chunk_hex] += data
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            sock.sendto(ack_pkt, from_addr)
            session["expected_seq"] += 1

            # Determine if this is the last segment:
            payload_len = len(data)

            # Case A: payload shorter than MAX_PAYLOAD => this is last segment
            last_segment_received = payload_len < MAX_PAYLOAD

            # Case B: fallback — if we've accumulated at least CHUNK_DATA_SIZE (original behavior)
            if len(g_receiving[chunk_hex]) >= CHUNK_DATA_SIZE:
                last_segment_received = True

            if last_segment_received:
                # If last segment was shorter, compute exact total bytes:
                total_bytes = len(g_receiving[chunk_hex])
                out_file = g_output_map.get(chunk_hex, f"download_{chunk_hex}.fragment")
                with open(out_file, "wb") as wf:
                    # write exactly the received bytes (some tests expect exact length)
                    pickle.dump({chunk_hex: g_receiving[chunk_hex][:total_bytes]}, wf)
                # update local has_chunks with the exact bytes
                sha1 = hashlib.sha1()
                sha1.update(g_receiving[chunk_hex][:total_bytes])
                g_context.has_chunks[chunk_hex] = g_receiving[chunk_hex][:total_bytes]
                # cleanup
                del g_receiving[chunk_hex]
                try:
                    del g_downloading[addr_key]
                except KeyError:
                    pass

        else:
            ack_to_send = session["expected_seq"] - 1
            if ack_to_send < 0:
                ack_to_send = 0
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=ack_to_send)
            sock.sendto(ack_pkt, from_addr)

    # ACK: sender side (RDT handling)
    elif pkg_type == PktType.ACK:
        ack_num = ack_h
        now = time.time()
        # find session for this peer
        for chunk_hex, session in list(g_uploads.items()):
            if session["addr"] == (from_addr[0], from_addr[1]):
                last_sent = session.get("last_sent_seq", 0)
                total = session.get("total_segs", 0)
                last_acked = session.get("last_acked", 0)
                sent_times = session.get("sent_times", {})

                # If this ACK advances the highest cumulative ACK (new information)
                if ack_num > last_acked:
                    # Compute SampleRTT if we have a send timestamp for acked seq
                    if ack_num in sent_times:
                        sampleRTT = now - sent_times[ack_num]
                        # Update RTT estimates & dynamic timeoutInterval
                        rdt_update_rtt(session, sampleRTT)

                    # advance last_acked
                    session["last_acked"] = ack_num
                    # clear dup count for this ack_num (we have new progress)
                    session["dup_ack_counts"].pop(ack_num, None)

                    # Remove timestamps for all seq <= ack_num (they are acknowledged)
                    for s in list(sent_times.keys()):
                        if s <= ack_num:
                            session["sent_times"].pop(s, None)

                    # Reset the retransmission timer to avoid immediate retransmit
                    session["last_sent_time"] = now

                    # If ack acknowledges the last sent segment, either finish or send next
                    if ack_num == last_sent:
                        if last_sent < total:
                            next_seq = last_sent + 1
                            _send_data_segment_for_session(chunk_hex, sock, seq=next_seq)
                            # ensure last_sent_time is up-to-date (send function sets it)
                            session["last_sent_time"] = time.time()
                        else:
                            # finished sending this chunk
                            try:
                                del g_uploads[chunk_hex]
                            except KeyError:
                                pass
                            if g_active_uploads > 0:
                                g_active_uploads -= 1
                    else:
                        # ack acknowledges some earlier seq; we keep sending where we were
                        if last_sent < total:
                            next_seq = last_sent + 1
                            _send_data_segment_for_session(chunk_hex, sock, seq=next_seq)
                            session["last_sent_time"] = time.time()

                # Duplicate ACK detected (ack_num == last_acked)
                elif ack_num == last_acked:
                    # handle duplicate ack counts and fast retransmit
                    cnt = session.get("dup_ack_counts", {}).get(ack_num, 0) + 1
                    session.setdefault("dup_ack_counts", {})[ack_num] = cnt
                    # If reached 3 duplicate ACKs, fast retransmit once for the missing seq (ack_num + 1)
                    if cnt >= 3 and (ack_num not in session.get("fast_retransmitted", set())):
                        missing_seq = ack_num + 1
                        if 1 <= missing_seq <= total:
                            _send_data_segment_for_session(chunk_hex, sock, seq=missing_seq)
                            session.setdefault("fast_retransmitted", set()).add(ack_num)
                            # update timer after fast retransmit
                            session["last_sent_time"] = time.time()
                # else: older/out-of-order ack - ignore
                break


    else:
        pass

    # print("SKELETON CODE CALLED, FILL this!")


def process_user_input(sock: simsocket.SimSocket) -> None:
    """
    Handles a single line of user input from ``sys.stdin``.

    Parses the input and, if the command is "DOWNLOAD", calls
    :func:`process_download` with the provided file paths.

    :param sock: The :class:`simsocket.SimSocket` to be passed to
                 :func:`process_download`.
    :type sock: simsocket.SimSocket
    """
    try:
        command, chunk_file, output_file = input().split()
    except Exception:
        return
    if command == "DOWNLOAD":
        process_download(sock, chunk_file, output_file)
    else:
        pass


def peer_run(context: PeerContext) -> None:
    """
    Runs the main event loop for the peer.

    Initializes the :class:`simsocket.SimSocket` and enters a loop
    that uses :func:`select.select` to monitor both the socket for
    inbound packets (handled by :func:`process_inbound_udp`) and
    ``sys.stdin`` for user commands (handled by
    :func:`process_user_input`).

    :param context: The peer's configuration and state object.
    """
    global g_context
    g_context = context

    addr: AddressType = (context.ip, context.port)
    sock = simsocket.SimSocket(context.identity, addr, verbose=context.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                now = time.time()
                for chunk_hex, session in list(g_uploads.items()):
                    last = session.get("last_sent_time", 0)
                    timeout = rdt_get_timeout(session)
                    if now - last > timeout:
                        seq = session.get("last_sent_seq", 1)
                        _send_data_segment_for_session(chunk_hex, sock, seq=seq)
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def rdt_update_rtt(session: dict, sampleRTT: float) -> None:
    """Update EstimatedRTT / DevRTT / TimeoutInterval per given formulas."""
    # use constants ALPHA, BETA defined earlier
    prevEst = session.get("estimatedRTT", sampleRTT)
    prevDev = session.get("devRTT", max(0.0, sampleRTT / 2.0))
    est = (1 - ALPHA) * prevEst + ALPHA * sampleRTT
    dev = (1 - BETA) * prevDev + BETA * abs(sampleRTT - est)
    session["estimatedRTT"] = est
    session["devRTT"] = dev
    session["timeoutInterval"] = est + 4 * dev


def rdt_get_timeout(session: dict) -> float:
    """
    Return the effective timeout for the session.
    If a user-specified fixed timeout (-t) is set in g_context, prefer that.
    Otherwise, return dynamic timeoutInterval computed from RTT.
    """
    if getattr(g_context, "timeout", 0):
        # respect user-specified fixed timeout
        return float(session.get("timeout", g_context.timeout))
    return float(session.get("timeoutInterval", session.get("timeout", 0.5)))


def rdt_handle_dup_ack(session: dict, ack_num: int, sock: simsocket.SimSocket, chunk_hex: str) -> None:
    """
    Maintain dup ack counts (per-round). When dup count reaches 3 for ack_num,
    do a fast retransmit for missing_seq = ack_num + 1 (only once per ack_num).
    """
    last_acked = session.get("last_acked", 0)
    # If ack advances beyond last_acked, reset dup counters for that ack
    if ack_num > last_acked:
        session["dup_ack_counts"].pop(ack_num, None)
        session["last_acked"] = ack_num
        return

    # duplicate ack
    cnt = session["dup_ack_counts"].get(ack_num, 0) + 1
    session["dup_ack_counts"][ack_num] = cnt

    # only trigger fast retransmit when count == 3 and not triggered before for this ack_num
    if cnt >= 3 and (ack_num not in session.get("fast_retransmitted", set())):
        missing_seq = ack_num + 1
        total = session.get("total_segs", 0)
        if 1 <= missing_seq <= total:
            _send_data_segment_for_session(chunk_hex, sock, seq=missing_seq)
            session.setdefault("fast_retransmitted", set()).add(ack_num)



def main() -> None:
    """
    Main entry point for the peer script.

    Parses command-line arguments, initializes the global PeerContext,
    and starts the peer's main run loop.
    """

    """
    -i: ID, it is the index in nodes.map

    -p: Peer list file, it will be in the form "*.map" like nodes.map.

    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in peer_context.
        The loaded dictionary has the form: {chunkhash: chunkdata}

    -m: The max number of peer that you can send chunk to concurrently.
        If more peers ask you for chunks, you should reply "DENIED"

    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.

    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT.
        If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """

    parser = argparse.ArgumentParser(
        description="CS305 Project Peer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--identity",
        dest="identity",
        type=int,
        help="Which peer # am I?",
    )
    parser.add_argument(
        "-p",
        "--peer-file",
        dest="peer_file",
        type=str,
        help="The list of all peers",
        default="nodes.map",
    )
    parser.add_argument(
        "-c",
        "--chunk-file",
        dest="chunk_file",
        type=str,
        help="Pickle dumped dictionary {chunkhash: chunkdata}",
    )
    parser.add_argument(
        "-m",
        "--max-conn",
        dest="max_conn",
        type=int,
        help="Max # of concurrent sending",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        type=int,
        help="verbose level",
        default=0,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        dest="timeout",
        type=int,
        help="pre-defined timeout",
        default=0,
    )
    args = parser.parse_args()

    context = PeerContext(args)
    peer_run(context)


if __name__ == "__main__":
    main()
