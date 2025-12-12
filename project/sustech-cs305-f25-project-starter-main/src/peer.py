import sys
import os
import select
import struct
import socket
import hashlib
import argparse
import pickle
import time
import threading
from queue import Queue, Empty
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
# wsl
# python3 -m utils.make_data ./example/ex_file.tar ./example/data1.fragment 4 1,2
# python3 -m utils.make_data ./example/ex_file.tar ./example/data2.fragment 4 3,4
# sed -n '3p' master.chunkhash > example/download.chunkhash
# perl utils/hupsim.pl -m example/ex_topo.map -n example/ex_nodes_map -p 50305 -v 2

# wsl
# export SIMULATOR="127.0.0.1:50305"
# python3 -m example.demo_sender -p example/ex_nodes_map -c example/data2.fragment -m 1 -i 2 -v 3

# wsl
# export SIMULATOR="127.0.0.1:50305"
# python3 -m example.demo_receiver -p example/ex_nodes_map -c example/data1.fragment -m 1 -i 1 -v 3
# DOWNLOAD example/download.chunkhash example/test.fragment

# wsl
# pytest test/test_01_basic_handshaking.py
# pytest test/test_02_basic_transfer.py
# pytest test/test_03_basic_concurrency.py
# pytest test/test_04_basic_crash.py
# pytest test/test_05_adv_1.py
# pytest test/test_06_adv_2.py

BUF_SIZE: int = 1400
CHUNK_DATA_SIZE: int = 512 * 1024
MAX_PAYLOAD: int = 1024

MAX_CONCURRENT_DOWNLOADS_PER_CHUNK = 2
MAX_TOTAL_CONCURRENT_DOWNLOADS = 4

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
g_downloading: Dict[Tuple[Tuple[str, int], str], Dict] = {}

# Chunks we want (set by DOWNLOAD): list of chunk hex
g_want_chunks: List[str] = []

# Candidate map (chunk -> list of candidate addrs)
g_candidates: Dict[str, List[Tuple[str, int]]] = {}

# Upload sessions: chunkhash -> session dict
# session: {'addr': (ip,port), 'chunk_bytes': bytes, 'last_sent_seq': int,
#           'total_segs': int, 'last_sent_time': float, 'timeout': float}
g_uploads: Dict[Tuple[str,Tuple[str,int]],Dict] = {}

# Active upload count
g_active_uploads: int = 0

# Output map: chunkhash -> output filename
g_output_map: Dict[str, str] = {}

#重发WHOHAS次数
g_whohas_retry_count: int = 0

g_out_of_order_buffer: Dict[Tuple[Tuple[str, int], str], Dict[int, bytes]] = {}  # 乱序包缓存

#最大重试次数
MAX_WHOHAS_RETRIES: int = 3

#窗口滑动
WINDOW_SIZE = 10

# 下载会话超时时间（用于检测发送端崩溃），单位：秒
DOWNLOAD_TIMEOUT: float = 3.0

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
    global g_want_chunks, g_receiving, g_candidates, g_output_map, g_downloading, g_whohas_retry_count

    g_whohas_retry_count = 0
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
                    # print(f"DEBUG: Added chunk {ch} to download list")
    except Exception as e:
        print(f"process_download: failed to read {chunk_file}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return

    if not g_want_chunks:
        return


    payload = b"".join(_hex_to_bytes(h) for h in g_want_chunks)
    pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

    sent_count = 0
    for p in g_context.peers:
        try:
            pid = int(p[0])
            if pid == g_context.identity:
                continue
            peer_ip = p[1]
            peer_port = int(p[2])
            sock.sendto(pkt, (peer_ip, peer_port))
            sent_count += 1
        except Exception as e:
            continue
    # 准确定时重传
    threading.Timer(3.0, _retry_whohas, [sock]).start()

def _start_upload_session(chunk_hex: str, addr: Tuple[str, int], sock: simsocket.SimSocket) -> None:
    """
    Initialize an upload session and send first DATA segment.
    """
    global g_uploads, g_active_uploads, g_context

    chunk_bytes = g_context.has_chunks[chunk_hex]
    total_segs = (len(chunk_bytes) + MAX_PAYLOAD - 1) // MAX_PAYLOAD

    preset_timeout = getattr(g_context, "timeout", 0) or 0
    if preset_timeout:
        initial_timeout = float(preset_timeout)
    else:
        initial_timeout = 0.5

    # Congestion control initialization (Tahoe-style)
    cc_state = "slow_start"  # "slow_start" or "congestion_avoidance"
    ssthresh = 64
    cwnd = 1
    dupACKcount = 0

    session = {
        "addr": addr,
        "chunk_bytes": chunk_bytes,
        "total_segs": total_segs,

        # RDT / timing
        "last_sent_seq": 0,
        "last_sent_time": 0.0,
        "timeout": initial_timeout,
        "sent_times": {},

        # ACK / seq window
        "last_acked": 0,
        "send_base": 1,
        "next_seq_num": 1,

        # RTT estimation
        "estimatedRTT": initial_timeout,
        "devRTT": initial_timeout / 2.0,
        "timeoutInterval": initial_timeout,

        # Congestion control fields
        "cc_state": cc_state,
        "ssthresh": ssthresh,
        "cwnd": cwnd,  # packets
        "dupACKcount": dupACKcount,
        "fast_retransmitted": set(),

        # "window_size": WINDOW_SIZE,

    }

    key = (chunk_hex, addr)
    g_uploads[key] = session
    g_active_uploads += 1

    # Send up to cwnd initial segments
    _send_within_cwnd(key, sock)

    print(f"DEBUG: Upload session started for {chunk_hex}, cwnd={cwnd}, ssthresh={ssthresh}, total_segs={total_segs}")

def _send_data_segment_for_session(session_key: Tuple[str, Tuple[str, int]], sock: simsocket.SimSocket,
                                   seq: int = None) -> None:
    """(Re)send specific segment for an upload session."""
    global g_active_uploads

    session = g_uploads.get(session_key)
    if not session:
        return

    addr = session["addr"]
    chunk_bytes = session["chunk_bytes"]
    total_segs = session["total_segs"]

    if seq is None:
        seq = session.get("last_acked", 0) + 1

    # 不再发送 EOF 包，Bound seq to [1, total_segs]
    if seq > total_segs or seq < 1:
        return

    print(f"DEBUG: Sending segment {seq}/{total_segs} to {addr}")

    # 发送数据段
    start = (seq - 1) * MAX_PAYLOAD
    end = min(start + MAX_PAYLOAD, len(chunk_bytes))
    part = chunk_bytes[start:end]

    # 检查数据段大小
    if len(part) == 0:
        print(f"DEBUG: ERROR: Empty segment at seq {seq}")
        return

    pkt = _pack_header(PktType.DATA, HEADER_LEN + len(part), seq=seq, ack=0) + part
    sock.sendto(pkt, addr)

    # 更新会话状态
    now = time.time()
    session["last_sent_time"] = now
    session["last_sent_seq"] = seq
    session["sent_times"][seq] = now

    # 设置超时间隔
    if "timeoutInterval" not in session or not session["timeoutInterval"]:
        session["timeoutInterval"] = session.get("timeout", 0.5)

def _send_within_cwnd(session_key: Tuple[str, Tuple[str, int]], sock: simsocket.SimSocket) -> None:
    """
    Send new segments while inflight < cwnd.
    inflight = next_seq_num - send_base
    """
    session = g_uploads.get(session_key)
    if not session:
        return

    total_segs = session["total_segs"]
    send_base = session["send_base"]
    next_seq_num = session["next_seq_num"]
    cwnd = session.get("cwnd", 1)

    while (next_seq_num - send_base) < min(cwnd, WINDOW_SIZE) and next_seq_num <= total_segs:
        _send_data_segment_for_session(session_key, sock, seq=next_seq_num)
        session["next_seq_num"] = next_seq_num + 1
        next_seq_num += 1

def _on_new_ack(session_key: Tuple[str, Tuple[str, int]], sock: simsocket.SimSocket, ack_num: int, now: float) -> None:
    """
    Handle new ACK that advances last_acked. Apply cc rules and send within cwnd.
    """
    global g_active_uploads
    session = g_uploads.get(session_key)
    if not session:
        return

    total_segs = session["total_segs"]
    last_acked = session.get("last_acked", 0)
    send_base = session.get("send_base", 1)

    # RTT sample: from sent_times[ack_num]
    sent_times = session.get("sent_times", {})
    if ack_num in sent_times:
        sampleRTT = max(0.0, now - sent_times[ack_num])
        rdt_update_rtt(session, sampleRTT)

    # Advance acked window
    session["last_acked"] = ack_num
    session["send_base"] = ack_num + 1

    # Congestion control transitions + growth
    cc_state = session.get("cc_state", "slow_start")
    cwnd = session.get("cwnd", 1)
    ssthresh = session.get("ssthresh", 64)

    # This ACK advances the round; per spec we can reset dupACKcount for new round,
    # BUT do not reset when fast retransmit just happened (spec says not reset after FR);
    # We interpret "per-round" as reset when progress occurs.
    session["dupACKcount"] = 0
    session["fast_retransmitted"]. discard(ack_num + 1)  # optional cleanup

    if cc_state == "slow_start":
        # cwnd += 1 per new ACK
        cwnd += 1
        session["cwnd"] = cwnd
        # Transition if cwnd >= ssthresh
        if cwnd >= ssthresh:
            session["cc_state"] = "congestion_avoidance"
            print(f"DEBUG: CC transition to congestion_avoidance, cwnd={cwnd}, ssthresh={ssthresh}")
    else:
        # Congestion Avoidance: cwnd += floor(1/cwnd) per new ACK
        inc = max(1, int(1 / max(cwnd, 1)))
        cwnd += inc
        session["cwnd"] = max(cwnd, 1)

    # Completion check
    if ack_num >= total_segs:
        print(f"DEBUG: 🎉 All data segments ACKed for {session_key[0]}, upload completed! cwnd={session['cwnd']}")
        try:
            del g_uploads[session_key]
            g_active_uploads = max(0, g_active_uploads - 1)
        except KeyError:
            pass
        return

    # Transmit new packets allowed by increased cwnd
    _send_within_cwnd(session_key, sock)

def _on_duplicate_ack(session_key: Tuple[str, Tuple[str, int]], sock: simsocket.SimSocket, ack_num: int) -> None:
    """
    Handle duplicate ACK. Increment dupACKcount and fast retransmit once per seq when dupACKcount==3.
    """
    session = g_uploads.get(session_key)
    if not session:
        return

    dup = session.get("dupACKcount", 0) + 1
    session["dupACKcount"] = dup
    print(f"DEBUG: DUP ACK {ack_num}, dupACKcount={dup}")

    # Fast retransmit once when dupACKcount==3
    next_seq = ack_num + 1
    if dup == 3 and next_seq not in session["fast_retransmitted"]:
        session["fast_retransmitted"].add(next_seq)
        print(f"DEBUG: 🚀 Fast retransmit seq={next_seq} (Tahoe), set ssthresh=max(floor(cwnd/2),2), cwnd=1")

        # Tahoe-style reaction
        cwnd = session.get("cwnd", 1)
        ssthresh = max(int(cwnd / 2), 2)
        session["ssthresh"] = ssthresh
        session["cwnd"] = 1
        session["cc_state"] = "slow_start"

        # Retransmit the presumed lost packet
        _send_data_segment_for_session(session_key, sock, seq=next_seq)
        session["send_base"] = ack_num + 1
        session["next_seq_num"] = max(session.get("next_seq_num", ack_num + 1), ack_num + 2)
        # Do NOT reset dupACKcount after fast retransmit (per spec)

def _stdin_reader(cmd_queue):
    """Blockingly read lines from stdin and put them into the queue."""
    try:
        while True:
            line = sys.stdin.readline()
            if line == "":
                # No data right now (EOF on this read), wait a bit and retry.
                # This prevents the reader thread from exiting and keeps stdin open.
                time.sleep(0.01)
                continue
            cmd_queue.put(line)
    except Exception:
        # 静默退出，让主循环自己结束
        pass

def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function should receive data, unpack the standard header,
    and then use the packet type to route the packet to the appropriate
    handling logic (e.g., for WHOHAS, IHAVE, GET, DATA, ACK).

    :param sock: The :class:`simsocket.SimSocket` with a pending packet.
    :type sock: simsocket.SimSocket
    """
    global g_context, g_active_uploads, g_candidates, g_receiving, g_want_chunks, g_uploads, g_downloading, g_out_of_order_buffer

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
        peer_has_chunks = []
        for i in range(0, len(data), 20):
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            peer_has_chunks.append(hhex)

        for hhex in peer_has_chunks:
            if hhex in g_want_chunks:
                addr = (from_addr[0], from_addr[1])

                download_key = (addr, hhex)
                if download_key in g_downloading:
                    continue

                # 检查总并发下载数限制
                if len(g_downloading) >= 20:
                    continue

                # 发送 GET 请求并创建下载会话
                pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(_hex_to_bytes(hhex)), seq=0,
                                       ack=0) + _hex_to_bytes(hhex)
                sock.sendto(pkt_get, from_addr)

                g_downloading[download_key] = {
                    "chunk": hhex,
                    "expected_seq": 1,
                    "total_segs": None,
                    "start_time": time.time(),
                    "last_ack_time": time.time()
                }

                # 初始化接收缓冲区
                if hhex not in g_receiving:
                    g_receiving[hhex] = b""

                if hhex not in g_candidates:
                    g_candidates[hhex] = []
                if addr not in g_candidates[hhex]:
                    g_candidates[hhex].append(addr)
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
        # 查找对应的下载会话
        session = None
        session_key = None
        for key, sess in g_downloading.items():
            if key[0] == addr_key:
                session = sess
                session_key = key
                break

        if not session:
            return

        chunk_hex = session["chunk"]
        expected = session["expected_seq"]
        seq_num = seq_h
        payload = data

        # ⭐ 忽略空数据包
        if len(payload) == 0:
            print(f"DEBUG: ⚠️ Ignoring empty DATA packet seq={seq_num}")
            return

        # 初始化 total_segs
        if session["total_segs"] is None:
            session["total_segs"] = (CHUNK_DATA_SIZE + MAX_PAYLOAD - 1) // MAX_PAYLOAD
            print(f"DEBUG:  Initialized total_segs={session['total_segs']} for chunk {chunk_hex}")

        if chunk_hex not in g_receiving:
            g_receiving[chunk_hex] = b""

        if session_key not in g_out_of_order_buffer:
            g_out_of_order_buffer[session_key] = {}

        if seq_num == expected:
            # 正确的序列号,追加数据
            g_receiving[chunk_hex] += payload
            session["last_ack_time"] = time.time()

            # 发送ACK
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            sock.sendto(ack_pkt, from_addr)

            # 更新期望序列号
            session["expected_seq"] = expected + 1

            # ⭐ 检查缓冲区中是否有后续的连续包
            buffer = g_out_of_order_buffer[session_key]
            while (expected + 1) in buffer:
                next_seq = expected + 1
                next_payload = buffer.pop(next_seq)

                g_receiving[chunk_hex] += next_payload
                session["expected_seq"] = next_seq + 1
                session["last_ack_time"] = time.time()

                # 发送ACK
                ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=next_seq)
                sock.sendto(ack_pkt, from_addr)

                expected = next_seq
                print(f"DEBUG: ✨ Delivered buffered packet seq={next_seq}, new expected={expected + 1}")

            # 检查是否完成
            current_expected = session["expected_seq"]
            if (current_expected - 1) == session["total_segs"]:
                print(f"DEBUG: 📦 All segments received for {chunk_hex}")
                _complete_download(chunk_hex, len(g_receiving[chunk_hex]), session_key, from_addr, sock,
                                   current_expected - 1)

        elif seq_num > expected:
            # ⭐ 乱序包: 缓存起来
            buffer = g_out_of_order_buffer[session_key]
            if seq_num not in buffer:  # 避免重复缓存
                buffer[seq_num] = payload
                print(
                    f"DEBUG: 📦 Buffered out-of-order packet seq={seq_num}, expected={expected}, buffer_size={len(buffer)}")

            # 发送累积ACK (期望序列号的前一个)
            ack_to_send = expected - 1
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=ack_to_send)
            sock.sendto(ack_pkt, from_addr)
        else:
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            sock.sendto(ack_pkt, from_addr)
            print(f"DEBUG: 🔁 Duplicate packet seq={seq_num}, expected={expected}")

    # ACK: sender side (RDT + Tahoe CC)

    # 有滑动窗口 可通过test3
    elif pkg_type == PktType.ACK:
        ack_num = ack_h
        now = time.time()

        # find sessions for this from_addr
        for session_key, session in list(g_uploads.items()):
            chunk_hex, sess_addr = session_key
            if sess_addr != (from_addr[0], from_addr[1]):
                continue

            total_segs = session.get("total_segs", 0)
            last_acked = session.get("last_acked", 0)

            print(
                f"DEBUG: ACK received: {ack_num}, last_acked: {last_acked}, total_segs: {total_segs}, cwnd={session.get('cwnd', 1)}, ssthresh={session.get('ssthresh', 64)}, cc_state={session.get('cc_state', 'slow_start')}")

            if ack_num > last_acked:
                # New ACK progresses the window
                _on_new_ack(session_key, sock, ack_num, now)
            elif ack_num == session.get("last_acked", 0):
                # Duplicate ACK
                _on_duplicate_ack(session_key, sock, ack_num)
            # else: stale ACK (ack_num < last_acked), ignore


def process_user_input(sock: simsocket.SimSocket, line: str) -> None:
    """
    Handles a single line of user input from ``sys.stdin``.

    Parses the input and, if the command is "DOWNLOAD", calls
    :func:`process_download` with the provided file paths.

    :param sock: The :class:`simsocket.SimSocket` to be passed to
                 :func:`process_download`.
    :type sock: simsocket.SimSocket
    """
    try:
        parts = line.strip().split()
        if len(parts) != 3:
            return
        command, chunk_file, output_file = parts
    except Exception:
        return
    if command.upper() == "DOWNLOAD":
        process_download(sock, chunk_file, output_file)


def peer_run(context: PeerContext) -> None:
    global g_context
    g_context = context

    addr: AddressType = (context.ip, context.port)
    sock = simsocket.SimSocket(context.identity, addr, verbose=context.verbose)

    # 新增：命令队列 + 后台读取线程
    cmd_queue: Queue[str] = Queue()
    t = threading.Thread(target=_stdin_reader, args=(cmd_queue,), daemon=True)
    t.start()

    try:
        while True:
            # 仅监视 socket，避免在 Windows 上 select sys.stdin
            ready = select.select([sock], [], [], 0.01)

            if ready[0]:
                process_inbound_udp(sock)

            # 处理所有已到达的命令行
            while True:
                try:
                    line = cmd_queue.get_nowait()
                except Empty:
                    break
                process_user_input(sock, line)

            # 下面保留你已有的定时/超时逻辑（发送端重传、下载会话超时等）
            now = time.time()
            for session_key, session in list(g_uploads.items()):
                timeout = rdt_get_timeout(session)
                send_base = session.get("send_base", 1)
                # 使用最早未被 ACK 的分片的发送时间作为超时基准（更符合 RDT）
                last = session.get("sent_times", {}).get(send_base, session.get("last_sent_time", 0))
                if now - last > timeout:
                    # Tahoe-style reaction on timeout
                    cwnd = session.get("cwnd", 1)
                    ssthresh = max(int(cwnd / 2), 2)
                    session["ssthresh"] = ssthresh
                    session["cwnd"] = 1
                    session["cc_state"] = "slow_start"
                    # 可选：重置 dupACKcount
                    session["dupACKcount"] = 0
                    print(
                        f"DEBUG: ⏲️ Timeout: set ssthresh={ssthresh}, cwnd=1, cc_state=slow_start; retransmit seq={send_base}")
                    seq_to_retransmit = send_base
                    _send_data_segment_for_session(session_key, sock, seq=seq_to_retransmit)

            if not getattr(g_context, "timeout", 0):
                for session_key, session in list(g_downloading.items()):
                    last_recv = session.get("last_ack_time", session.get("start_time", 0))
                    if now - last_recv > DOWNLOAD_TIMEOUT:
                        _handle_download_timeout(session_key, sock)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


# def _force_complete_transfer():
#     """禁用强制完成"""
#     pass


# if int(time.time()) % 10 == 0:  # 每10秒检查一次进行强制传输
#     _force_complete_transfer()

def rdt_update_rtt(session: dict, sampleRTT: float) -> None:
    """Update EstimatedRTT / DevRTT / TimeoutInterval per given formulas."""
    # use constants ALPHA, BETA defined earlier
    prevEst = session.get("estimatedRTT", None)
    prevDev = session.get("devRTT", None)
    if prevEst is None:
        # first sample: set estimates directly
        est = sampleRTT
        dev = sampleRTT / 2.0
    else:
        est = (1 - ALPHA) * prevEst + ALPHA * sampleRTT
        prevDev = prevDev if prevDev is not None else sampleRTT / 2.0
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

# 重传
def _retry_whohas(sock: simsocket.SimSocket) -> None:
    """重试发送 WHOHAS 包的函数"""
    global g_whohas_retry_count, g_want_chunks, g_downloading

    time.sleep(3)

    # 检查是否需要重试
    if not g_downloading and g_want_chunks and g_whohas_retry_count < MAX_WHOHAS_RETRIES:
        g_whohas_retry_count += 1

        # 重新发送 WHOHAS
        payload = b"".join(_hex_to_bytes(h) for h in g_want_chunks)
        pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

        sent_count = 0
        for p in g_context.peers:
            try:
                pid = int(p[0])
                if pid == g_context.identity:
                    continue
                peer_ip = p[1]
                peer_port = int(p[2])
                sock.sendto(pkt, (peer_ip, peer_port))
                sent_count += 1
            except Exception as e:
                continue

        # 如果还有重试次数，安排下一次重试
        if g_whohas_retry_count < MAX_WHOHAS_RETRIES:
            threading.Timer(3.0, _retry_whohas, [sock]).start()  # 3秒后再次重试


def _handle_download_timeout(session_key: Tuple[Tuple[str, int], str], sock: simsocket.SimSocket) -> None:
    """
    下载端检测到某个发送端长时间无响应（可能崩溃）时：
    1. 清空当前 chunk 的已接收数据；
    2. 将该发送端从候选列表中移除；
    3. 若还有其它候选 peer，则向其重新发送 GET；
    4. 若没有候选，则重新对该 chunk 发送 WHOHAS。
    """
    global g_downloading, g_receiving, g_candidates, g_context

    session = g_downloading.pop(session_key, None)
    if not session:
        return

    addr, chunk_hex = session_key
    print(f"DEBUG: Download timeout for chunk {chunk_hex} from {addr}, will retry with another peer if possible")

    # 1. 清空该 chunk 已接收的数据
    if chunk_hex in g_receiving:
        g_receiving[chunk_hex] = b""

    # 2. 从候选列表中移除当前发送端
    cand_list = g_candidates.get(chunk_hex, [])
    cand_list = [c for c in cand_list if c != addr]
    g_candidates[chunk_hex] = cand_list

    # 3. 若还有其它候选 peer，直接向其中一个发送 GET 并创建新的下载会话
    if cand_list:
        new_addr = cand_list[0]
        try:
            payload = _hex_to_bytes(chunk_hex)
        except ValueError:
            # 非法 hash，放弃
            return

        pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(payload), seq=0, ack=0) + payload
        sock.sendto(pkt_get, new_addr)

        g_downloading[(new_addr, chunk_hex)] = {
            "chunk": chunk_hex,
            "expected_seq": 1,
            "total_segs": None,
            "start_time": time.time(),
            "last_ack_time": time.time(),
        }
        print(f"DEBUG: Retry chunk {chunk_hex} from backup peer {new_addr}")
        return

    # 4. 没有其它候选 peer，重新对该 chunk 发送 WHOHAS，等待新的 IHAVE
    try:
        payload = _hex_to_bytes(chunk_hex)
    except ValueError:
        return

    pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload
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

    print(f"DEBUG: No backup peer for chunk {chunk_hex}, re-broadcast WHOHAS")

# Replace the entire _complete_download(...) function with this improved implementation:

def _complete_download(chunk_hex: str, total_bytes: int, session_key: Tuple, from_addr: Tuple,
                       sock: simsocket.SimSocket, seq_num: int):
    """完成下载的改进版本"""
    global g_receiving, g_downloading, g_context, g_output_map, g_want_chunks, g_candidates, g_out_of_order_buffer

    # 清理乱序缓冲区
    if session_key in g_out_of_order_buffer:
        del g_out_of_order_buffer[session_key]

    # 从下载会话中移除
    if session_key in g_downloading:
        session = g_downloading[session_key]
        total_segs = session.get("total_segs")

        # 检查是否真的完成了
        if seq_num != total_segs:
            print(f"DEBUG: ⚠️ Download incomplete: received seq {seq_num}, expected {total_segs}")
            return

        try:
            del g_downloading[session_key]
        except KeyError:
            pass

    data = g_receiving.get(chunk_hex)
    if not data:
        print(f"DEBUG: ❌ No data in g_receiving for {chunk_hex}")
        return

    # 检查数据大小
    if len(data) != CHUNK_DATA_SIZE:
        print(f"DEBUG: ⚠️ Data size mismatch:  got {len(data)}, expected {CHUNK_DATA_SIZE}")
        if len(data) < CHUNK_DATA_SIZE:
            return

    out_file = g_output_map.get(chunk_hex)
    if not out_file:
        print(f"DEBUG: ❌ No output file mapped for {chunk_hex}")
        return

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)

    try:
        # 验证数据的SHA1哈希
        sha1 = hashlib.sha1()
        sha1.update(data)
        computed_hash = sha1.hexdigest()

        if computed_hash != chunk_hex:
            print(f"❌ Hash mismatch!  Expected {chunk_hex}, got {computed_hash}")
            return

        # 使用pickle格式写入
        existing_data = {}
        if os.path.exists(out_file):
            try:
                with open(out_file, "rb") as f:
                    existing_data = pickle.load(f)
            except:
                existing_data = {}

        existing_data[chunk_hex] = data

        with open(out_file, "wb") as f:
            pickle.dump(existing_data, f)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        print(f"✅ Chunk {chunk_hex} verified and written to {out_file} (size: {len(data)} bytes)")

        g_context.has_chunks[chunk_hex] = data
        if chunk_hex in g_want_chunks:
            g_want_chunks.remove(chunk_hex)

        if chunk_hex in g_candidates:
            g_candidates[chunk_hex] = [c for c in g_candidates[chunk_hex] if c != from_addr]

    except Exception as e:
        print(f"❌ Write failed:  {e}")
        import traceback
        traceback.print_exc()


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
