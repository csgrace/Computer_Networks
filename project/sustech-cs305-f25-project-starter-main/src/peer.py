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
# python3 -m utils.make_data ./example/ex_file.tar ./example/data1.fragment 4 1,2
# python3 -m utils.make_data ./example/ex_file.tar ./example/data2.fragment 4 3,4
# sed -n '3p' master.chunkhash > example/download.chunkhash
# perl utils/hupsim.pl -m example/ex_topo.map -n example/ex_nodes_map -p 50305 -v 2

# export SIMULATOR="127.0.0.1:50305"
# python3 -m example.demo_sender -p example/ex_nodes_map -c example/data2.fragment -m 1 -i 2 -v 3

# export SIMULATOR="127.0.0.1:50305"
# python3 -m example.demo_receiver -p example/ex_nodes_map -c example/data1.fragment -m 1 -i 1 -v 3
# DOWNLOAD example/download.chunkhash example/test.fragment

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
    global g_want_chunks, g_receiving, g_candidates, g_output_map, g_downloading

    g_want_chunks = []
    g_candidates = {}
    g_receiving = {}
    g_output_map = {}
    g_downloading = {}
    g_whohas_retry_count = 0

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

    session = {
        "addr": addr,
        "chunk_bytes": chunk_bytes,
        "last_sent_seq": 0,
        "total_segs": total_segs,
        "last_sent_time": 0.0,
        "timeout": initial_timeout,
        "sent_times": {},
        "last_acked": 0,
        "dup_ack_counts": {},
        "fast_retransmitted": set(),
        "estimatedRTT": initial_timeout,
        "devRTT": initial_timeout / 2.0,
        "timeoutInterval": initial_timeout,
        "window_size": WINDOW_SIZE,
        "send_base": 1,
        "next_seq_num": 1,
    }

    key = (chunk_hex, addr)
    g_uploads[key] = session
    g_active_uploads += 1

    # 使用流水线发送初始窗口的数据包
    initial_burst = min(WINDOW_SIZE, total_segs)
    for seq in range(1, initial_burst + 1):
        _send_data_segment_for_session(key, sock, seq=seq)
        session["next_seq_num"] = seq + 1

    print(f"DEBUG: Upload session started for {chunk_hex}, sent {initial_burst} initial segments")

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

    # 不再发送 EOF 包，序号范围限制在 [1, total_segs]
    if seq > total_segs:
        return

    print(f"DEBUG: Sending segment {seq}/{total_segs} to {addr}")

    # 发送数据段
    start = (seq - 1) * MAX_PAYLOAD
    end = start + MAX_PAYLOAD
    if end > len(chunk_bytes):
        end = len(chunk_bytes)
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


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function should receive data, unpack the standard header,
    and then use the packet type to route the packet to the appropriate
    handling logic (e.g., for WHOHAS, IHAVE, GET, DATA, ACK).

    :param sock: The :class:`simsocket.SimSocket` with a pending packet.
    :type sock: simsocket.SimSocket
    """
    global g_context, g_active_uploads, g_candidates, g_receiving, g_want_chunks, g_uploads, g_downloading, g_active_uploads

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
    # DATA: receiving side
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
        payload_len = len(data)

        if chunk_hex not in g_receiving:
            g_receiving[chunk_hex] = b""

        # 不再使用 0 长度 DATA 作为 EOF；若出现视为异常，直接丢弃
        if payload_len == 0:
            return

        if seq_num == expected:
            # 追加有效载荷并发送ACK
            current_size = len(g_receiving[chunk_hex])
            g_receiving[chunk_hex] += data
            new_size = len(g_receiving[chunk_hex])
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            sock.sendto(ack_pkt, from_addr)
            session["expected_seq"] += 1
            session["last_ack_time"] = time.time()

            # 检查是否达到预期文件大小（512KB）
            if new_size >= CHUNK_DATA_SIZE:
                _complete_download(chunk_hex, new_size, session_key, from_addr, sock, seq_num)

        else:
            # 乱序包，发送期望序列号-1的ACK
            ack_to_send = session["expected_seq"] - 1
            if ack_to_send < 0:
                ack_to_send = 0
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=ack_to_send)
            sock.sendto(ack_pkt, from_addr)

    # ACK: sender side (RDT handling)
    # ACK (sender side)
    # ACK: sender side (RDT handling)
    # ACK: sender side (RDT handling)
    # ACK: sender side (RDT handling)

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
            send_base = session.get("send_base", 1)
            next_seq_num = session.get("next_seq_num", 1)
            window_size = session.get("window_size", WINDOW_SIZE)

            print(f"DEBUG: ACK received: {ack_num}, last_acked: {last_acked}, total_segs: {total_segs}")

            if ack_num > last_acked:
                # new ACK progress
                session["last_acked"] = ack_num
                session["send_base"] = ack_num + 1
                session["last_sent_time"] = now

                # 如果已经确认到最后一个数据段，则认为上传完成，关闭会话
                if ack_num >= total_segs:
                    print(f"DEBUG: 🎉 All data segments ACKed for {chunk_hex}, upload completed!")
                    try:
                        del g_uploads[session_key]
                        if g_active_uploads > 0:
                            g_active_uploads -= 1
                    except KeyError:
                        pass
                    continue

                # 滑动窗口：发送新的数据段
                while next_seq_num < send_base + window_size and next_seq_num <= total_segs:
                    print(f"DEBUG: Sending next segment: {next_seq_num}")
                    _send_data_segment_for_session(session_key, sock, seq=next_seq_num)
                    session["next_seq_num"] = next_seq_num + 1
                    next_seq_num += 1
            elif ack_num == last_acked:
                # duplicate ACK, fast retransmit
                print(f"DEBUG: 🔄 DUPLICATE ACK {ack_num}, fast retransmit")
                next_seq = ack_num + 1
                _send_data_segment_for_session(session_key, sock, seq=next_seq)
    else:
        pass


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
    global g_context
    g_context = context

    addr: AddressType = (context.ip, context.port)
    sock = simsocket.SimSocket(context.identity, addr, verbose=context.verbose)

    last_force_check = 0

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.01)  # 减少到0.01 避免超时

            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                now = time.time()

                # 每2秒强制检查一次
                # if now - last_force_check > 2.0:
                #     last_force_check = now
                #     _force_complete_transfer()

                # 超时重传检查
                for session_key, session in list(g_uploads.items()):
                    last = session.get("last_sent_time", 0)
                    timeout = rdt_get_timeout(session)
                    if now - last > timeout:
                        last_seq = session.get("last_sent_seq", 1)
                        _send_data_segment_for_session(session_key, sock, seq=last_seq)

                # 下载会话超时检查（检测发送端崩溃）
                # 只在用户未指定超时时间时检查，否则使用用户指定的超时时间
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

def _complete_download(chunk_hex: str, total_bytes: int, session_key: Tuple, from_addr: Tuple,
                       sock: simsocket.SimSocket, seq_num: int):
    """Helper function to complete a download and write file."""
    global g_receiving, g_downloading, g_context, g_output_map, g_want_chunks

    # 验证数据完整性
    if total_bytes < CHUNK_DATA_SIZE:
        return

    # 清理下载会话
    if session_key in g_downloading:
        del g_downloading[session_key]

    # 检查这个 chunk 是否在接收缓冲区中且有数据
    if chunk_hex in g_receiving and len(g_receiving[chunk_hex]) >= CHUNK_DATA_SIZE:
        out_file = g_output_map.get(chunk_hex)
        if not out_file:
            return

        # 确保目录存在
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        try:
            download_data = {}
            completed_chunks = []

            for ch in list(g_receiving.keys()):
                if ch in g_receiving and len(g_receiving[ch]) >= CHUNK_DATA_SIZE:
                    download_data[ch] = g_receiving[ch]
                    completed_chunks.append(ch)

            # 写入文件
            with open(out_file, "wb") as wf:
                pickle.dump(download_data, wf)

            for ch in completed_chunks:
                g_context.has_chunks[ch] = g_receiving[ch]
                if ch in g_want_chunks:
                    g_want_chunks.remove(ch)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return

    if not g_want_chunks and not g_downloading:
        # 最终验证输出文件
        output_files = set(g_output_map.values())
        for out_file in output_files:
            if os.path.exists(out_file):
                file_size = os.path.getsize(out_file)
                try:
                    with open(out_file, "rb") as f:
                        content = pickle.load(f)
                    # 验证哈希
                    for ch, data in content.items():
                        sha1 = hashlib.sha1()
                        sha1.update(data)
                        actual_hash = sha1.hexdigest()
                except Exception as e:
                    print(f"DEBUG: Error reading output file: {e}")

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
