"""
Refactored peer implementation with better structure.
Maintains all functionality from peer.py but with improved organization.
"""
import sys
import os
import select
import struct
import socket
import hashlib
import argparse
import pickle
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import IntEnum
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

# Ensure project root in sys.path
_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_this_dir, ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

# ============================================================================
# Constants
# ============================================================================

BUF_SIZE: int = 1400
CHUNK_DATA_SIZE: int = 512 * 1024
MAX_PAYLOAD: int = 1024

MAX_CONCURRENT_DOWNLOADS_PER_CHUNK = 8
MAX_TOTAL_CONCURRENT_DOWNLOADS = 8

HEADER_FMT: str = "BBHII"
HEADER_LEN: int = struct.calcsize(HEADER_FMT)

MAX_WHOHAS_RETRIES: int = 3
WINDOW_SIZE = 32
DOWNLOAD_TIMEOUT_WITH_DATA: float = 3.0
DOWNLOAD_TIMEOUT_WITHOUT_DATA: float = 1.0

# RTT params
ALPHA = 0.15
BETA = 0.3


class PktType(IntEnum):
    WHOHAS = 0
    IHAVE = 1
    GET = 2
    DATA = 3
    ACK = 4
    DENIED = 5


# ============================================================================
# Step 1: Data Classes
# ============================================================================

@dataclass
class DownloadSession:
    """Represents a download session for a chunk from a specific peer."""
    chunk: str  # current downloading chunk
    expected_seq: int = 1
    total_segs: Optional[int] = None
    start_time: float = field(default_factory=time.time)
    last_ack_time: float = field(default_factory=time.time)
    waiting_chunks: List[str] = field(default_factory=list)
    timeout_count: int = 0


@dataclass
class UploadSession:
    """Represents an upload session for a chunk to a specific peer."""
    addr: Tuple[str, int]
    chunk_bytes: bytes
    total_segs: int

    # RDT / timing
    last_sent_seq: int = 0
    last_sent_time: float = 0.0
    timeout: float = 0.5
    sent_times: Dict[int, float] = field(default_factory=dict)

    # ACK / seq window
    last_acked: int = 0
    send_base: int = 1
    next_seq_num: int = 1
    last_ack_time: float = field(default_factory=time.time)  # Track when we last received an ACK

    # RTT estimation
    estimatedRTT: float = 0.5
    devRTT: float = 0.25
    timeoutInterval: float = 0.5

    # Congestion control (Tahoe-style)
    cc_state: str = "slow_start"  # "slow_start" or "congestion_avoidance"
    ssthresh: int = 64
    cwnd: float = 1.0
    dupACKcount: int = 0
    fast_retransmitted: set = field(default_factory=set)


# ============================================================================
# Step 2: PeerState Class
# ============================================================================

class PeerState:
    """Manages all peer state that was previously global variables."""

    def __init__(self, context: PeerContext):
        self.context = context

        # Downloads in progress: chunkhash -> byte buffer (collector)
        self.receiving: Dict[str, bytes] = {}

        # Downloads metadata: mapping from source addr (ip,port) -> session
        self.downloading: Dict[Tuple[Tuple[str, int], str], DownloadSession] = {}

        # Chunks we want (set by DOWNLOAD): list of chunk hex
        self.want_chunks: List[str] = []

        # Candidate map (chunk -> list of candidate addrs)
        self.candidates: Dict[str, List[Tuple[str, int]]] = {}

        # Upload sessions: chunkhash -> session
        self.uploads: Dict[Tuple[str, Tuple[str, int]], UploadSession] = {}

        # Active upload count
        self.active_uploads: int = 0

        # Output map: chunkhash -> output filename
        self.output_map: Dict[str, str] = {}

        # Retry count for WHOHAS
        self.whohas_retry_count: int = 0

        # Out-of-order packet buffer
        self.out_of_order_buffer: Dict[Tuple[Tuple[str, int], str], Dict[int, bytes]] = {}
        
        # Cwnd recording for congestion control visualization
        # Format: {session_key: [(timestamp, cwnd_value, event_type, ssthresh), ...]}
        # event_type: 'slow_start', 'congestion_avoidance', 'timeout', 'fast_retransmit', 'init'
        self.cwnd_history: Dict[Tuple[str, Tuple[str, int]], List[Tuple[float, float, str, int]]] = {}

        self.next_whohas_retry_time: Optional[float] = None

    def reset_download_state(self):
        """Reset download-related state for a new download."""
        self.whohas_retry_count = 0
        self.next_whohas_retry_time = None  # 重置调度时间
        self.want_chunks = []
        self.candidates = {}
        self.receiving = {}
        self.output_map = {}
        self.downloading = {}


# ============================================================================
# Step 3: Core Peer Class Framework
# ============================================================================

class Peer:
    """Main peer class that handles all peer operations."""

    def __init__(self, context: PeerContext):
        self.context = context
        self.state = PeerState(context)
        self.sock: Optional[simsocket.SimSocket] = None
        # self.cmd_queue: Queue[str] = Queue()
        # self.stdin_thread: Optional[threading.Thread] = None

    def _log_prefix(self) -> str:
        """Generate log prefix with peer identity and address."""
        return f"[Peer{self.context.identity}@{self.context.ip}:{self.context.port}]"

    def _log(self, message: str):
        """Print log message with peer prefix."""
        # if self.context.identity in [1,5]: # filter
        print(f"{self._log_prefix()} {message}")

    def _record_cwnd(self, session_key: Tuple[str, Tuple[str, int]], cwnd: float, event_type: str, ssthresh: int):
        """Record cwnd change for visualization."""
        if session_key not in self.state.cwnd_history:
            self.state.cwnd_history[session_key] = []
        self.state.cwnd_history[session_key].append((time.time(), cwnd, event_type, ssthresh))

    def run(self):
        """Main event loop."""
        addr: AddressType = (self.context.ip, self.context.port)
        self.sock = simsocket.SimSocket(self.context.identity, addr, verbose=self.context.verbose)

        # Start stdin reader thread
        # self.stdin_thread = threading.Thread(target=self._stdin_reader, daemon=True)
        # self.stdin_thread.start()

        try:
            while True:
                # 监听 socket 和 stdin（Unix 系统支持）
                rlist = [self.sock]
                try:
                    # 尝试将 stdin 加入监听（Windows 不支持，会抛异常）
                    rlist.append(sys.stdin)
                except:
                    pass

                ready, _, _ = select.select(rlist, [], [], 0.01)

                # 处理网络数据包
                if self.sock in ready:
                    self._process_inbound_udp()

                # 处理 stdin 输入（非阻塞）
                if sys.stdin in ready:
                    line = sys.stdin.readline()
                    if line:
                        self._process_user_input(line)

                # 处理超时和定时任务
                self._check_timeouts()

        except KeyboardInterrupt:
            pass
        finally:
            self._plot_cwnd()
            if self.sock:
                self.sock.close()

    # ========================================================================
    # Step 4: Simple Modules (CommandReader, etc.)
    # ========================================================================


    def _process_user_input(self, line: str):
        """Process a single line of user input."""
        try:
            command, chunk_file, output_file = line.strip().split()
            if command == "DOWNLOAD":
                self._process_download(chunk_file, output_file)
        except Exception:
            pass

    # ========================================================================
    # Step 5: Complex Modules (TransferManager, CongestionManager)
    # ========================================================================

    def _process_download(self, chunk_file: str, output_file: str):
        """Handle DOWNLOAD command."""
        self.state.reset_download_state()
        self._log(f"DEBUG: Starting download from {chunk_file} to {output_file}")

        try:
            with open(chunk_file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        _, ch = parts[0], parts[1]
                        self.state.want_chunks.append(ch)
                        self.state.receiving[ch] = b""
                        self.state.candidates[ch] = []
                        self.state.output_map[ch] = output_file
        except Exception as e:
            self._log(f"process_download: failed to read {chunk_file}: {e}")
            import traceback
            traceback.print_exc()
            return

        self._log(f"DEBUG: Want to download {len(self.state.want_chunks)} chunks: {self.state.want_chunks}")

        if not self.state.want_chunks:
            return

        # Send WHOHAS
        payload = b"".join(_hex_to_bytes(h) for h in self.state.want_chunks)
        pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

        for p in self.context.peers:
            try:
                pid = int(p[0])
                if pid == self.context.identity:
                    continue
                peer_ip = p[1]
                peer_port = int(p[2])
                self.sock.sendto(pkt, (peer_ip, peer_port))
            except Exception:
                continue

        # Schedule retry
        self.state.next_whohas_retry_time = time.time() + 3.0

    def _retry_whohas(self):
        """Retry sending WHOHAS packets."""

        if (not self.state.downloading and
                self.state.want_chunks and
                self.state.whohas_retry_count < MAX_WHOHAS_RETRIES):

            self.state.whohas_retry_count += 1
            payload = b"".join(_hex_to_bytes(h) for h in self.state.want_chunks)
            pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

            for p in self.context.peers:
                try:
                    pid = int(p[0])
                    if pid == self.context.identity:
                        continue
                    peer_ip = p[1]
                    peer_port = int(p[2])
                    self.sock.sendto(pkt, (peer_ip, peer_port))
                except Exception:
                    continue

            # 如果还需要继续重试，设置下次重试时间
            if self.state.whohas_retry_count < MAX_WHOHAS_RETRIES:
                self.state.next_whohas_retry_time = time.time() + 3.0
            else:
                self.state.next_whohas_retry_time = None

        else:
            # 不需要重试，清空调度时间
            self.state.next_whohas_retry_time = None


    def _process_inbound_udp(self):
        """Process a single inbound UDP packet."""
        pkt, from_addr = self.sock.recvfrom(BUF_SIZE)
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

        # Route to appropriate handler
        if pkg_type == PktType.WHOHAS:
            self._handle_whohas(from_addr, data)
        elif pkg_type == PktType.IHAVE:
            self._handle_ihave(from_addr, data)
        elif pkg_type == PktType.DENIED:
            self._log(f"DEBUG: Received DENIED packet from {from_addr}")
        elif pkg_type == PktType.GET:
            self._handle_get(from_addr, data)
        elif pkg_type == PktType.DATA:
            self._handle_data(from_addr, seq_h, data)
        elif pkg_type == PktType.ACK:
            self._handle_ack(from_addr, ack_h)

    def _handle_whohas(self, from_addr: Tuple[str, int], data: bytes):
        """Handle WHOHAS packet."""
        have_hashes = []
        for i in range(0, len(data), 20):
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            if hhex in self.context.has_chunks:
                have_hashes.append(hbytes)

        max_conn = getattr(self.context, "max_conn", None)
        if max_conn is None:
            max_conn = getattr(getattr(self.context, "args", None), "max_conn", None)
        can_upload = (self.state.active_uploads < max_conn) if isinstance(max_conn, int) else True

        if have_hashes:
            if can_upload:
                # 有chunks且可以上传：发送IHAVE
                payload = b"".join(have_hashes)
                pkt_ihave = _pack_header(PktType.IHAVE, HEADER_LEN + len(payload), seq=0, ack=0) + payload
                self.sock.sendto(pkt_ihave, from_addr)
                self._log(f"DEBUG: Sent IHAVE with {len(have_hashes)} chunks to {from_addr}")
            else:
                # 有chunks但不能上传：发送DENIED
                pkt_denied = _pack_header(PktType.DENIED, HEADER_LEN, seq=0, ack=0)
                self.sock.sendto(pkt_denied, from_addr)
                self._log(f"DEBUG: Sent DENIED to {from_addr} (max_conn reached)")
        else:
            # 没有请求的chunks：不回复（但不是DENIED）
            self._log(f"DEBUG: No requested chunks, ignoring WHOHAS from {from_addr}")

    def _handle_ihave(self, from_addr: Tuple[str, int], data: bytes):
        """Handle IHAVE packet."""
        peer_has_chunks = []
        for i in range(0, len(data), 20):
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            peer_has_chunks.append(hhex)

        addr = (from_addr[0], from_addr[1])

        for hhex in peer_has_chunks:
            if hhex in self.state.want_chunks:
                # Check if already downloading this chunk from any peer
                if any(sess.chunk == hhex for sess in self.state.downloading.values()):
                    if hhex not in self.state.candidates:
                        self.state.candidates[hhex] = []
                    if addr not in self.state.candidates[hhex]:
                        self.state.candidates[hhex].append(addr)
                    continue

                # Check if already have a download session from this addr (for any chunk)
                existing_session = None
                existing_key = None
                for key, sess in self.state.downloading.items():
                    if key[0] == addr:  # key is (addr, chunk_hex), check if addr matches
                        existing_session = sess
                        existing_key = key
                        break

                if existing_session is not None:
                    # Add this chunk to waiting_chunks of existing session
                    if hhex not in existing_session.waiting_chunks:
                        existing_session.waiting_chunks.append(hhex)
                        self._log(
                            f"DEBUG: Added chunk {hhex} to waiting_chunks of existing session from {addr} (current chunk: {existing_session.chunk})")

                    # Add to candidates
                    self.state.candidates.setdefault(hhex, [])
                    if addr not in self.state.candidates[hhex]:
                        self.state.candidates[hhex].append(addr)
                    continue

                # Check if this specific (addr, hhex) session already exists
                download_key = (addr, hhex)
                if download_key in self.state.downloading:
                    continue

                # Check total concurrent downloads limit
                if len(self.state.downloading) >= MAX_TOTAL_CONCURRENT_DOWNLOADS:
                    self.state.candidates.setdefault(hhex, [])
                    if addr not in self.state.candidates[hhex]:
                        self.state.candidates[hhex].append(addr)
                    continue

                # Send GET and create download session
                payload = _hex_to_bytes(hhex)
                pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(payload), seq=0, ack=0) + payload
                self.sock.sendto(pkt_get, from_addr)

                self.state.downloading[download_key] = DownloadSession(
                    chunk=hhex,
                    expected_seq=1,
                    total_segs=None,
                    start_time=time.time(),
                    last_ack_time=time.time(),
                    waiting_chunks=[]
                )

                if hhex not in self.state.receiving:
                    self.state.receiving[hhex] = b""

                self.state.candidates.setdefault(hhex, [])
                if addr not in self.state.candidates[hhex]:
                    self.state.candidates[hhex].append(addr)

    def _handle_get(self, from_addr: Tuple[str, int], data: bytes):
        """Handle GET packet."""
        if len(data) < 20:
            return
        requested_hex = _bytes_to_hex(data[:20])
        if requested_hex in self.context.has_chunks:
            addr = (from_addr[0], from_addr[1])

            # Check if upload session already exists for this (chunk, addr)
            upload_key = (requested_hex, addr)
            if upload_key in self.state.uploads:
                existing_session = self.state.uploads[upload_key]
                now = time.time()

                # 检查会话是否有效
                time_since_last_ack = now - existing_session.last_ack_time
                time_since_last_send = now - existing_session.last_sent_time

                # 判断会话是否真的活跃
                is_slow = False
                if existing_session.total_segs is not None:
                    progress_ratio = existing_session.send_base / existing_session.total_segs
                    if progress_ratio < 0.1 and time_since_last_ack > DOWNLOAD_TIMEOUT_WITHOUT_DATA:
                        # 刚开始但很长时间没有ACK
                        is_slow = True
                    elif progress_ratio > 0.1 and time_since_last_ack > DOWNLOAD_TIMEOUT_WITH_DATA:
                        # 有一定进度但长时间没有ACK
                        is_slow = True

                if is_slow:
                    # 会话太慢 重置
                    self._log(
                        f"DEBUG: GET for {requested_hex} from {addr}: upload session exists but too slow (progress={existing_session.send_base}/{existing_session.total_segs}, last_ack={time_since_last_ack:.1f}s), resetting")
                    del self.state.uploads[upload_key]
                    self.state.active_uploads = max(0, self.state.active_uploads - 1)

                else:
                    self._log(
                        f"DEBUG: GET for {requested_hex} from {addr}: upload session exists and is active, ignoring duplicate GET")
                    return

            max_conn = getattr(self.context, "max_conn", None)
            if max_conn is None:
                max_conn = getattr(getattr(self.context, "args", None), "max_conn", None)
            if isinstance(max_conn, int) and self.state.active_uploads >= max_conn:
                pkt_denied = _pack_header(PktType.DENIED, HEADER_LEN, seq=0, ack=0)
                self.sock.sendto(pkt_denied, from_addr)
            else:
                self._start_upload_session(requested_hex, addr)

    def _handle_data(self, from_addr: Tuple[str, int], seq_num: int, data: bytes):
        """Handle DATA packet."""
        addr_key = (from_addr[0], from_addr[1])

        # Find corresponding download session
        session = None
        session_key = None
        for key, sess in self.state.downloading.items():
            if key[0] == addr_key:
                session = sess
                session_key = key
                break

        if not session:
            return

        chunk_hex = session.chunk
        expected = session.expected_seq
        payload = data

        if len(payload) == 0:
            self._log(f"DEBUG: ⚠️ Ignoring empty DATA packet seq={seq_num}")
            return

        # Initialize total_segs
        if session.total_segs is None:
            session.total_segs = (CHUNK_DATA_SIZE + MAX_PAYLOAD - 1) // MAX_PAYLOAD
            self._log(f"DEBUG:  Initialized total_segs={session.total_segs} for chunk {chunk_hex}")

        if chunk_hex not in self.state.receiving:
            self.state.receiving[chunk_hex] = b""

        if session_key not in self.state.out_of_order_buffer:
            self.state.out_of_order_buffer[session_key] = {}

        if seq_num == expected:
            # Correct sequence number
            self.state.receiving[chunk_hex] += payload
            session.last_ack_time = time.time()

            current_len = len(self.state.receiving[chunk_hex])
            expected_len = CHUNK_DATA_SIZE
            progress = min(100, (current_len * 100) / expected_len)
            self._log(f"DEBUG: Received seq={seq_num}, progress: {progress:.1f}% ({current_len}/{expected_len} bytes)")

            # Send ACK
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            self.sock.sendto(ack_pkt, from_addr)

            # Update expected sequence
            session.expected_seq = expected + 1

            # Check buffer for subsequent packets
            buffer = self.state.out_of_order_buffer[session_key]
            while (expected + 1) in buffer:
                next_seq = expected + 1
                next_payload = buffer.pop(next_seq)

                self.state.receiving[chunk_hex] += next_payload
                session.expected_seq = next_seq + 1
                session.last_ack_time = time.time()

                ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=next_seq)
                self.sock.sendto(ack_pkt, from_addr)

                expected = next_seq
                self._log(f"DEBUG: ✨ Delivered buffered packet seq={next_seq}, new expected={expected + 1}")

            # Check if complete (after processing buffered packets)
            current_expected = session.expected_seq
            if session.total_segs is not None and (current_expected - 1) == session.total_segs:
                self._log(f"DEBUG: 📦 All segments received for {chunk_hex}")
                self._complete_download(chunk_hex, len(self.state.receiving[chunk_hex]),
                                        session_key, from_addr, current_expected - 1)

        elif seq_num > expected:
            # Out-of-order packet: buffer it
            buffer = self.state.out_of_order_buffer[session_key]
            if seq_num not in buffer:
                buffer[seq_num] = payload
                self._log(
                    f"DEBUG: 📦 Buffered out-of-order packet seq={seq_num}, expected={expected}, buffer_size={len(buffer)}")

            # Update last_ack_time even for out-of-order packets (indicates peer is still alive)
            session.last_ack_time = time.time()


            # Send cumulative ACK (但不能发送 ACK=0，因为 seq 从 1 开始)
            if expected > 1:
                ack_to_send = expected - 1
                ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=ack_to_send)
                self.sock.sendto(ack_pkt, from_addr)
                self._log(f"DEBUG:  Sent cumulative ACK={ack_to_send} for out-of-order seq={seq_num}")
            else:
                # 如果 expected=1（还没收到任何数据），不发送 ACK（或者可以选择不发送）
                # 因为没有可以确认的数据
                self._log(f"DEBUG:  Ignoring out-of-order seq={seq_num}, expected={expected}, no data received yet")
        else:
            ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=seq_num)
            self.sock.sendto(ack_pkt, from_addr)
            self._log(f"DEBUG: 🔁 Duplicate packet seq={seq_num}, expected={expected}")

    def _handle_ack(self, from_addr: Tuple[str, int], ack_num: int):
        """Handle ACK packet."""
        now = time.time()

        # Find sessions for this from_addr
        for session_key, session in list(self.state.uploads.items()):
            chunk_hex, sess_addr = session_key
            if sess_addr != (from_addr[0], from_addr[1]):
                continue

            total_segs = session.total_segs
            last_acked = session.last_acked

            self._log(f"DEBUG: ACK received: {ack_num}, last_acked: {last_acked}, total_segs: {total_segs}, "
                      f"cwnd={session.cwnd}, ssthresh={session.ssthresh}, cc_state={session.cc_state}")

            if ack_num > last_acked:
                # New ACK
                self._on_new_ack(session_key, ack_num, now)
            elif ack_num == session.last_acked:
                # Duplicate ACK
                self._on_duplicate_ack(session_key, ack_num)

    def _check_timeouts(self):
        """Check for timeout conditions."""
        now = time.time()

        # 新增：检查 WHOHAS 重试调度
        if (self.state.next_whohas_retry_time is not None and
                now >= self.state.next_whohas_retry_time):
            self.state.next_whohas_retry_time = None  # 先清空，避免重复触发
            self._retry_whohas()

        # Check upload timeouts
        for session_key, session in list(self.state.uploads.items()):
            timeout = self._rdt_get_timeout(session)
            send_base = session.send_base

            if send_base in session.sent_times:
                last = session.sent_times[send_base]
                if now - last > timeout:
                    # Tahoe-style reaction on timeout
                    cwnd = session.cwnd
                    ssthresh = max(int(cwnd / 2), 2)
                    session.ssthresh = ssthresh
                    session.cwnd = 1.0
                    session.cc_state = "slow_start"
                    session.dupACKcount = 0
                    self._record_cwnd(session_key, session.cwnd, 'timeout', session.ssthresh)
                    self._log(f"DEBUG: ⏲️ Timeout: retransmit seq={send_base}")
                    self._send_data_segment_for_session(session_key, send_base)

            next_seq_num = session.next_seq_num

            # If we've already sent packets beyond send_base, those packets might have arrived
            # (just ACK delayed). Don't retransmit send_base immediately in this case.
            # Only retransmit if we haven't sent beyond send_base (indicating real loss)
            if next_seq_num <= send_base:
                last = session.sent_times.get(send_base, session.last_sent_time)
                if now - last > timeout:
                    # Tahoe-style reaction on timeout
                    cwnd = session.cwnd
                    ssthresh = max(int(cwnd / 2), 2)
                    session.ssthresh = ssthresh
                    session.cwnd = 1.0
                    session.cc_state = "slow_start"
                    session.dupACKcount = 0
                    self._record_cwnd(session_key, session.cwnd, 'timeout', session.ssthresh)
                    self._log(
                        f"DEBUG: ⏲️ Timeout: set ssthresh={ssthresh}, cwnd=1, cc_state=slow_start; retransmit seq={send_base}")
                    seq_to_retransmit = send_base
                    self._send_data_segment_for_session(session_key, seq_to_retransmit)

        # Check download timeouts
        # Always check download timeouts regardless of context.timeout setting
        # (context.timeout is for upload RTT estimation, not download timeout detection)
        for session_key, session in list(self.state.downloading.items()):
            last_recv = session.last_ack_time
            expected_seq = session.expected_seq
            total_segs = session.total_segs

            # 没有收到任何数据 使用较短超时
            if expected_seq == 1:
                if now - last_recv > DOWNLOAD_TIMEOUT_WITHOUT_DATA:
                    self._handle_download_timeout(session_key)
            else:
                if now - last_recv > DOWNLOAD_TIMEOUT_WITH_DATA:
                    self._log(f"DEBUG: Download progress: expected_seq={expected_seq}, total_segs={total_segs}")
                    self._handle_download_timeout(session_key)
                else:
                    if now - last_recv > 5.0 and total_segs is not None:
                        ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, seq=0, ack=expected_seq - 1)
                        addr = session_key[0]  # (ip, port)
                        self.sock.sendto(ack_pkt, addr)
                        self._log(f"DEBUG: 🔍 Sending probe ACK {expected_seq - 1} to {addr}")

    # ========================================================================
    # Upload Session Management
    # ========================================================================

    def _start_upload_session(self, chunk_hex: str, addr: Tuple[str, int]):
        """Initialize an upload session and send first DATA segment."""
        chunk_bytes = self.context.has_chunks[chunk_hex]
        total_segs = (len(chunk_bytes) + MAX_PAYLOAD - 1) // MAX_PAYLOAD

        preset_timeout = getattr(self.context, "timeout", 0) or 0
        if preset_timeout:
            initial_timeout = float(preset_timeout)
        else:
            initial_timeout = 0.5

        session = UploadSession(
            addr=addr,
            chunk_bytes=chunk_bytes,
            total_segs=total_segs,
            timeout=initial_timeout,
            estimatedRTT=initial_timeout,
            devRTT=initial_timeout / 2.0,
            timeoutInterval=initial_timeout,
            cc_state="slow_start",
            ssthresh=64,
            cwnd=1.0,
            dupACKcount=0
        )

        key = (chunk_hex, addr)
        self.state.uploads[key] = session
        self.state.active_uploads += 1

        # Record initial cwnd
        self._record_cwnd(key, session.cwnd, 'init', session.ssthresh)

        # Send up to cwnd initial segments
        self._send_within_cwnd(key)

        self._log(f"DEBUG: Upload session started for {chunk_hex}, cwnd={session.cwnd}, "
                  f"ssthresh={session.ssthresh}, total_segs={total_segs}")

    def _send_data_segment_for_session(self, session_key: Tuple[str, Tuple[str, int]], seq: int = None):
        """(Re)send specific segment for an upload session."""
        session = self.state.uploads.get(session_key)
        if not session:
            return

        addr = session.addr
        chunk_bytes = session.chunk_bytes
        total_segs = session.total_segs

        if seq is None:
            seq = session.last_acked + 1

        if seq > total_segs or seq < 1:
            return

        if seq not in session.sent_times:
            self._log(f"DEBUG: Sending segment {seq}/{total_segs} to {addr}")
        else:
            self._log(f"DEBUG: Retransmitting segment {seq}/{total_segs} to {addr}")

        # Send data segment
        start = (seq - 1) * MAX_PAYLOAD
        end = min(start + MAX_PAYLOAD, len(chunk_bytes))
        part = chunk_bytes[start:end]

        if len(part) == 0:
            self._log(f"DEBUG: ERROR: Empty segment at seq {seq}")
            return

        pkt = _pack_header(PktType.DATA, HEADER_LEN + len(part), seq=seq, ack=0) + part
        self.sock.sendto(pkt, addr)

        # Update session state
        now = time.time()
        session.last_sent_time = now
        session.last_sent_seq = seq
        session.sent_times[seq] = now

        if not session.timeoutInterval:
            session.timeoutInterval = session.timeout

    def _send_within_cwnd(self, session_key: Tuple[str, Tuple[str, int]]):
        """Send new segments while inflight < cwnd."""
        session = self.state.uploads.get(session_key)
        if not session:
            return

        total_segs = session.total_segs
        send_base = session.send_base
        next_seq_num = session.next_seq_num
        cwnd = session.cwnd

        effective_cwnd = int(cwnd)
        # max_inflight = min(effective_cwnd, WINDOW_SIZE)
        max_inflight = effective_cwnd

        while (next_seq_num - send_base) < max_inflight and next_seq_num <= total_segs:
            self._send_data_segment_for_session(session_key, next_seq_num)
            session.next_seq_num = next_seq_num + 1
            next_seq_num += 1

    # ========================================================================
    # Congestion Control (Tahoe)
    # ========================================================================

    def _on_new_ack(self, session_key: Tuple[str, Tuple[str, int]], ack_num: int, now: float):
        """Handle new ACK (Tahoe congestion control core)."""
        session = self.state.uploads.get(session_key)
        if not session:
            return

        total_segs = session.total_segs
        last_acked = session.last_acked

        # RTT sampling
        if ack_num in session.sent_times:
            sample_rtt = max(0.0, now - session.sent_times[ack_num])
            self._rdt_update_rtt(session, sample_rtt)

        # Update ACK window
        session.last_acked = ack_num
        old_send_base = session.send_base
        session.send_base = ack_num + 1
        session.last_ack_time = now  # Update last ACK time

        # Reset dupACKcount on new ACK
        session.dupACKcount = 0
        session.fast_retransmitted.discard(ack_num + 1)

        # Check if new send_base has already timed out (due to delayed ACK)
        # However, if next_seq_num > send_base, it means we've already sent packets beyond send_base,
        # so those packets might have already arrived (just ACK delayed). Don't retransmit immediately.
        new_send_base = session.send_base
        next_seq_num = session.next_seq_num

        # Only check timeout if we haven't sent packets beyond send_base
        # If next_seq_num > send_base, let normal timeout mechanism handle it
        if new_send_base <= session.total_segs and next_seq_num <= new_send_base:
            timeout = self._rdt_get_timeout(session)
            new_send_base_time = session.sent_times.get(new_send_base, None)
            if new_send_base_time is not None:
                elapsed = now - new_send_base_time
                if elapsed > timeout:
                    # The new send_base packet has already timed out, and we haven't sent beyond it
                    # This indicates the packet is likely lost, retransmit immediately
                    self._log(
                        f"DEBUG: New send_base {new_send_base} already timed out (elapsed={elapsed:.3f}s > timeout={timeout:.3f}s), retransmitting")
                    # Tahoe-style reaction
                    cwnd = session.cwnd
                    ssthresh = max(int(cwnd / 2), 2)
                    session.ssthresh = ssthresh
                    session.cwnd = 1.0
                    session.cc_state = "slow_start"
                    session.dupACKcount = 0
                    self._record_cwnd(session_key, session.cwnd, 'timeout', session.ssthresh)
                    self._send_data_segment_for_session(session_key, new_send_base)
                    # Don't continue with normal ACK processing (cwnd growth) after timeout
                    return

        cc_state = session.cc_state
        cwnd = session.cwnd
        ssthresh = session.ssthresh

        # Tahoe congestion control: state transition and growth
        if cc_state == "slow_start":
            # Slow start: each new ACK, cwnd += 1 (exponential growth)
            cwnd += 1
            session.cwnd = cwnd
            self._record_cwnd(session_key, session.cwnd, 'slow_start', ssthresh)
            self._log(f"DEBUG: Slow Start: cwnd={cwnd}, ssthresh={ssthresh}")

            # Check transition to congestion avoidance
            if cwnd >= ssthresh:
                session.cc_state = "congestion_avoidance"
                self._record_cwnd(session_key, session.cwnd, 'congestion_avoidance', ssthresh)
                self._log(f"DEBUG: ⚡ Transition to Congestion Avoidance (cwnd={cwnd} >= ssthresh={ssthresh})")
        else:
            # Congestion avoidance: each new ACK, cwnd += 1/cwnd (linear growth)
            increment = 1.0 / max(cwnd, 1)
            cwnd += increment
            session.cwnd = cwnd
            self._record_cwnd(session_key, session.cwnd, 'congestion_avoidance', ssthresh)
            self._log(f"DEBUG: Congestion Avoidance: cwnd={cwnd:.2f}")

        # Completion check
        if ack_num >= total_segs:
            self._log(f"DEBUG: Upload complete for {session_key[0]}")
            try:
                del self.state.uploads[session_key]
                self.state.active_uploads = max(0, self.state.active_uploads - 1)
            except KeyError:
                pass
            return

        # Send new packets allowed by window
        self._send_within_cwnd(session_key)

    def _on_duplicate_ack(self, session_key: Tuple[str, Tuple[str, int]], ack_num: int):
        """Handle duplicate ACK. Fast retransmit when dupACKcount==3."""
        session = self.state.uploads.get(session_key)
        if not session:
            return

        dup = session.dupACKcount + 1
        session.dupACKcount = dup
        session.last_ack_time = time.time()  # Update last ACK time even for duplicate ACKs
        self._log(f"DEBUG: Duplicate ACK {ack_num}, dupACKcount={dup}")

        # Fast retransmit: trigger only when dupACKcount==3, and only once per seq
        next_seq = ack_num + 1
        if dup == 3 and next_seq not in session.fast_retransmitted:
            session.fast_retransmitted.add(next_seq)
            self._log(f"DEBUG: Fast Retransmit seq={next_seq}")

            # Tahoe reaction: ssthresh=max(cwnd/2, 2), cwnd=1, enter slow start
            cwnd = session.cwnd
            ssthresh = max(int(cwnd / 2), 2)
            session.ssthresh = ssthresh
            session.cwnd = 1.0
            session.cc_state = "slow_start"
            self._record_cwnd(session_key, session.cwnd, 'fast_retransmit', session.ssthresh)
            # Note: don't reset dupACKcount (prevent duplicate retransmission)

            # Retransmit
            self._send_data_segment_for_session(session_key, seq=next_seq)
            session.send_base = ack_num + 1
            session.next_seq_num = max(session.next_seq_num, ack_num + 2)
            self._log(f"DEBUG:  Tahoe reaction: ssthresh={ssthresh}, cwnd=1")

    # ========================================================================
    # Cwnd Visualization
    # ========================================================================

    def _plot_cwnd(self):
        """Plot cwnd changes over time for all sessions."""
        if not self.state.cwnd_history:
            return
        
        # Create output directory if it doesn't exist
        log_dir = os.path.join(_project_root, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Plot each session separately
        for session_key, history in self.state.cwnd_history.items():
            if not history:
                continue
            
            chunk_hex, addr = session_key
            peer_id = self.context.identity
            addr_str = f"{addr[0]}:{addr[1]}"
            
            # Extract data
            timestamps = [t[0] for t in history]
            cwnd_values = [t[1] for t in history]
            event_types = [t[2] for t in history]
            ssthresh_values = [t[3] for t in history]
            
            # Normalize timestamps to start from 0
            if timestamps:
                start_time = timestamps[0]
                timestamps = [t - start_time for t in timestamps]
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Plot cwnd
            ax.plot(timestamps, cwnd_values, 'b-', linewidth=2, label='cwnd', marker='o', markersize=4)
            
            # Plot ssthresh as horizontal lines
            unique_ssthresh = []
            unique_ssthresh_times = []
            prev_ssthresh = None
            for i, (t, ssthresh) in enumerate(zip(timestamps, ssthresh_values)):
                if ssthresh != prev_ssthresh:
                    unique_ssthresh.append(ssthresh)
                    unique_ssthresh_times.append(t)
                    prev_ssthresh = ssthresh
                elif i == len(timestamps) - 1:
                    # Draw line to the end
                    if unique_ssthresh:
                        ax.hlines(unique_ssthresh[-1], unique_ssthresh_times[-1], t, 
                                 colors='r', linestyles='--', linewidth=1.5, alpha=0.7)
            
            # Draw ssthresh lines
            for i in range(len(unique_ssthresh) - 1):
                ax.hlines(unique_ssthresh[i], unique_ssthresh_times[i], unique_ssthresh_times[i+1],
                         colors='r', linestyles='--', linewidth=1.5, alpha=0.7, label='ssthresh' if i == 0 else '')
            if unique_ssthresh and len(timestamps) > 0:
                ax.hlines(unique_ssthresh[-1], unique_ssthresh_times[-1], timestamps[-1],
                         colors='r', linestyles='--', linewidth=1.5, alpha=0.7, label='ssthresh' if len(unique_ssthresh) == 1 else '')
            
            # Annotate events
            event_colors = {
                'init': 'green',
                'slow_start': 'blue',
                'congestion_avoidance': 'orange',
                'timeout': 'red',
                'fast_retransmit': 'purple'
            }
            
            prev_event = None
            for i, (t, cwnd, event, _) in enumerate(zip(timestamps, cwnd_values, event_types, ssthresh_values)):
                if event != prev_event and event in event_colors:
                    ax.scatter(t, cwnd, color=event_colors[event], s=100, zorder=5, 
                             label=event.replace('_', ' ').title() if event != prev_event else '')
                    # Add text annotation for major events
                    if event in ['timeout', 'fast_retransmit', 'congestion_avoidance']:
                        ax.annotate(event.replace('_', ' ').title(), 
                                  xy=(t, cwnd), xytext=(5, 5), textcoords='offset points',
                                  fontsize=8, alpha=0.7)
                prev_event = event
            
            # Set labels and title
            ax.set_xlabel('Time (seconds)', fontsize=12)
            ax.set_ylabel('Congestion Window (cwnd)', fontsize=12)
            ax.set_title(f'Peer{peer_id} - Cwnd vs Time (Chunk: {chunk_hex[:8]}..., Addr: {addr_str})', fontsize=14)
            ax.grid(True, alpha=0.3)
            ax.legend(loc='upper left', fontsize=9)
            
            # Save figure
            safe_addr = addr_str.replace(':', '_')
            safe_chunk = chunk_hex[:8]
            filename = f"cwnd_peer{peer_id}_{safe_chunk}_{safe_addr}.png"
            filepath = os.path.join(log_dir, filename)
            plt.tight_layout()
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            
            self._log(f"DEBUG: Saved cwnd plot to {filepath}")

    # ========================================================================
    # Cwnd Visualization
    # ========================================================================

    def _plot_cwnd(self):
        """Plot cwnd changes over time for all sessions."""
        if not self.state.cwnd_history:
            return
        
        # Create output directory if it doesn't exist
        log_dir = os.path.join(_project_root, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Plot each session separately
        for session_key, history in self.state.cwnd_history.items():
            if not history:
                continue
            
            chunk_hex, addr = session_key
            peer_id = self.context.identity
            addr_str = f"{addr[0]}:{addr[1]}"
            
            # Extract data
            timestamps = [t[0] for t in history]
            cwnd_values = [t[1] for t in history]
            event_types = [t[2] for t in history]
            ssthresh_values = [t[3] for t in history]
            
            # Normalize timestamps to start from 0
            if timestamps:
                start_time = timestamps[0]
                timestamps = [t - start_time for t in timestamps]
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Plot cwnd
            ax.plot(timestamps, cwnd_values, 'b-', linewidth=2, label='cwnd', marker='o', markersize=4)
            
            # Plot ssthresh as horizontal lines
            unique_ssthresh = []
            unique_ssthresh_times = []
            prev_ssthresh = None
            for i, (t, ssthresh) in enumerate(zip(timestamps, ssthresh_values)):
                if ssthresh != prev_ssthresh:
                    unique_ssthresh.append(ssthresh)
                    unique_ssthresh_times.append(t)
                    prev_ssthresh = ssthresh
            
            # Draw ssthresh lines
            ssthresh_labeled = False
            for i in range(len(unique_ssthresh)):
                label = 'ssthresh' if not ssthresh_labeled else ''
                if i < len(unique_ssthresh) - 1:
                    ax.hlines(unique_ssthresh[i], unique_ssthresh_times[i], unique_ssthresh_times[i+1],
                             colors='r', linestyles='--', linewidth=1.5, alpha=0.7, label=label)
                else:
                    ax.hlines(unique_ssthresh[i], unique_ssthresh_times[i], timestamps[-1] if timestamps else unique_ssthresh_times[i],
                             colors='r', linestyles='--', linewidth=1.5, alpha=0.7, label=label)
                if not ssthresh_labeled:
                    ssthresh_labeled = True
            
            # Annotate events - mark major events (timeout, fast_retransmit)
            # Track which event types we've already added to legend
            timeout_labeled = False
            fast_retransmit_labeled = False
            
            for i, (t, cwnd, event, _) in enumerate(zip(timestamps, cwnd_values, event_types, ssthresh_values)):
                if event == 'timeout':
                    # Only add label for the first timeout event
                    label = 'Timeout' if not timeout_labeled else ''
                    ax.scatter(t, cwnd, color='red', s=150, zorder=5, marker='x', label=label)
                    if not timeout_labeled:
                        timeout_labeled = True
                    ax.annotate('Timeout', xy=(t, cwnd), xytext=(10, 10), textcoords='offset points',
                              fontsize=9, alpha=0.8, fontweight='bold', color='red')
                elif event == 'fast_retransmit':
                    # Only add label for the first fast_retransmit event
                    label = 'Fast Retransmit' if not fast_retransmit_labeled else ''
                    ax.scatter(t, cwnd, color='purple', s=150, zorder=5, marker='s', label=label)
                    if not fast_retransmit_labeled:
                        fast_retransmit_labeled = True
                    ax.annotate('Fast Retransmit', xy=(t, cwnd), xytext=(10, 10), textcoords='offset points',
                              fontsize=9, alpha=0.8, fontweight='bold', color='purple')
            
            # Mark congestion avoidance transition
            prev_event = None
            for i, (t, cwnd, event, _) in enumerate(zip(timestamps, cwnd_values, event_types, ssthresh_values)):
                if event == 'congestion_avoidance' and prev_event == 'slow_start':
                    ax.axvline(x=t, color='green', linestyle='--', alpha=0.6, linewidth=2)
                    ax.text(t, ax.get_ylim()[1] * 0.98, 'CA Start', rotation=90, 
                           verticalalignment='top', fontsize=9, alpha=0.8, color='green', fontweight='bold')
                prev_event = event
            
            # Set labels and title
            ax.set_xlabel('Time (seconds)', fontsize=12)
            ax.set_ylabel('Congestion Window (cwnd)', fontsize=12)
            ax.set_title(f'Peer{peer_id} - Cwnd vs Time (Chunk: {chunk_hex[:8]}..., Addr: {addr_str})', fontsize=14)
            ax.grid(True, alpha=0.3)
            ax.legend(loc='upper left', fontsize=9)
            
            # Save figure
            safe_addr = addr_str.replace(':', '_')
            safe_chunk = chunk_hex[:8]
            filename = f"cwnd_peer{peer_id}_{safe_chunk}_{safe_addr}.png"
            filepath = os.path.join(log_dir, filename)
            plt.tight_layout()
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            
            self._log(f"DEBUG: Saved cwnd plot to {filepath}")

    # ========================================================================
    # RTT Management
    # ========================================================================

    def _rdt_update_rtt(self, session: UploadSession, sampleRTT: float):
        """Update EstimatedRTT / DevRTT / TimeoutInterval per given formulas."""
        prevEst = session.estimatedRTT
        prevDev = session.devRTT

        if prevEst is None or prevEst == 0:
            # First sample: set estimates directly
            est = sampleRTT
            dev = sampleRTT / 2.0
        else:
            est = (1 - ALPHA) * prevEst + ALPHA * sampleRTT
            prevDev = prevDev if prevDev is not None else sampleRTT / 2.0
            dev = (1 - BETA) * prevDev + BETA * abs(sampleRTT - est)

        session.estimatedRTT = est
        session.devRTT = dev
        session.timeoutInterval = max(0.5, est + 4 * dev)

    def _rdt_get_timeout(self, session: UploadSession) -> float:
        """Return the effective timeout for the session."""
        if getattr(self.context, "timeout", 0):
            return float(session.timeout)
        return max(0.5, float(session.timeoutInterval if session.timeoutInterval else session.timeout or 0.5))

    # ========================================================================
    # Download Management
    # ========================================================================

    def _handle_download_timeout(self, session_key: Tuple[Tuple[str, int], str]):
        """
        下载端检测到某个发送端长时间无响应（可能崩溃）时：
        1. 清空当前 chunk 的已接收数据；
        2. 将该发送端从候选列表中移除；
        3. 若还有其它候选 peer，则向其重新发送 GET；
        4. 若没有候选，则重新对该 chunk 发送 WHOHAS。
        """
        session = self.state.downloading.pop(session_key, None)
        if not session:
            return

        addr, chunk_hex = session_key
        session.timeout_count += 1

        # 如果超时次数太多 放弃这个peer
        if session.timeout_count >= 3:
            self._log(f"DEBUG: Abandoning {addr} for chunk {chunk_hex} after {session.timeout_count} timeouts")
            if chunk_hex in self.state.receiving:
                self.state.receiving[chunk_hex] = b""
            if session_key in self.state.out_of_order_buffer:
                del self.state.out_of_order_buffer[session_key]

            cand_list = self.state.candidates.get(chunk_hex, [])
            cand_list = [c for c in cand_list if c != addr]
            self.state.candidates[chunk_hex] = cand_list
            return

        self._log(f"DEBUG: Download timeout #{session.timeout_count} for chunk {chunk_hex} from {addr}")

        # 1. 清空该 chunk 已接收的数据
        if chunk_hex in self.state.receiving:
            self.state.receiving[chunk_hex] = b""

        # 清理乱序缓冲区
        if session_key in self.state.out_of_order_buffer:
            del self.state.out_of_order_buffer[session_key]

        # 2. 从候选列表中移除当前发送端
        cand_list = self.state.candidates.get(chunk_hex, [])
        cand_list = [c for c in cand_list if c != addr]
        self.state.candidates[chunk_hex] = cand_list

        # TODO: waiting_chunks 处理 再次发送WHOHAS找谁有该chunk

        # 3. 若还有其它候选 peer，直接向其中一个发送 GET 并创建新的下载会话
        if cand_list:
            # Check if already downloading this chunk from another peer
            if any(sess.chunk == chunk_hex for sess in self.state.downloading.values()):
                self._log(f"DEBUG: Already downloading chunk {chunk_hex} from another peer, skipping retry")
                return

            new_addr = cand_list[0]
            try:
                payload = _hex_to_bytes(chunk_hex)
            except ValueError:
                # 非法 hash，放弃
                return

            pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(payload), seq=0, ack=0) + payload
            self.sock.sendto(pkt_get, new_addr)

            self.state.downloading[(new_addr, chunk_hex)] = DownloadSession(
                chunk=chunk_hex,
                expected_seq=1,
                total_segs=None,
                start_time=time.time(),
                last_ack_time=time.time(),
                waiting_chunks=[]
            )

            # 确保接收缓冲区已初始化
            if chunk_hex not in self.state.receiving:
                self.state.receiving[chunk_hex] = b""

            self._log(f"DEBUG: Retry chunk {chunk_hex} from backup peer {new_addr}")
            return

        # 4. 没有其它候选 peer，重新对所有 want_chunks 发送 WHOHAS，等待新的 IHAVE
        if self.state.want_chunks:
            try:
                # Send WHOHAS for all remaining want_chunks
                payload = b"".join(_hex_to_bytes(h) for h in self.state.want_chunks)
                pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

                for p in self.context.peers:
                    try:
                        pid = int(p[0])
                        if pid == self.context.identity:
                            continue
                        peer_ip = p[1]
                        peer_port = int(p[2])
                        self.sock.sendto(pkt, (peer_ip, peer_port))
                    except Exception:
                        continue

                self._log(
                    f"DEBUG: No backup peer for chunk {chunk_hex}, re-broadcast WHOHAS for all want_chunks: {self.state.want_chunks}")

                # Reset retry count since we're starting a new search, and schedule retry if needed
                self.state.whohas_retry_count = 0
                self.state.next_whohas_retry_time = time.time() + 3.0
            except Exception as e:
                self._log(f"DEBUG: Failed to send WHOHAS: {e}")

    def _complete_download(self, chunk_hex: str, total_bytes: int, session_key: Tuple,
                           from_addr: Tuple, seq_num: int):
        """Complete download - verify chunk and write all chunks when complete."""
        # Clean up out-of-order buffer
        if session_key in self.state.out_of_order_buffer:
            del self.state.out_of_order_buffer[session_key]

        # Get session and check for waiting chunks before deletion
        session = self.state.downloading.get(session_key)
        if not session:
            self._log(f"DEBUG: No session found for {chunk_hex}")
            return

        # 检查是否真的完成了
        if session.total_segs is None:
            self._log(f"DEBUG: total_segs is None, cannot complete for {chunk_hex}")
            return

        # 检查是否收到了所有segment
        if seq_num != session.total_segs:
            self._log(
                f"DEBUG: Not the last segment for {chunk_hex}: received seq {seq_num}, expected last {session.total_segs}")
            return

        data = self.state.receiving.get(chunk_hex)
        if not data:
            self._log(f"DEBUG: No data in receiving for {chunk_hex}")
            return

        # Check data size - allow >= CHUNK_DATA_SIZE (may have extra padding)
        if len(data) < CHUNK_DATA_SIZE:
            self._log(
                f"DEBUG: Data size too small for {chunk_hex}: got {len(data)}, expected at least {CHUNK_DATA_SIZE}")
            return

        out_file = self.state.output_map.get(chunk_hex)
        if not out_file:
            self._log(f"DEBUG: No output file mapped for {chunk_hex}")
            return

        try:
            # Verify SHA1 hash
            sha1 = hashlib.sha1()
            sha1.update(data)
            computed_hash = sha1.hexdigest()

            if computed_hash != chunk_hex:
                self._log(f"Hash mismatch! Expected {chunk_hex}, got {computed_hash}")
                return

            self._log(f"Chunk {chunk_hex} verified (size: {len(data)} bytes)")

            # Store chunk data in context (but don't write to file yet)
            self.context.has_chunks[chunk_hex] = data

            # Remove from want_chunks to mark as completed
            if chunk_hex in self.state.want_chunks:
                self.state.want_chunks.remove(chunk_hex)
                self._log(f"DEBUG: Removed {chunk_hex} from want_chunks. Remaining: {self.state.want_chunks}")

            if chunk_hex in self.state.candidates:
                self.state.candidates[chunk_hex] = [c for c in self.state.candidates[chunk_hex] if c != from_addr]

            waiting_chunks = session.waiting_chunks.copy()

            try:
                del self.state.downloading[session_key]
                self._log(f"DEBUG: Removed download session for {chunk_hex} from {from_addr}")
            except KeyError:
                pass

            # Check if there are waiting chunks to download from the same peer
            if waiting_chunks:
                next_chunk_hex = waiting_chunks.pop(0)
                self._log(
                    f"DEBUG: Auto-requesting next chunk {next_chunk_hex} from {from_addr} (remaining waiting: {waiting_chunks})")

                # Check if we still want this chunk
                if next_chunk_hex in self.state.want_chunks:
                    self._log(
                        f"DEBUG: [still wanted] Auto-requesting next chunk {next_chunk_hex} from {from_addr} (remaining waiting: {waiting_chunks})")
                    # Check if not already downloading from another peer
                    if not any(sess.chunk == next_chunk_hex for sess in self.state.downloading.values()):
                        self._log(
                            f"DEBUG: [not downloading] Auto-requesting next chunk {next_chunk_hex} from {from_addr} (remaining waiting: {waiting_chunks})")
                        # Send GET request for next chunk
                        try:
                            payload = _hex_to_bytes(next_chunk_hex)
                            pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(payload), seq=0, ack=0) + payload
                            self.sock.sendto(pkt_get, from_addr)

                            # Create new download session for next chunk
                            new_session_key = (from_addr, next_chunk_hex)
                            self.state.downloading[new_session_key] = DownloadSession(
                                chunk=next_chunk_hex,
                                expected_seq=1,
                                total_segs=None,
                                start_time=time.time(),
                                last_ack_time=time.time(),
                                waiting_chunks=waiting_chunks  # Pass remaining waiting chunks
                            )

                            # Initialize receiving buffer
                            if next_chunk_hex not in self.state.receiving:
                                self.state.receiving[next_chunk_hex] = b""

                            self._log(f"DEBUG: Created new download session for {next_chunk_hex} from {from_addr}")
                        except ValueError:
                            self._log(f"DEBUG: Invalid chunk hash {next_chunk_hex}, skipping")
                    else:
                        self._log(f"DEBUG: Already downloading {next_chunk_hex} from another peer, skipping")
                else:
                    self._log(f"DEBUG: Chunk {next_chunk_hex} no longer in want_chunks, skipping")

            self._log(
                f"DEBUG: Checking completion - want_chunks: {self.state.want_chunks}, downloading sessions: {len(self.state.downloading)}")
            # Check if all chunks are complete - if so, write all chunks to file
            # This check happens after processing waiting_chunks to ensure we don't write prematurely
            if not self.state.want_chunks and not self.state.downloading:
                # All chunks are complete, write to file
                self._log(f"DEBUG: All chunks completed! Writing to {out_file}")
                self._write_all_chunks_to_file(out_file)
            else:
                self._log(
                    f"DEBUG: Not all chunks completed yet. want_chunks: {self.state.want_chunks}, active downloads: {len(self.state.downloading)}")

        except Exception as e:
            self._log(f"Complete download failed: {e}")
            import traceback
            traceback.print_exc()

    def _write_all_chunks_to_file(self, out_file: str):
        """Write all completed chunks to the output file."""
        try:
            # Collect all chunks that should be written to this file
            chunks_to_write = {}
            for chunk_hex, file_path in self.state.output_map.items():
                if file_path == out_file and chunk_hex in self.context.has_chunks:
                    chunks_to_write[chunk_hex] = self.context.has_chunks[chunk_hex]

            if not chunks_to_write:
                self._log(f"DEBUG: No chunks to write to {out_file}")
                return

            # Create directory if needed
            os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)

            # Write all chunks using pickle format
            with open(out_file, "wb") as f:
                pickle.dump(chunks_to_write, f)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

            self._log(
                f"All chunks written to {out_file} ({len(chunks_to_write)} chunks: {list(chunks_to_write.keys())})")

        except Exception as e:
            self._log(f"Write all chunks failed: {e}")
            import traceback
            traceback.print_exc()


# ============================================================================
# Utility Functions (unchanged from original)
# ============================================================================

def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def _bytes_to_hex(b: bytes) -> str:
    return b.hex()


def _pack_header(ptype: int, plen: int, seq: int = 0, ack: int = 0) -> bytes:
    return struct.pack(
        HEADER_FMT, ptype, HEADER_LEN, socket.htons(plen), socket.htonl(seq), socket.htonl(ack)
    )


# ============================================================================
# Entry Point
# ============================================================================

def peer_run(context: PeerContext) -> None:
    """Entry point - maintains compatibility with original interface."""
    peer = Peer(context)
    peer.run()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="CS305 Peer")
    parser.add_argument(
        "-p",
        "--peer-file",
        dest="peer_file",
        type=str,
        required=True,
        help="The list of all peers"
    )
    parser.add_argument(
        "-c",
        "--chunk-file",
        dest="chunk_file",
        type=str,
        required=True,
        help="Pickle dumped dictionary {chunkhash: chunkdata}"
    )
    parser.add_argument(
        "-m",
        "--max-conn",
        dest="max_conn",
        type=int,
        required=True,
        help="Max # of concurrent sending"
    )
    parser.add_argument(
        "-i",
        "--identity",
        dest="identity",
        type=int,
        required=True,
        help="Which peer # am I?"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        type=int,
        default=0,
        help="Verbosity level"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        dest="timeout",
        type=int,
        default=0,
        help="Pre-defined timeout"
    )

    args = parser.parse_args()

    context = PeerContext(args)
    peer_run(context)


if __name__ == "__main__":
    main()
