import sys
import os
import select
import struct
import socket
import hashlib
import argparse
import pickle

from typing import Dict, List, Tuple
from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

# 动态插入项目路径，确保可以正确导入 utils
_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_this_dir, ".."))

# 检查并插入项目根路径
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# 打印调试信息，验证路径插入是否正确
print(f"Inserted project root to sys.path: {_project_root}")
print(f"Current sys.path:\n", "\n".join(sys.path))


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

# Global context used by handlers
g_context: PeerContext | None = None

# Track downloads in progress: chunkhash_hex -> received bytes
g_receiving: Dict[str, bytes] = {}

# Track which chunks we are trying to download (set by DOWNLOAD command)
g_want_chunks: List[str] = []

# Map chunkhash -> list of candidate peers (ip, port)
g_candidates: Dict[str, List[Tuple[str, int]]] = {}

# Number of active uploads (simple counter)
g_active_uploads: int = 0

# Map uploading chunkhash -> (peer_addr) to track active uploads if needed
g_uploads: Dict[str, Tuple[str, int]] = {}

# Map downloading chunkhash -> output-file (for later dump), optional
g_output_map: Dict[str, str] = {}

def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def _bytes_to_hex(b: bytes) -> str:
    return b.hex()

def _pack_header(ptype: int, plen: int, seq: int = 0, ack: int = 0) -> bytes:
    # plen is full packet length (header + payload)
    # pack fields: type, hlen (we use HEADER_LEN), plen (2byte), seq(4), ack(4)
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
    global g_want_chunks, g_receiving, g_candidates, g_output_map

    g_want_chunks = []
    g_candidates = {}
    g_receiving = {}
    g_output_map = {}
    # Read chunkhash file (take all lines)
    try:
        with open(chunk_file, "r") as f:
            for line in f:
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
        print(f"Error reading chunk file {chunk_file}: {e}", file=sys.stderr)
        return

    if len(g_want_chunks) == 0:
        print("No chunks to download.")
        return

    # Build WHOHAS payload: concatenation of 20-byte binary SHA1 for each wanted chunk
    payload = b"".join(_hex_to_bytes(h) for h in g_want_chunks)
    pkt = _pack_header(PktType.WHOHAS, HEADER_LEN + len(payload), seq=0, ack=0) + payload

    # Flood WHOHAS to all peers except self
    for p in g_context.peers:
        try:
            pid = int(p[0])
            if pid == g_context.identity:
                continue
            peer_ip = p[1]
            peer_port = int(p[2])
            sock.sendto(pkt, (peer_ip, peer_port))
            if g_context.verbose >= 2:
                print(f"SENT WHOHAS to {peer_ip}:{peer_port} for {len(g_want_chunks)} chunks")
        except Exception:
            continue
    # print("PROCESS DOWNLOAD SKELETON CODE CALLED.  Fill me in!")


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function should receive data, unpack the standard header,
    and then use the packet type to route the packet to the appropriate
    handling logic (e.g., for WHOHAS, IHAVE, GET, DATA, ACK).

    :param sock: The :class:`simsocket.SimSocket` with a pending packet.
    :type sock: simsocket.SimSocket
    """
    global g_context, g_active_uploads, g_candidates, g_receiving, g_want_chunks, g_uploads

    # Receive packet
    pkt: bytes
    from_addr: AddressType
    pkt, from_addr = sock.recvfrom(BUF_SIZE)

    pkg_type: int
    hlen: int
    plen: int
    seq: int
    ack: int
    try:
        pkg_type, hlen, plen, seq, ack = struct.unpack(HEADER_FMT, pkt[:HEADER_LEN])
    except Exception:
        if g_context and g_context.verbose:
            print("Received malformed packet (bad header)")
        return

    data: bytes = pkt[HEADER_LEN:]
    try:
        seq_h = socket.ntohl(seq)
        ack_h = socket.ntohl(ack)
    except Exception:
        seq_h = seq
        ack_h = ack

    # WHOHAS handling: Sends IHAVE packets if peer has the requested chunks
    if pkg_type == PktType.WHOHAS:
        have_hashes = []
        for i in range(0, len(data), 20):  # Process the requested chunk hashes
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            if hhex in g_context.has_chunks:
                have_hashes.append(hbytes)  # Record the hashes we have

        # Check upload constraints (max_conn)
        max_conn = getattr(g_context, "max_conn", None)
        if max_conn is None:
            max_conn = getattr(getattr(g_context, "args", None), "max_conn", None)
        can_upload = g_active_uploads < max_conn if max_conn is not None else True

        # Respond with IHAVE if allowed, otherwise DENIED
        if can_upload and have_hashes:
            payload = b"".join(have_hashes)
            pkt_ihave = _pack_header(PktType.IHAVE, HEADER_LEN + len(payload)) + payload
            sock.sendto(pkt_ihave, from_addr)
            if g_context.verbose >= 2:
                print(f"Sent IHAVE to {from_addr} for {len(have_hashes)} chunks")
        else:
            pkt_denied = _pack_header(PktType.DENIED, HEADER_LEN)
            sock.sendto(pkt_denied, from_addr)
            if g_context.verbose >= 2:
                print(f"Sent DENIED to {from_addr}")

    # IHAVE Handling: Sends GET packets if peer has needed chunks
    elif pkg_type == PktType.IHAVE:
        for i in range(0, len(data), 20):  # Process the available chunk hashes
            hbytes = data[i:i + 20]
            if len(hbytes) < 20:
                continue
            hhex = _bytes_to_hex(hbytes)
            if hhex in g_want_chunks:
                g_candidates.setdefault(hhex, []).append(from_addr)  # Record candidate peer
                # Immediately send GET packet for this chunk
                pkt_get = _pack_header(PktType.GET, HEADER_LEN + len(hbytes)) + hbytes
                sock.sendto(pkt_get, from_addr)
                if g_context.verbose >= 2:
                    print(f"Sent GET to {from_addr} for chunk {hhex}")

    # GET Handling: Sends DATA packets if requested chunk is available
    elif pkg_type == PktType.GET:
        if len(data) < 20:
            return
        requested_hex = _bytes_to_hex(data[:20])  # Get requested chunk hash
        if requested_hex in g_context.has_chunks:
            chunk_bytes = g_context.has_chunks[requested_hex]
            to_send = chunk_bytes[:MAX_PAYLOAD]  # Send one chunk at a time
            g_active_uploads += 1  # Increment upload count
            g_uploads[requested_hex] = from_addr
            pkt_data = _pack_header(PktType.DATA, HEADER_LEN + len(to_send), seq=1) + to_send
            sock.sendto(pkt_data, from_addr)
            if g_context.verbose >= 2:
                print(f"Sent DATA to {from_addr} for chunk {requested_hex} ({len(to_send)} bytes)")

    # DATA Handling: Saves received chunk data, acknowledges receipt
    elif pkg_type == PktType.DATA:
        for want in list(g_receiving.keys()):
            if len(g_receiving[want]) < CHUNK_DATA_SIZE:  # Append data only if not complete
                g_receiving[want] += data
                ack_pkt = _pack_header(PktType.ACK, HEADER_LEN, ack=seq_h)
                sock.sendto(ack_pkt, from_addr)
                if g_context.verbose >= 2:
                    print(f"Received DATA ({len(data)} bytes) from {from_addr}, sent ACK seq {seq_h}")
                # If complete, save chunk and clean up
                if len(g_receiving[want]) == CHUNK_DATA_SIZE:
                    with open(g_output_map.get(want, f"download_{want}.fragment"), "wb") as f:
                        pickle.dump({want: g_receiving[want]}, f)
                    print(f"GOT complete chunk {want}")
                    g_context.has_chunks[want] = g_receiving[want]
                    del g_receiving[want]

    # ACK Handling: Frees up upload slots after acknowledgment
    elif pkg_type == PktType.ACK:
        if g_uploads:
            try:
                completed_chunk, _ = g_uploads.popitem()
                g_active_uploads -= 1
                if g_context.verbose >= 2:
                    print(f"Received ACK for chunk {completed_chunk}, finished upload")
            except Exception:
                pass

    # Unknown Packet Handling
    else:
        if g_context.verbose >= 3:
            print(f"Unknown packet type {pkg_type} from {from_addr}")

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
    command, chunk_file, output_file = input().split()
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
            ready: tuple[list, list, list] = select.select(
                [sock, sys.stdin], [], [], 0.1
            )
            read_ready: list = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


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
