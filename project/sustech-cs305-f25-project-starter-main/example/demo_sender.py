import sys
import select
import struct
import socket
import argparse

from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

"""
This is an example on how to use the provided skeleton code.
Please note that this receiver will only download 1 chunk from the sender as we only maintain ONE downloading process.
You are advised to focus the following things:
1. How to make a pkt using struct?
2. How to send/receive pkt with simsocket?
3. How to interpret bytes and how to adapt bytes to/from network endian?
4. How to use hashlib?
"""

# Define buffer size and chunk data size
BUF_SIZE: int = 1400
CHUNK_DATA_SIZE: int = 512 * 1024

# Define header format and length
HEADER_FMT: str = "BBHII"
HEADER_LEN: int = struct.calcsize(HEADER_FMT)


# Define packet types constants
class PktType:
    WHOHAS: int = 0
    IHAVE: int = 1
    GET: int = 2
    DATA: int = 3
    ACK: int = 4


# Define maximum payload size
MAX_PAYLOAD: int = 1024

# Global variables to hold configuration and state
# This may not be the best design, but is used here for simplicity
g_context: PeerContext | None = None
g_sending_chunkhash: str = ""


def process_download(
    sock: simsocket.SimSocket, chunk_file: str, output_file: str
) -> None:
    """
    Placeholder for download logic. In this sender example, it does nothing.

    :param sock: The socket used for sending packets.
    :param chunk_file: Path to a file containing chunk hashes.
    :param output_file: Path where downloaded data would be saved.
    """
    # print(f"PROCESS GET SKELETON CODE CALLED. Fill me in! I've been doing! ({chunk_file}, {output_file})")
    # This method will not be called in sender
    pass


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound UDP packet from the socket.

    Unpacks the packet header, identifies its type, and routes it
    to the correct logic (e.g., sending IHAVE on WHOHAS, sending DATA on GET).

    :param sock: The socket that received the inbound packet.
    """
    # Receive pkt
    global g_context
    global g_sending_chunkhash

    pkt: bytes
    from_addr: AddressType
    pkt, from_addr = sock.recvfrom(BUF_SIZE)

    pkt_type: int
    hlen: int
    plen: int
    seq: int
    ack: int
    pkt_type, hlen, plen, seq, ack = struct.unpack(HEADER_FMT, pkt[:HEADER_LEN])
    data: bytes = pkt[HEADER_LEN:]

    match pkt_type:
        case PktType.WHOHAS:
            # received a WHOHAS pkt
            # see what chunk the sender has
            whohas_chunk_hash: bytes = data[:20]
            # bytes to hex_str
            chunkhash_str: str = whohas_chunk_hash.hex()
            g_sending_chunkhash = chunkhash_str

            print(f"whohas: {chunkhash_str}, has: {list(g_context.has_chunks.keys())}")
            if chunkhash_str in g_context.has_chunks:
                # send back IHAVE pkt
                ihave_header: bytes = struct.pack(
                    HEADER_FMT,
                    PktType.IHAVE,
                    HEADER_LEN,
                    socket.htons(
                        HEADER_LEN + len(whohas_chunk_hash)
                    ),  # converted to htons 2 bytes
                    socket.htonl(0),  # converted to htonl 4 bytes
                    socket.htonl(0),
                )
                ihave_pkt: bytes = ihave_header + whohas_chunk_hash
                sock.sendto(ihave_pkt, from_addr)
        case PktType.GET:
            # received a GET pkt
            chunk_data: bytes = g_context.has_chunks[g_sending_chunkhash][:MAX_PAYLOAD]

            # send back DATA
            data_header: bytes = struct.pack(
                HEADER_FMT,
                PktType.DATA,
                HEADER_LEN,
                socket.htons(HEADER_LEN),
                socket.htonl(1),
                0,
            )
            sock.sendto(data_header + chunk_data, from_addr)

        case PktType.ACK:
            # received an ACK pkt
            ack_num: int = socket.ntohl(ack)
            if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {g_sending_chunkhash}")
                pass
            else:
                left: int = ack_num * MAX_PAYLOAD
                right: int = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data: bytes = g_context.has_chunks[g_sending_chunkhash][left:right]
                # send next data
                data_header: bytes = struct.pack(
                    HEADER_FMT,
                    PktType.DATA,
                    HEADER_LEN,
                    socket.htons(HEADER_LEN + len(next_data)),
                    socket.htonl(ack_num + 1),
                    0,
                )
                sock.sendto(data_header + next_data, from_addr)
        case _:
            pass


def process_user_input(sock: simsocket.SimSocket) -> None:
    """
    Handles a command read from standard input.

    Parses the user's command and calls the download process
    (which is a placeholder in this sender example).

    :param sock: The simsocket object to be passed to process_download.
    """
    command, chunk_file, out_file = input().split()
    if command == "DOWNLOAD":
        process_download(sock, chunk_file, out_file)
    else:
        pass


def peer_run(context: PeerContext) -> None:
    """
    Runs the main event loop for the peer.

    Initializes the peer's socket and uses select() to multiplex
    between handling network packets and user input from stdin
    (Note: User input is ignored in this sender example).

    :param context: The configuration and state object for this peer.
    """
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
                    # process_user_input(sock)
                    # Sender does not need to handle user input
                    pass
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
    global g_context

    parser = argparse.ArgumentParser(
        description="CS305 Project sender example",
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

    g_context = PeerContext(args)
    peer_run(g_context)


if __name__ == "__main__":
    main()
