import sys
import select
import struct
import socket
import hashlib
import argparse
import pickle

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


# Global variables to hold configuration and state
# This may not be the best design, but is used here for simplicity
g_context: PeerContext | None = None
g_output_file: str | None = None
g_received_chunk: dict[str, bytes] = {}
g_downloading_chunkhash: str = ""


def process_download(
    sock: simsocket.SimSocket, chunk_file: str, output_file: str
) -> None:
    """
    Initiates the download process for a chunk.

    Reads a chunk hash from the chunk_file, builds a WHOHAS packet,
    and broadcasts it to all peers listed in the global context.

    :param sock: The socket used for sending packets.
    :param chunk_file: Path to a file containing the hash of the chunk to download.
    :param output_file: Path where the downloaded chunk data will be saved.
    """
    # print(f"PROCESS GET SKELETON CODE CALLED. Fill me in! I've been doing! ({chunk_file}, {output_file})")
    global g_output_file
    global g_received_chunk
    global g_downloading_chunkhash

    g_output_file = output_file
    # Step 1: read chunkhash to be downloaded from chunk_file
    download_hash: bytes = b""
    with open(chunk_file, "r") as chunk_file_handler:
        index: str
        datahash_str: str
        index, datahash_str = chunk_file_handler.readline().strip().split(" ")
        g_received_chunk[datahash_str] = b""
        g_downloading_chunkhash = datahash_str

        # hex_str to bytes
        datahash: bytes = bytes.fromhex(datahash_str)
        download_hash += datahash

    # |1Byte type |1Byte h len|     2Byte pkt len     |
    # |              4Byte  SEQ Number                |
    # |              4Byte  ACK Number                |
    whohas_header: bytes = struct.pack(
        HEADER_FMT,
        PktType.WHOHAS,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(download_hash)),  # converted to htons 2 bytes
        socket.htonl(0),  # converted to htons 4 bytes
        socket.htonl(0),
    )
    whohas_pkt: bytes = whohas_header + download_hash

    # Step 3: flooding whohas to all peers in peer list
    peer_list: list[list[str]] = g_context.peers
    for p in peer_list:
        if int(p[0]) != g_context.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound UDP packet from the socket.

    Unpacks the packet header, identifies its type, and routes it
    to the correct logic (e.g., sending GET on IHAVE, sending ACK on DATA).

    :param sock: The socket that received the inbound packet.
    """
    # Receive pkt
    pkt: bytes
    from_addr: AddressType
    pkt, from_addr = sock.recvfrom(BUF_SIZE)

    pkg_type: int
    hlen: int
    plen: int
    seq: int
    ack: int
    pkg_type, hlen, plen, seq, ack = struct.unpack(HEADER_FMT, pkt[:HEADER_LEN])
    data: bytes = pkt[HEADER_LEN:]

    match pkg_type:
        case PktType.IHAVE:
            # received an IHAVE pkt
            # see what chunk the sender has
            get_chunk_hash: bytes = data[:20]

            # send back GET pkt
            get_header: bytes = struct.pack(
                HEADER_FMT,
                PktType.GET,
                HEADER_LEN,
                socket.htons(HEADER_LEN + len(get_chunk_hash)),
                socket.htonl(0),
                socket.htonl(0),
            )
            get_pkt: bytes = get_header + get_chunk_hash
            sock.sendto(get_pkt, from_addr)

        case PktType.DATA:
            # received a DATA pkt
            g_received_chunk[g_downloading_chunkhash] += data

            # send back ACK
            ack_pkt: bytes = struct.pack(
                HEADER_FMT,
                PktType.ACK,
                HEADER_LEN,
                socket.htons(HEADER_LEN),
                0,
                seq,
            )
            sock.sendto(ack_pkt, from_addr)

            # see if finished
            if len(g_received_chunk[g_downloading_chunkhash]) == CHUNK_DATA_SIZE:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                with open(g_output_file, "wb") as write_file_handler:
                    pickle.dump(g_received_chunk, write_file_handler)

                # add to this peer's has_chunk:
                g_context.has_chunks[g_downloading_chunkhash] = g_received_chunk[
                    g_downloading_chunkhash
                ]

                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                print(f"GOT {g_output_file}")

                # The following things are just for illustration, you do not need to print out in your design.
                sha1 = hashlib.sha1()
                sha1.update(g_received_chunk[g_downloading_chunkhash])
                received_chunkhash_str: str = sha1.hexdigest()
                print(f"Expected chunkhash: {g_downloading_chunkhash}")
                print(f"Received chunkhash: {received_chunkhash_str}")
                success: bool = g_downloading_chunkhash == received_chunkhash_str
                print(f"Successfully received: {success}")
                if success:
                    print("Congratulations! You have completed the example!")
                else:
                    print("Example fails. Please check the example files carefully.")

        case _:
            pass


def process_user_input(sock: simsocket.SimSocket) -> None:
    """
    Handles a command read from standard input.

    Parses the user's command and initiates the download process
    if the command is "DOWNLOAD".

    :param sock: The simsocket object to be passed to process_download.
    """
    # Use split() without arguments for more robust splitting on whitespace
    command, chunk_file, out_file = input().split()
    if command == "DOWNLOAD":
        process_download(sock, chunk_file, out_file)
    else:
        pass


def peer_run(context: PeerContext) -> None:
    """
    Runs the main event loop for the peer.

    Initializes the peer's socket and uses select() to multiplex
    between handling network packets and user input from stdin.

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
            if read_ready:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
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
        description="CS305 Project receiver example",
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
