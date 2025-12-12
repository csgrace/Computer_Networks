import sys
import os
import pickle


class PeerContext:
    """
    Manages the peer's runtime configuration, state, and known peer list.

    This class is initialized from command-line arguments. It is responsible
    for parsing the peer list file and the "has chunks" file to build the
    peer's initial state. It also validates the peer's own identity and
    derives its local IP address and port from the loaded peer list.

    :ivar output_file: The default output file name (not currently used).
    :ivar peer_list_file: Path to the file containing the list of all peers.
    :ivar has_chunk_file: Path to the fragment file describing chunks this peer owns.
    :ivar max_conn: The maximum number of concurrent connections.
    :ivar identity: The unique ID of this peer.
    :ivar peers: A list of peer info lists. Each sublist is [id_str, ip, port_str].
    :ivar has_chunks: A dictionary mapping chunk hashes (hex str) to chunk data.
    :ivar verbose: The verbosity level for logging.
    :ivar timeout: The pre-defined timeout value.
    :ivar ip: The IP address of this peer, derived from the peer list.
    :ivar port: The port number of this peer, derived from the peer list.
    """

    def __init__(self, args) -> None:
        """
        Initializes the PeerContext from parsed command-line arguments.

        :param args: The namespace object returned by
                     :func:`argparse.ArgumentParser.parse_args`.
                     Must contain attributes: peer_file, chunk_file, max_conn,
                     identity, verbose, and timeout.
        :raises SystemExit: If the peer identity is 0 or if the peer's own ID
                            is not found in the peer list file.
        """
        self.output_file: str = "output.dat"
        self.peer_list_file: str = args.peer_file
        self.has_chunk_file: str = args.chunk_file
        self.max_conn: int = args.max_conn
        self.identity: int = args.identity
        self.peers: list[list[str]] = []
        self.has_chunks: dict[str, bytes] = {}
        self.verbose: int = args.verbose
        self.timeout: int = args.timeout

        self.load_peers()
        self.load_chunks()

        if self.identity == 0:
            print("bt_parse error: Node identity must not be zero!")
            sys.exit(1)

        p: list[str] | None = self.get_peer_info_by_id(self.identity)
        if p is None:
            print(
                f"bt_parse error: No peer information for myself (id {self.identity})!"
            )
            sys.exit(1)

        self.ip: str = p[1]
        self.port: int = int(p[2])

    def load_peers(self) -> None:
        """
        Loads the peer list from the file specified in ``self.peer_list_file``.

        Populates ``self.peers`` with the parsed peer information.
        """
        with open(self.peer_list_file, "r") as file:
            for line in file:
                if line.startswith("#"):
                    continue
                line = line.strip(os.linesep)
                self.peers.append(line.split(" "))  # node_id, hostname, port

    def load_chunks(self) -> None:
        """
        Loads the "has chunks" data from the pickle file specified
        in ``self.has_chunk_file``.

        Populates ``self.has_chunks`` with the loaded dictionary.
        """
        with open(self.has_chunk_file, "rb") as file:
            self.has_chunks = pickle.load(file)

    def get_peer_info_by_id(self, identity: int) -> list[str] | None:
        """
        Searches the loaded peer list for a specific peer identity.

        :param identity: The ID of the peer to find.
        :return: The peer info list [id, ip, port] if found, otherwise None.
        """
        for item in self.peers:
            if int(item[0]) == identity:
                return item
        return None

    def __str__(self) -> str:
        lines = [
            "CS305 PROJECT PEER",
            # f"{'chunk-file:':<16} {self.chunk_file}",
            f"{'has-chunk-file:':<16} {self.has_chunk_file}",
            f"{'max-conn:':<16} {self.max_conn}",
            f"{'peer-identity:':<16} {self.identity}",
            f"{'peer-list-file:':<16} {self.peer_list_file}",
            "Peers:",
        ]

        for peer_id, peer_ip, peer_port in self.peers:
            lines.append(f"  peer {peer_id}: {peer_ip}:{peer_port}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"PeerContext(identity={self.identity}, " f"peers_count={len(self.peers)})"
        )
