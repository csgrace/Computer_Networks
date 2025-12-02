import struct
import socket
import logging
from dataclasses import dataclass
from pathlib import Path

_SPIFFY_HEADER_FMT: str = "I4s4sHH"
SPIFFY_HEADER_LEN: int = struct.calcsize(_SPIFFY_HEADER_FMT)
_STD_HEADER_FMT: str = "BBHII"
STD_HEADER_LEN: int = struct.calcsize(_STD_HEADER_FMT)

_MAX_BUF_SIZE: int = 1500


@dataclass
class StdPkt:
    pkt_type: int
    header_len: int
    pkt_len: int
    seq: int
    ack: int
    pkt_bytes: bytes
    from_addr: tuple[str, int]
    to_addr: tuple[str, int]


class CheckerSocket:
    def __init__(self, addr: tuple[str, int]) -> None:
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(addr)

        self._logger: logging.Logger = logging.getLogger("Checker-LOGGER")
        self._logger.setLevel(logging.DEBUG)
        formatter: logging.Formatter = logging.Formatter(
            fmt="%(relativeCreated)d | %(levelname)s | %(name)s -  | %(message)s"
        )

        # check log dir
        log_dir: Path = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        fh: logging.FileHandler = logging.FileHandler(
            filename=log_dir / "Checker.log", mode="w"
        )
        fh.setLevel(level=logging.DEBUG)
        fh.setFormatter(formatter)
        self._logger.addHandler(fh)
        self._logger.info("Start logging")

    def recv_pkt_from(self) -> StdPkt:
        read_pkt_byte: bytes
        from_addr: tuple[str, int]
        read_pkt_byte, from_addr = self._sock.recvfrom(_MAX_BUF_SIZE)

        mixed_headers: bytes = read_pkt_byte[: SPIFFY_HEADER_LEN + STD_HEADER_LEN]

        spiffy_id: int
        src_addr_raw: bytes
        dest_addr_raw: bytes
        src_port_raw: int
        dest_port_raw: int
        (
            spiffy_id,
            src_addr_raw,
            dest_addr_raw,
            src_port_raw,
            dest_port_raw,
        ) = struct.unpack(_SPIFFY_HEADER_FMT, mixed_headers[:SPIFFY_HEADER_LEN])

        src_addr_str: str = socket.inet_ntoa(src_addr_raw)
        dest_addr_str: str = socket.inet_ntoa(dest_addr_raw)
        src_port_int: int = socket.ntohs(src_port_raw)
        dest_port_int: int = socket.ntohs(dest_port_raw)

        pkt_type: int
        header_len: int
        pkt_len: int
        seq: int
        ack: int
        pkt_type, header_len, pkt_len, seq, ack = struct.unpack(
            _STD_HEADER_FMT, mixed_headers[SPIFFY_HEADER_LEN:]
        )

        header_len = socket.ntohs(header_len)
        pkt_len = socket.ntohs(pkt_len)
        seq = socket.ntohl(seq)
        ack = socket.ntohl(ack)

        # can_read, _, _ = select.select([self.__sock], [], [], 1)
        # if len(can_read) > 0:
        #     remainder_data, _ = self.__sock.recvfrom(pkt_len + SPIFFY_HEADER_LEN)

        # if len(can_read) == 0 or len(remainder_data) != pkt_len + SPIFFY_HEADER_LEN:
        #     self.__logger.error(
        #         f"Pkt len in header is not correctly set or pkt corrupted {pkt_len}, {header_len}"
        #     )
        #     raise Exception("Bad pkt len in header")

        to_addr: tuple[str, int] = (dest_addr_str, dest_port_int)
        pkt: StdPkt = StdPkt(
            pkt_type, header_len, pkt_len, seq, ack, read_pkt_byte, from_addr, to_addr
        )

        self._logger.debug(
            f"{from_addr} sends a type{pkt_type} pkt to {to_addr}, seq{seq}, ack{ack}"
        )

        return pkt

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self._sock.sendto(data, addr)

    def fileno(self) -> int:
        return self._sock.fileno()

    def log_debug(self, msg: str) -> None:
        self._logger.debug(msg)
