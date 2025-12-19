import struct
import socket
import logging
import os
import sys
from pathlib import Path

type AddressType = tuple[str, int]


class SimSocket:
    """
    Wraps a standard UDP socket to transparently add/remove a "spiffy" simulator header.

    This class provides a socket-like interface (sendto, recvfrom, fileno, close)
    that mimics `socket.socket`.

    On initialization, it checks for the ``SIMULATOR`` environment variable.

    - If ``SIMULATOR`` is set (e.g., "127.0.0.1:12345"), this class enables
      "spiffy" mode. All outgoing packets from :meth:`sendto` are prepended
      with a spiffy header (containing the *intended* destination) and
      sent to the simulator's address. :meth:`recvfrom` will expect
      packets *from* the simulator, strip this header, and return
      the *original* sender's address and data.

    - If ``SIMULATOR`` is not set, this class behaves as a standard,
      pass-through UDP socket.

    It also provides a dedicated, file-based, and stdout-based logger for
    each peer instance.

    :ivar _sock: The underlying `socket.socket` (UDP) instance.
    :ivar _logger: The logger instance for this peer, named "PEER{pid}_LOGGER".
    :ivar _spiffy_enabled: True if the simulator environment variable is set.
    :ivar _spiffy_addr: The (ip, port) tuple of the simulator itself.
    :ivar _node_id: The peer's ID, stored for use in the spiffy header.
    :ivar _address: The (ip, port) address this socket is bound to.
    """

    _src_addr: str = ""
    _src_port: int = 0

    _spiffy_enabled: bool = False
    _node_id: int = 0
    _spiffy_addr: AddressType | None = None

    _SPIFFY_HEADER_FMT: str = "I4s4sHH"
    _SPIFFY_HEADER_LEN: int = struct.calcsize(_SPIFFY_HEADER_FMT)

    _STD_HEADER_FMT: str = "BBHII"
    _STD_HEADER_FMT_ORDERED: str = f"!{_STD_HEADER_FMT}"
    _STD_HEADER_LEN: int = struct.calcsize(_STD_HEADER_FMT)

    def __init__(self, pid: int, address: AddressType, verbose: int = 2) -> None:
        """
        Initializes the SimSocket.

        Binds a UDP socket to the given address, sets up logging, and
        attempts to initialize the connection to the network simulator.

        :param pid: The peer identity number. Used for naming the log file
                    (e.g., "peer1.log") and the logger instance.
        :param address: The (ip, port) tuple to bind this socket locally.
        :param verbose: Controls the logging level for stdout.
                        1=WARNING, 2=INFO (default), 3=DEBUG.
        """
        self._address: AddressType = address
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(address)
        self._logger: logging.Logger = logging.getLogger(f"P{pid}")
        self._logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d |- %(levelname)-5s |- %(name)s:%(lineno)d |- %(message)s",
            datefmt="%m-%d %H:%M:%S",
        )

        if verbose > 0:
            match verbose:
                case 1:
                    sh_level = logging.WARNING
                case 2:
                    sh_level = logging.INFO
                case 3:
                    sh_level = logging.DEBUG
                case _:
                    sh_level = logging.INFO

            sh = logging.StreamHandler(stream=sys.stdout)
            sh.setLevel(level=sh_level)
            sh.setFormatter(formatter)
            self._logger.addHandler(sh)

        # check log dir
        log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(filename=log_dir / f"peer{pid}.log", mode="w")

        fh.setLevel(level=logging.DEBUG)
        fh.setFormatter(formatter)
        self._logger.addHandler(fh)
        self._logger.info("Start logging")
        self._init_simulator(pid)

    def fileno(self) -> int:
        """
        Return the socket's file descriptor.
        Wrapper for the underlying socket's fileno() method.

        :return: The integer file descriptor.
        """
        return self._sock.fileno()

    def sendto(self, data_bytes: bytes, address: AddressType, flags: int = 0) -> int:
        """
        Send data to the socket.
        Wrapper for the underlying socket's sendto() method.

        If spiffy mode is enabled, the data is prepended with a spiffy
        header and sent to the simulator.
        Otherwise, it is sent directly to the specified address.

        :param data_bytes: The data to send.
        :param address: The target (ip, port) destination.
        :param flags: Optional flags (passed to the underlying socket).
        :return: The number of bytes sent from the original ``data_bytes``.
        """
        ip, port = address
        pkt_type, header_len, pkt_len, seq, ack = struct.unpack(
            self._STD_HEADER_FMT_ORDERED, data_bytes[: self._STD_HEADER_LEN]
        )
        if not self._spiffy_enabled:
            self._logger.debug(
                f"sending a type{pkt_type} pkt to {address} via normal socket, seq{seq}, ack{ack}, pkt_len{pkt_len}"
            )
            return self._sock.sendto(data_bytes, flags, address)

        dest_addr_bytes: bytes = socket.inet_aton(ip)
        dest_port_net: int = socket.htons(port)
        node_id_net: int = socket.htonl(self._node_id)
        src_addr_bytes: bytes = socket.inet_aton(self._src_addr)
        src_port_net: int = socket.htons(self._src_port)

        spiffy_header: bytes = struct.pack(
            self._SPIFFY_HEADER_FMT,
            node_id_net,
            src_addr_bytes,
            dest_addr_bytes,
            src_port_net,
            dest_port_net,
        )

        packet_with_header: bytes = spiffy_header + data_bytes

        self._logger.debug(
            f"sending a type{pkt_type} pkt to {address} via spiffy, seq{seq}, ack{ack}, pkt_len{pkt_len}"
        )
        ret: int = self._sock.sendto(packet_with_header, flags, self._spiffy_addr)
        return ret - len(spiffy_header)

    def recvfrom(self, bufsize: int, flags: int = 0) -> tuple[bytes, AddressType]:
        """
        Receive data from the socket.
        Wrapper for the underlying socket's recvfrom() method.

        If spiffy mode is enabled, this method receives data from the
        simulator, parses the spiffy header to get the original sender's
        address, and returns the application data and that original address.
        Otherwise, it behaves as a standard socket recvfrom.

        :param bufsize: The number of bytes to read for the application data.
        :param flags: Optional flags (passed to the underlying socket).
        :raises Exception: If the packet header is corrupted (spiffy mode only).
        :return: A tuple ``(data,address)`` where ``data`` is a bytes object
                 of the received data and ``address`` is the (ip, port)
                 of the peer that sent the data.
        """
        if not self._spiffy_enabled:
            ret: tuple[bytes, AddressType] = self._sock.recvfrom(bufsize, flags)
            pkt_type, header_len, pkt_len, seq, ack = struct.unpack(
                self._STD_HEADER_FMT_ORDERED, ret[0][: self._STD_HEADER_LEN]
            )
            self._logger.debug(
                f"receiving a type{pkt_type} pkt from {ret[1]} via normal socket, seq{seq}, ack{ack}, pkt_len{pkt_len}"
            )
            return ret

        ret: tuple[bytes, AddressType] | None = self._sock.recvfrom(
            bufsize + self._SPIFFY_HEADER_LEN, flags
        )

        if ret is not None:
            simu_bytes, addr = ret
            _, src_addr_bytes, dest_addr_bytes, src_port_net, dest_port_net = (
                struct.unpack(
                    self._SPIFFY_HEADER_FMT, simu_bytes[: self._SPIFFY_HEADER_LEN]
                )
            )
            from_addr: AddressType = (
                socket.inet_ntoa(src_addr_bytes),
                socket.ntohs(src_port_net),
            )
            to_addr: AddressType = (
                socket.inet_ntoa(dest_addr_bytes),
                socket.ntohs(dest_port_net),
            )
            data_bytes: bytes = simu_bytes[self._SPIFFY_HEADER_LEN :]

            pkt_type, header_len, pkt_len, seq, ack = struct.unpack(
                self._STD_HEADER_FMT_ORDERED, data_bytes[: self._STD_HEADER_LEN]
            )
            self._logger.debug(
                f"receiving a type{pkt_type} pkt from {from_addr} via spiffy, seq{seq}, ack{ack}, pkt_len{pkt_len}"
            )

            # check if spiffy header intact
            if to_addr != self._address:
                self._logger.error("Packet header corrupted, please check bytes read.")
                raise Exception("Packet header corrupted!")

            return data_bytes, from_addr

        self._logger.error("Error on simulator recvfrom: received None")

    def _init_simulator(self, node_id: int) -> bool:
        """
        Check for and initialize the spiffy network simulator.

        Reads the ``SIMULATOR`` environment variable. If set and formatted
        correctly (ip:port), it enables spiffy mode.

        :param node_id: The ID of this peer.
        :return: True if spiffy mode was successfully enabled, False otherwise.
        """
        simulator_env: str | None = os.getenv("SIMULATOR")
        if simulator_env is None:
            self._logger.warning("Simulator not set, using normal socket.")
            return False

        addr: list[str] = simulator_env.split(":")
        if len(addr) != 2:
            self._logger.warning(f"Badly formatted addr: {simulator_env}")
            return False

        self._spiffy_addr = (addr[0], int(addr[1]))
        self._node_id = node_id
        self._spiffy_enabled = True
        self._src_addr = self._address[0]
        self._src_port = self._address[1]

        self._logger.info(
            f"Network simulator activated, running at {self._spiffy_addr}."
        )
        return True

    def log_info(self, msg: str) -> None:
        """
        Log an INFO level message.

        :param msg: The message string to log.
        """
        self._logger.info(msg)

    def close(self) -> None:
        """
        Close the underlying socket.
        Wrapper for the underlying socket's close() method.
        """
        self._logger.info("socket closed")
        self._sock.close()
