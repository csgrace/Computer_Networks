import time

import pytest

import grader


@pytest.fixture(scope="module")
def handshaking_session() -> grader.GradingSession:
    blocking_time: int = 10

    handshaking_session: grader.GradingSession = grader.GradingSession(
        grader.normal_handler
    )
    _PEER_FILE = "src/peer.py"
    _NODES_MAP = "test/tmp1/nodes1.map"
    _MAX_CONN = 1
    peer_args = [
        (1, "test/tmp1/data1.fragment", 58001),
        (2, "test/tmp1/data2.fragment", 58002),
        (3, "test/tmp1/data1.fragment", 58003),
        (4, "test/tmp1/data1.fragment", 58004),
        (5, "test/tmp1/data1.fragment", 58005),
        (6, "test/tmp1/data1.fragment", 58006),
        (7, "test/tmp1/data1.fragment", 58007),
    ]
    for peer_id, has_chunk, port in peer_args:
        handshaking_session.add_peer(
            identity=peer_id,
            peer_file_loc=_PEER_FILE,
            nodes_map_loc=_NODES_MAP,
            has_chunk_loc=has_chunk,
            max_connection=_MAX_CONN,
            peer_addr=("127.0.0.1", port),
        )

    handshaking_session.run_grader()

    handshaking_session.peer_list[("127.0.0.1", 58001)].send_cmd(
        """DOWNLOAD test/tmp1/download_target.chunkhash test/tmp1/download_result.fragment\n"""
    )
    time.sleep(blocking_time)

    for p in handshaking_session.peer_list.values():
        p.terminate_peer()

    return handshaking_session


def test_flooding_whohas(handshaking_session: grader.GradingSession) -> None:
    peer1_addr = "127.0.0.1", 58001
    for i in range(58002, 58008):
        assert (
            handshaking_session.peer_list[peer1_addr].send_record[("127.0.0.1", i)][0]
            > 0
        ), f"Fail to send WHOHAS to {i}"


def test_send_ihave(handshaking_session: grader.GradingSession) -> None:
    peer1_addr = "127.0.0.1", 58001
    peer2_addr = "127.0.0.1", 58002
    assert (
        handshaking_session.peer_list[peer2_addr].send_record[peer1_addr][1] > 0
    ), "Fail to send IHAVE"


def test_send_download(handshaking_session: grader.GradingSession) -> None:
    peer1_addr = "127.0.0.1", 58001
    peer2_addr = "127.0.0.1", 58002
    assert (
        handshaking_session.peer_list[peer1_addr].send_record[peer2_addr][2] > 0
    ), "Fail to send DOWLOAD"


def test_handshaking(handshaking_session: grader.GradingSession) -> None:
    peer1_addr = "127.0.0.1", 58001
    peer2_addr = "127.0.0.1", 58002

    # (receiver_addr, sender_addr, packet_type_index, error_message)
    expected_records = [
        (peer2_addr, peer1_addr, 0, "Fail to receive any WHOHAS"),
        (peer1_addr, peer2_addr, 1, "Fail to receive any IHAVE"),
        (peer2_addr, peer1_addr, 2, "Fail to receive any DOWNLOAD"),
        (peer1_addr, peer2_addr, 3, "Fail to receive any DATA"),
        (peer2_addr, peer1_addr, 4, "Fail to receive any ACK"),
    ]

    for receiver, sender, pkt_type, fail_message in expected_records:
        assert (
            handshaking_session.peer_list[receiver].recv_record[sender][pkt_type] > 0
        ), fail_message
