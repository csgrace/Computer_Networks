import time
import pickle
import hashlib
from pathlib import Path

import pytest

import grader

"""
This test examines the basic function of your robustness.
Peer1 will be downloading chunk2 from Peer2, then peer2 will crash in the dowloading process. Peer1 should be able to download from peer3.

This test will be running with network simulator, with topology test/tmp4/topo4.map. 

.fragment files:
data4-1.fragment: chunk1
data4-2.fragment: chunk2

This testing script is equivalent to run the following commands in different shells (remember to export SIMULATOR in each shell):

perl utils/hupsim.pl -m test/tmp4/topo3.map -n test/tmp4/nodes4.map -p {port_number} -v 3


python3 src/peer.py -p test/tmp4/nodes4.map -c test/tmp4/data4-1.fragment -m 100 -i 1
DOWNLOAD test/tmp4/download_target4.chunkhash test/tmp4/download_result.fragment


python3 src/peer.py -p test/tmp4/nodes4.map -c test/tmp4/data4-2.fragment -m 100 -i 2
(CTRL+C to terminate peer2 after 1 seconds)


python3 src/peer.py -p test/tmp4/nodes4.map -c test/tmp4/data4-2.fragment -m 100 -i 3
"""


@pytest.fixture(scope="module")
def crash_session() -> tuple[grader.GradingSession, bool]:
    success: bool = False
    time_max: int = 80
    result_path = Path("test/tmp4/download_result.fragment")
    if result_path.exists():
        result_path.unlink()

    stime: float = time.perf_counter()
    crash_session: grader.GradingSession = grader.GradingSession(
        grader.normal_handler,
        latency=0.01,
        spiffy=True,
        topo_map="test/tmp4/topo4.map",
        nodes_map="test/tmp4/nodes4.map",
    )
    _PEER_FILE = "src/peer.py"
    _NODES_MAP = "test/tmp4/nodes4.map"
    _MAX_CONN = 100
    peer_args = [
        (1, "test/tmp4/data4-1.fragment", 58001),
        (2, "test/tmp4/data4-2.fragment", 58002),
        (3, "test/tmp4/data4-2.fragment", 58003),
    ]
    for peer_id, has_chunk, port in peer_args:
        crash_session.add_peer(
            identity=peer_id,
            peer_file_loc=_PEER_FILE,
            nodes_map_loc=_NODES_MAP,
            has_chunk_loc=has_chunk,
            max_connection=_MAX_CONN,
            peer_addr=("127.0.0.1", port),
            timeout=None,
        )

    crash_session.run_grader()

    crash_session.peer_list[("127.0.0.1", 58001)].send_cmd(
        "DOWNLOAD test/tmp4/download_target4.chunkhash test/tmp4/download_result.fragment\n"
    )

    time.sleep(1)

    # crash peer2
    crash_session.peer_list[("127.0.0.1", 58002)].terminate_peer()

    while True:
        if result_path.exists():
            success = True
            break
        if time.perf_counter() - stime > time_max:
            success = False
            break
        time.sleep(0.5)

    for p in crash_session.peer_list.values():
        if p.process is not None:
            p.terminate_peer()

    return crash_session, success


def test_finish(crash_session: tuple[grader.GradingSession, bool]) -> None:
    session, success = crash_session
    assert success, "Fail to complete transfer or timeout"


def test_content() -> None:
    result_path = Path("test/tmp4/download_result.fragment")
    with result_path.open("rb") as download_file:
        download_fragment: dict[str, bytes] = pickle.load(download_file)

    target_hash: list[str] = ["45acace8e984465459c893197e593c36daf653db"]

    for th in target_hash:
        assert (
            th in download_fragment
        ), f"download hash mismatch, target: {th}, has: {download_fragment.keys()}"

        sha1 = hashlib.sha1()
        sha1.update(download_fragment[th])
        received_hash_str: str = sha1.hexdigest()
        assert (
            th.strip() == received_hash_str.strip()
        ), f"received data mismatch, expect hash: {target_hash}, actual: {received_hash_str}"
