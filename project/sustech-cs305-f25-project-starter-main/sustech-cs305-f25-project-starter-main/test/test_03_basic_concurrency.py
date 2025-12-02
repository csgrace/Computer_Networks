import time
import pickle
import hashlib
import pytest
from pathlib import Path

import concurrency_visualizer
import grader

"""
This test examines the basic function of your concurrency.
Peer1 will be downloading chunk2,3 from Peer2, 3 concurrently.

This test will be running with network simulator, with topology test/tmp3/topo3.map. You can assume there will not be
packet loss in this test. The script will check if you can correctly download all chunks, and it will generate a concurrency_analysis plot
which will be checked on presentation.

.fragment files:
data3-1.fragment: chunk1
data3-2.fragment: chunk2
data3-3.fragment: chunk3

This testing script is equivalent to run the following commands in different shells (remember to export SIMULATOR):

perl utils/hupsim.pl -m test/tmp3/topo3.map -n test/tmp3/nodes3.map -p {port_number} -v 3


python3 src/peer.py -p test/tmp3/nodes3.map -c test/tmp3/data3-1.fragment -m 100 -i 1 -t 60
DOWNLOAD test/tmp3/download_target3.chunkhash test/tmp3/download_result.fragment


python3 src/peer.py -p test/tmp3/nodes3.map -c test/tmp3/data3-2.fragment -m 100 -i 2 -t 60


python3 src/peer.py -p test/tmp3/nodes3.map -c test/tmp3/data3-3.fragment -m 100 -i 3 -t 60
"""


@pytest.fixture(scope="module")
def concurrent_session() -> tuple[grader.GradingSession, bool]:
    success: bool = False
    time_max: int = 80
    fragment_path: Path = Path("test/tmp3/download_result.fragment")
    fragment_path.unlink(missing_ok=True)

    stime: float = time.perf_counter()
    concurrent_session: grader.GradingSession = grader.GradingSession(
        grader.normal_handler,
        latency=0.01,
        spiffy=True,
    )
    _PEER_FILE = "src/peer.py"
    _NODES_MAP = "test/tmp3/nodes3.map"
    _MAX_CONN = 100
    peer_args = [
        (1, "test/tmp3/data3-1.fragment", ("127.0.0.1", 58001)),
        (2, "test/tmp3/data3-2.fragment", ("127.0.0.1", 58002)),
        (3, "test/tmp3/data3-3.fragment", ("127.0.0.1", 58003)),
        (3, "test/tmp3/data3-3.fragment", ("127.0.0.1", 58003)),
    ]
    for peer_id, has_chunk, addr in peer_args:
        concurrent_session.add_peer(
            identity=peer_id,
            peer_file_loc=_PEER_FILE,
            nodes_map_loc=_NODES_MAP,
            has_chunk_loc=has_chunk,
            max_connection=_MAX_CONN,
            peer_addr=addr,
        )

    concurrent_session.run_grader()

    concurrent_session.peer_list[("127.0.0.1", 58001)].send_cmd(
        """DOWNLOAD test/tmp3/download_target3.chunkhash test/tmp3/download_result.fragment\n"""
    )

    while True:
        if fragment_path.exists():
            success = True
            break
        elif time.perf_counter() - stime > time_max:
            # Reached max transmission time, abort
            success = False
            break

        time.sleep(0.5)

    for p in concurrent_session.peer_list.values():
        p.terminate_peer()

    return concurrent_session, success


def test_finish(concurrent_session: tuple[grader.GradingSession, bool]) -> None:
    session, success = concurrent_session
    assert success, "Fail to complete transfer or timeout"


def test_content() -> None:
    fragment_path = Path("test/tmp3/download_result.fragment")
    with fragment_path.open("rb") as download_file:
        download_fragment: dict[str, bytes] = pickle.load(download_file)

    target_hash: list[str] = [
        "45acace8e984465459c893197e593c36daf653db",
        "3b68110847941b84e8d05417a5b2609122a56314",
    ]

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


def test_concurrency_vis() -> None:
    concurrency_visualizer.analyze_and_plot("logs/peer1.log")
    assert (
        "This will be checked on your presentation"
        == "This will be checked on your presentation"
    )
