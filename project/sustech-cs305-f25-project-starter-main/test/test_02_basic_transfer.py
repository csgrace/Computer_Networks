import time
import pickle
import hashlib
from pathlib import Path

import pytest

import grader

"""
This test examines the basic function of your RDT and congestion control.
There will be a packet loss around #150
Your peer should retransmit and receive the entire data correctly and dump them to serialized dict.
To show your congestion control implementation, you need to plot your sending window size change in a plot similar to the one in
the document.
If you can pass RDT test, you will gain 10 points.
Congestion control will be inspected by humans on your presentation day. If you show the correct implementation of congestion control,
You will get 12 points. 22 in total.
However, note that this is just a sanity test. Passing this test does *NOT* guarantee your correctness in comprehensive tests.

.fragment file:
data1.fragment: chunk 1,2
data2.fragment: chunk 3,4

This test is equivalent to run (except for packet loss):
In shell1:
python3 src/peer.py -p test/tmp2/nodes2.map -c test/tmp2/data1.fragment -m 1 -i 1 -t 60

In shell2:
python3 src/peer.py -p test/tmp2/nodes2.map -c test/tmp2/data2.fragment -m 1 -i 2 -t 60

In shell1:
DOWNLOAD test/tmp2/download_target.chunkhash test/tmp2/download_result.fragment
"""


@pytest.fixture(scope="module")
def drop_session() -> tuple[grader.GradingSession, bool]:
    success: bool = False
    time_max: int = 80

    fragment_path = Path("test/tmp2/download_result.fragment")
    fragment_path.unlink(missing_ok=True)

    stime: float = time.perf_counter()
    drop_session: grader.GradingSession = grader.GradingSession(
        grader.drop_handler, latency=0.01
    )
    drop_session.add_peer(
        identity=1,
        peer_file_loc="src/peer.py",
        nodes_map_loc="test/tmp2/nodes2.map",
        has_chunk_loc="test/tmp2/data1.fragment",
        max_connection=1,
        peer_addr=("127.0.0.1", 58001),
    )
    drop_session.add_peer(
        identity=2,
        peer_file_loc="src/peer.py",
        nodes_map_loc="test/tmp2/nodes2.map",
        has_chunk_loc="test/tmp2/data2.fragment",
        max_connection=1,
        peer_addr=("127.0.0.1", 58002),
    )
    drop_session.run_grader()

    drop_session.peer_list[("127.0.0.1", 58001)].send_cmd(
        """DOWNLOAD test/tmp2/download_target.chunkhash test/tmp2/download_result.fragment\n"""
    )

    while True:
        if fragment_path.exists():
            success = True
            break
        elif time.perf_counter() - stime > time_max:
            # Reached max transmission time, abort
            success = False
            break

        time.sleep(0.3)

    for p in drop_session.peer_list.values():
        p.terminate_peer()

    return drop_session, success


def test_finish(drop_session: tuple[grader.GradingSession, bool]) -> None:
    session, success = drop_session
    assert success, "Fail to complete transfer or timeout"


def test_rdt(drop_session: tuple[grader.GradingSession, bool]) -> None:
    fragment_path = Path("test/tmp2/download_result.fragment")
    assert fragment_path.exists(), "no downloaded file"

    with fragment_path.open("rb") as download_file:
        download_fragment: dict[str, bytes] = pickle.load(download_file)
    target_hash: str = "3b68110847941b84e8d05417a5b2609122a56314"

    assert (
        target_hash in download_fragment
    ), f"download hash mismatch, target: {target_hash}, has: {download_fragment.keys()}"

    sha1 = hashlib.sha1()
    sha1.update(download_fragment[target_hash])
    received_hash_str: str = sha1.hexdigest()

    assert (
        target_hash.strip() == received_hash_str.strip()
    ), f"received data mismatch, expect hash: {target_hash}, actual: {received_hash_str}"
