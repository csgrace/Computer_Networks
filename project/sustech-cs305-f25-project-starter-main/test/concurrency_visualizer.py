import re
import argparse
from datetime import datetime

import matplotlib.pyplot as plt

_DATE_FMT: str = "%m-%d %H:%M:%S.%f"
_PATTERN: str = r"\('127.0.0.1', (\d*)\)"
_SPILITTER: str = "|-"

type TimeList = list[float]
type CountList = list[int]
type SessionData = list[TimeList | CountList]


def str2time(t_str: str) -> float:
    return datetime.strptime(t_str, _DATE_FMT).timestamp()


def log2port(log_str: str) -> int:
    match: re.Match | None = re.search(_PATTERN, log_str)
    return int(match.group(1))


def analyze_and_plot(file: str) -> None:
    sessions: dict[int, list] = {}
    start_time: float = 0

    with open(file, "r") as f:
        first_line: str = f.readline()
        start_info: list[str] = first_line.split(_SPILITTER)
        start_time = str2time(start_info[0].strip()) * 1000

        for line in f:
            if not line.strip():
                continue

            # "%(asctime)s :: %(levelname)-5s :: %(name)s:%(lineno)d :: %(message)s"
            info: list[str] = line.split(_SPILITTER)
            if info[1].strip() != "DEBUG" or "sending" in line:
                continue

            # print(info)
            session_port: int = log2port(info[3].strip())
            pkt_time: float = str2time(info[0].strip()) * 1000 - start_time
            if session_port not in sessions:
                sessions[session_port] = []
                pkt_cnt: CountList = [0]
                time_cnt: TimeList = [pkt_time]
                sessions[session_port].append(time_cnt)
                sessions[session_port].append(pkt_cnt)
            else:
                sessions[session_port][0].append(pkt_time)
                sessions[session_port][1].append(sessions[session_port][1][-1] + 1)

    # print(sessions)
    plt.figure()
    record: SessionData
    for port, record in sessions.items():
        plt.plot(record[0], record[1], ",", markersize=0.1)

    plt.legend(list(sessions.keys()))
    plt.xlabel("Time Since Start (ms)")
    plt.ylabel("Stream")
    plt.savefig("concurrency_analysis.png")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="log file to visualize")
    args: argparse.Namespace = parser.parse_args()

    file: str = args.file
    analyze_and_plot(file)


if __name__ == "__main__":
    main()
