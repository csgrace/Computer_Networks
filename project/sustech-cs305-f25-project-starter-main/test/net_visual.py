import argparse
from pathlib import Path

import networkx as nx
import matplotlib.pyplot as plt


def visualize_network(
    topo_file: str, nodes_file: str, output_file: str, show_queue: bool = False
) -> None:
    edges: list[list] = []
    peer_nodes: list[int] = []

    with open(topo_file, "r") as tf:
        for line in tf:
            if not line.strip():
                continue
            if "#" in line:
                continue
            line_info: list[str] = line.split(" ")
            edges.append(
                [int(line_info[0]), int(line_info[1]), {"queue": int(line_info[4])}]
            )

    with open(nodes_file, "r") as nf:
        for line in nf:
            if not line.strip():
                continue
            if "#" in line:
                continue
            line_info: list[str] = line.split(" ")
            peer_nodes.append(int(line_info[0]))

    print(f"edges: {edges}")
    print(f"nodes with peers: {peer_nodes}")
    G: nx.Graph = nx.Graph()
    G.add_edges_from(edges)

    nodes_colormap: list[str] = [
        "r" if node in peer_nodes else "b" for node in G.nodes()
    ]

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color=nodes_colormap)

    if show_queue:
        nx.draw_networkx_edge_labels(
            G, pos, edge_labels=nx.get_edge_attributes(G, "queue")
        )

    plt.savefig(output_file)

    print(f"plot saved to {Path(output_file).resolve()}, show queue size: {show_queue}")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("-t", "--topo", type=str, help="topo file", required=True)
    parser.add_argument("-n", "--node", type=str, help="nodes file", required=True)
    parser.add_argument(
        "-o", "--output", type=str, help="output file", default="net-visual.png"
    )
    parser.add_argument(
        "-q", "--queue", help="show queue size in plot", action="store_true"
    )
    args: argparse.Namespace = parser.parse_args()

    visualize_network(args.topo, args.node, args.output, args.queue)


if __name__ == "__main__":
    main()
