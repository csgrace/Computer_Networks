import argparse
import hashlib
import pickle
import sys
from pathlib import Path

BT_CHUNK_SIZE: int = 512 * 1024  # 512KiB
SHA1_HASH_SIZE: int = 20


def chunk_hash(chunk_bytes: bytes) -> str:
    """
    Computes the SHA1 hash of a byte chunk and returns it as a hex digest.

    :param chunk_bytes: The byte content of the chunk.
    :return: The SHA1 hash of the chunk as a hexadecimal string.
    """
    sha1_hash = hashlib.sha1()
    sha1_hash.update(chunk_bytes)
    return sha1_hash.hexdigest()


def parse_file(file_dir: str, chunk_num: int) -> tuple[list[bytes], list[str]]:
    """
    Parses a file into chunks, calculates their hashes, and writes a master hash file.

    :param file_dir: The path to the input file.
    :param chunk_num: The number of chunks to split the file into.
    :return: A tuple containing a list of chunk byte contents and a list of their corresponding SHA1 hashes.
    """
    file_path = Path(file_dir)

    file_size: int = file_path.stat().st_size

    num_max: int = file_size // BT_CHUNK_SIZE
    if num_max < chunk_num:
        print(
            f"Requested {chunk_num} chunks out of max number of chunks: {num_max}, using {num_max} instead of {chunk_num}",
            file=sys.stderr,
        )
    num: int = min(num_max, chunk_num)

    data_chunk: list[bytes] = []
    data_hash: list[str] = []

    with file_path.open("rb") as file:
        for i in range(num):
            chunk_byte: bytes = file.read(BT_CHUNK_SIZE)
            data_chunk.append(chunk_byte)
            data_hash.append(chunk_hash(chunk_byte))

    with open(Path("master.chunkhash"), "w") as f:
        for j, hash_val in enumerate(data_hash):
            print(f"{j + 1} {hash_val}", file=f)

    return data_chunk, data_hash


def make_data(
    my_input: str, my_output: str, chunk_num: int, my_index: list[int]
) -> None:
    """
    Creates a data file containing specific chunks from an input file.

    :param my_input: The path to the input file.
    :param my_output: The path to the output file.
    :param chunk_num: The number of chunks to split the input file into.
    :param my_index: A list of chunk indices to include in the output file.
    """
    data_chunk, data_hash = parse_file(my_input, chunk_num)

    my_data: dict[str, bytes] = {data_hash[i - 1]: data_chunk[i - 1] for i in my_index}

    output_path = Path(my_output)

    with output_path.open("wb") as wf:
        pickle.dump(my_data, wf)

    print([data_hash[i - 1] for i in my_index])


def main() -> None:
    """
    Main entry point for the data maker script.
    Parses command-line arguments and invokes the make_data function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="The location of the input file.")
    parser.add_argument("output", type=str, help="The location of the output file.")
    parser.add_argument("num", type=int, help="Split to how many chunks")
    parser.add_argument(
        "index",
        type=str,
        help="Comma-separated index of chunks to be included in the output file",
    )
    args: argparse.Namespace = parser.parse_args()

    my_input: str = args.input
    my_output: str = args.output
    my_index: list[int] = [int(i) for i in args.index.split(",")]

    make_data(my_input, my_output, args.num, my_index)


if __name__ == "__main__":
    main()
