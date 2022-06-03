import sys


def bytes_from_file(path):
    """Iterator. If path is None or empty, read from stdin."""

    def all_bytes(file):
        while True:
            buffer = file.read()
            if not buffer:
                return
            yield from (byte for byte in buffer)

    if path:
        with open(path, "rb") as file:
            yield from all_bytes(file)
    else:
        yield from all_bytes(sys.stdin.buffer)
